#include "dvargosh/telemetry.hpp"
#include "dvargosh/event_bus.hpp"
#include "dvargosh/logger.hpp"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace dvargosh {

namespace {

constexpr size_t kDefaultRingCapacity = 256;
constexpr int kDefaultTickMs = 200;
// A watch on the same stream fires at most once per cooldown window, so a
// continuously-breathing threshold produces one alert, not one per tick.
constexpr auto kWatchCooldown = std::chrono::seconds(2);

} // namespace

TelemetryHub::TelemetryHub(std::shared_ptr<EventBus> event_bus)
    : m_event_bus(std::move(event_bus)) {
    m_running = true;
    m_sampler = std::thread([this] { sampler_loop(); });
}

TelemetryHub::~TelemetryHub() {
    m_running = false;
    if (m_sampler.joinable()) {
        m_sampler.join();
    }
}

// --- Streams -----------------------------------------------------------------

MetricStreamId TelemetryHub::register_stream(const std::string& name, size_t capacity) {
    std::lock_guard<std::mutex> lock(m_streams_mutex);
    auto it = m_streams.find(name);
    if (it != m_streams.end()) return it->second->capacity; // idempotent; capacity is the identity for lazily-made streams
    auto stream = std::make_shared<Stream>();
    stream->capacity = capacity > 0 ? capacity : kDefaultRingCapacity;
    m_streams[name] = std::move(stream);
    return m_next_stream_id++;
}

void TelemetryHub::record(const std::string& name, double value) {
    std::shared_ptr<Stream> stream;
    {
        std::lock_guard<std::mutex> lock(m_streams_mutex);
        auto it = m_streams.find(name);
        if (it != m_streams.end()) {
            stream = it->second;
        } else {
            stream = std::make_shared<Stream>();
            stream->capacity = kDefaultRingCapacity;
            m_streams[name] = stream;
        }
    }

    std::lock_guard<std::mutex> slock(stream->mutex);
    if (stream->ring.size() >= stream->capacity) {
        stream->ring.pop_front();
        stream->dropped++;
    }
    if (stream->count == 0) {
        stream->min = value;
        stream->max = value;
    } else {
        stream->min = std::min(stream->min, value);
        stream->max = std::max(stream->max, value);
    }
    stream->ring.push_back(value);
    stream->last = value;
    stream->sum += value;
    stream->count++;
}

void TelemetryHub::increment(const std::string& name, double by) {
    std::shared_ptr<Stream> stream;
    {
        std::lock_guard<std::mutex> lock(m_streams_mutex);
        auto it = m_streams.find(name);
        if (it != m_streams.end()) stream = it->second;
    }
    if (stream) {
        std::lock_guard<std::mutex> slock(stream->mutex);
        stream->last += by;
        stream->sum += by;
        stream->max = std::max(stream->max, stream->last);
        stream->count++;
        if (stream->ring.size() >= stream->capacity) {
            stream->ring.pop_front();
            stream->dropped++;
        }
        stream->ring.push_back(stream->last);
        return;
    }
    record(name, by);
}

TelemetryHub::StreamSnapshot TelemetryHub::snapshot_stream(const Stream& s) const {
    StreamSnapshot snap;
    std::lock_guard<std::mutex> lock(s.mutex);
    snap.last = s.last;
    snap.min = s.min;
    snap.max = s.max;
    snap.avg = s.count > 0 ? s.sum / static_cast<double>(s.count) : 0.0;
    snap.count = s.count;
    snap.dropped = s.dropped;
    return snap;
}

std::vector<MetricSnapshotItem> TelemetryHub::snapshot(const std::string& glob) const {
    std::vector<std::pair<std::string, std::shared_ptr<Stream>>> matched;
    {
        std::lock_guard<std::mutex> lock(m_streams_mutex);
        for (const auto& [name, stream] : m_streams) {
            if (glob == "*" || glob.empty() || glob_match(glob, name)) {
                matched.emplace_back(name, stream);
            }
        }
    }
    std::sort(matched.begin(), matched.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::vector<MetricSnapshotItem> out;
    out.reserve(matched.size());
    for (const auto& [name, stream] : matched) {
        StreamSnapshot snap = snapshot_stream(*stream);
        MetricSnapshotItem item;
        item.name = name;
        item.last = snap.last;
        item.min = snap.min;
        item.max = snap.max;
        item.avg = snap.avg;
        item.count = snap.count;
        item.dropped = snap.dropped;
        out.push_back(std::move(item));
    }
    return out;
}

std::vector<MetricSnapshotItem> TelemetryHub::top_streams(size_t n, const std::string& glob) const {
    auto items = snapshot(glob);
    std::sort(items.begin(), items.end(),
              [](const MetricSnapshotItem& a, const MetricSnapshotItem& b) {
                  return a.last > b.last;
              });
    if (items.size() > n) items.resize(n);
    return items;
}

// --- Watchdog -----------------------------------------------------------------

Result<uint64_t> TelemetryHub::watch(
    const std::string& stream_glob,
    const std::string& op,
    double threshold,
    const std::string& action,
    const std::string& module
) {
    if (op != ">" && op != "<") {
        return Result<uint64_t>::failure(StatusCode::InvalidArg, "Watch op must be '>' or '<'");
    }
    if (action != "log" && action != "event" && action != "revoke") {
        return Result<uint64_t>::failure(StatusCode::InvalidArg, "Watch action must be 'log', 'event', or 'revoke'");
    }
    if (stream_glob.empty()) {
        return Result<uint64_t>::failure(StatusCode::InvalidArg, "Watch stream glob cannot be empty");
    }

    std::lock_guard<std::mutex> lock(m_watch_mutex);
    Watch w;
    w.id = m_next_watch_id++;
    w.stream_glob = stream_glob;
    w.op = op;
    w.threshold = threshold;
    w.action = action;
    w.module = module;
    uint64_t id = w.id;
    m_watches[id] = std::move(w);
    return Result<uint64_t>::success(id);
}

Result<void> TelemetryHub::unwatch(uint64_t id) {
    std::lock_guard<std::mutex> lock(m_watch_mutex);
    return m_watches.erase(id) > 0
        ? Result<void>::success()
        : Result<void>::failure(StatusCode::NotFound, "Watch id not found");
}

std::vector<WatchHandleInfo> TelemetryHub::list_watches() const {
    std::lock_guard<std::mutex> lock(m_watch_mutex);
    std::vector<WatchHandleInfo> out;
    out.reserve(m_watches.size());
    for (const auto& [id, w] : m_watches) {
        WatchHandleInfo info;
        info.id = w.id;
        info.stream_glob = w.stream_glob;
        info.op = w.op;
        info.threshold = w.threshold;
        info.action = w.action;
        info.module = w.module;
        out.push_back(std::move(info));
    }
    return out;
}

// --- Revocation epochs ----------------------------------------------------------

void TelemetryHub::track_policy(const std::string& module_name, const SecurityPolicy& policy) {
    std::lock_guard<std::mutex> lock(m_epoch_mutex);
    m_epochs[module_name] = policy.revocation_token();
}

void TelemetryHub::untrack_policy(const std::string& module_name) {
    std::lock_guard<std::mutex> lock(m_epoch_mutex);
    m_epochs.erase(module_name);
}

bool TelemetryHub::revoke_policy(const std::string& module_name) {
    std::shared_ptr<std::atomic<uint32_t>> token;
    {
        std::lock_guard<std::mutex> lock(m_epoch_mutex);
        auto it = m_epochs.find(module_name);
        if (it == m_epochs.end()) return false;
        token = it->second;
    }
    uint32_t expected = 0;
    return token->compare_exchange_strong(expected, 1, std::memory_order_relaxed);
}

bool TelemetryHub::restore_policy(const std::string& module_name) {
    std::shared_ptr<std::atomic<uint32_t>> token;
    {
        std::lock_guard<std::mutex> lock(m_epoch_mutex);
        auto it = m_epochs.find(module_name);
        if (it == m_epochs.end()) return false;
        token = it->second;
    }
    token->store(0, std::memory_order_relaxed);
    return true;
}

// --- Sampler & display ------------------------------------------------------------

void TelemetryHub::sampler_loop() {
    while (m_running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(m_tick_ms.load(std::memory_order_relaxed)));
        if (!m_running.load(std::memory_order_relaxed)) break;
        evaluate_watches();
    }
}

void TelemetryHub::evaluate_watches() {
    std::vector<Watch> watches;
    {
        std::lock_guard<std::mutex> lock(m_watch_mutex);
        watches.reserve(m_watches.size());
        for (const auto& [_, w] : m_watches) watches.push_back(w);
    }
    if (watches.empty()) return;

    for (const auto& w : watches) {
        auto items = snapshot(w.stream_glob);
        for (const auto& item : items) {
            bool breach = (w.op == ">") ? (item.last > w.threshold) : (item.last < w.threshold);
            if (!breach) continue;

            auto now = std::chrono::steady_clock::now();
            {
                std::lock_guard<std::mutex> lock(m_watch_mutex);
                auto it = m_watches.find(w.id);
                if (it != m_watches.end() && it->second.ever_fired &&
                    now - it->second.last_fired < kWatchCooldown) {
                    continue;
                }
                if (it != m_watches.end()) {
                    it->second.ever_fired = true;
                    it->second.last_fired = now;
                }
            }

            std::ostringstream msg;
            msg << "Watchdog breach: stream '" << item.name << "' " << w.op << " "
                << w.threshold << " (last=" << item.last << ") — action: " << w.action;
            log_warn(msg.str());

            if (w.action == "revoke" && !w.module.empty()) {
                if (revoke_policy(w.module)) {
                    log_error("Watchdog REVOKED module '", w.module,
                              "' — its next RPC invocation will be denied.");
                }
            }
            if (m_event_bus) {
                (void)m_event_bus->publish(
                    "telemetry.threshold_breach",
                    Value("stream=" + item.name + " op=" + w.op + " threshold=" +
                          std::to_string(w.threshold) + " last=" + std::to_string(item.last) +
                          " action=" + w.action),
                    "telemetry_hub",
                    nullptr);
            }
        }
    }
}

bool TelemetryHub::glob_match(const std::string& pattern, const std::string& value) {
    // Minimal glob: '*' matches any sequence (including empty); everything else literal.
    size_t p = 0, v = 0, star = std::string::npos, mark = 0;
    while (v < value.size()) {
        if (p < pattern.size() && (pattern[p] == value[v])) {
            ++p; ++v;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            mark = v;
        } else if (star != std::string::npos) {
            p = star + 1;
            v = ++mark;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

void TelemetryHub::dump_dashboard() const {
    auto items = snapshot("*");
    std::cout << "\n┌────────────────────────────────────────────────────────────────────────┐\n";
    std::cout << "│                        TELEMETRY HUB DASHBOARD                         │\n";
    std::cout << "├──────────────────────────────────────────┬──────────────┬──────────────┤\n";
    std::cout << "│ Stream                                   │        Last  │  Count/Drop  │\n";
    std::cout << "├──────────────────────────────────────────┼──────────────┼──────────────┤\n";
    for (const auto& item : items) {
        std::string name = item.name;
        if (name.length() > 40) name = name.substr(0, 37) + "...";
        std::cout << "│ " << name;
        for (size_t i = name.length(); i < 41; ++i) std::cout << " ";
        std::ostringstream last_ss;
        last_ss << std::fixed << std::setprecision(3) << item.last;
        std::string l = last_ss.str();
        std::cout << " │ ";
        for (size_t i = l.length(); i < 12; ++i) std::cout << " ";
        std::cout << l;
        std::ostringstream cnt_ss;
        cnt_ss << item.count << "/" << item.dropped;
        std::string c = cnt_ss.str();
        std::cout << " │ ";
        for (size_t i = c.length(); i < 12; ++i) std::cout << " ";
        std::cout << c << " │\n";
    }
    std::cout << "└──────────────────────────────────────────┴──────────────┴──────────────┘\n\n";
}

} // namespace dvargosh
