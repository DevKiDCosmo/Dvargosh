#pragma once

// ============================================================================
// Dvargosh TelemetryHub — process-wide telemetry, watchdog, and revocation
// ============================================================================
// Core-side accounting that modules cannot bypass (docs/execution_plan.md S3):
//   * Metric streams with bounded ring buffers (drop-oldest, never blocks hot paths)
//   * Native wiring into Registry::invoke (invoke.count / invoke.duration_ms)
//   * Watchdog thresholds -> log / event / revoke actions on a sampler thread
//   * Revocation epochs shared with SecurityPolicy (kill switch per module)
//   * Display: snapshot(), top_streams(), dump_dashboard()
// ============================================================================

#include "types.hpp"
#include "permissions.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace dvargosh {

class EventBus;

using MetricStreamId = uint64_t;

struct MetricSnapshotItem {
    std::string name;
    double last = 0.0;
    double min = 0.0;
    double max = 0.0;
    double avg = 0.0;
    uint64_t count = 0;   // samples recorded (lifetime)
    uint64_t dropped = 0; // samples dropped by ring overflow
};

struct WatchHandleInfo {
    uint64_t id = 0;
    std::string stream_glob;
    std::string op;        // ">" or "<"
    double threshold = 0.0;
    std::string action;    // "log" | "event" | "revoke"
    std::string module;    // revoke target (empty = no revocation)
};

class TelemetryHub {
public:
    explicit TelemetryHub(std::shared_ptr<EventBus> event_bus);
    ~TelemetryHub();

    TelemetryHub(const TelemetryHub&) = delete;
    TelemetryHub& operator=(const TelemetryHub&) = delete;

    // --- Metric streams -------------------------------------------------------

    // record() lazily creates streams; explicit registration only pins capacity.
    MetricStreamId register_stream(const std::string& name, size_t capacity = 256);
    void record(const std::string& name, double value);
    void increment(const std::string& name, double by = 1.0);

    std::vector<MetricSnapshotItem> snapshot(const std::string& glob = "*") const;

    // Top-N streams by name-ordered last value (dashboard helper).
    std::vector<MetricSnapshotItem> top_streams(size_t n, const std::string& glob = "*") const;

    // --- Watchdog --------------------------------------------------------------

    // Watches are evaluated by the sampler thread on every tick.
    // action: "log" | "event" | "revoke" ("revoke" flips the target module's epoch).
    Result<uint64_t> watch(
        const std::string& stream_glob,
        const std::string& op,       // ">" or "<"
        double threshold,
        const std::string& action,
        const std::string& module = ""
    );
    Result<void> unwatch(uint64_t id);
    std::vector<WatchHandleInfo> list_watches() const;

    // --- Revocation epochs (shared with SecurityPolicy) --------------------------

    void track_policy(const std::string& module_name, const SecurityPolicy& policy);
    void untrack_policy(const std::string& module_name);
    bool revoke_policy(const std::string& module_name);
    bool restore_policy(const std::string& module_name);

    // --- Display -----------------------------------------------------------------

    void dump_dashboard() const;
    void set_tick_interval_ms(int ms) { m_tick_ms = ms; }

private:
    struct Stream {
        mutable std::mutex mutex;
        std::deque<double> ring;
        size_t capacity = 256;
        double last = 0.0;
        double min = 0.0;
        double max = 0.0;
        double sum = 0.0;
        uint64_t count = 0;
        uint64_t dropped = 0;
    };

    struct Watch {
        uint64_t id = 0;
        std::string stream_glob;
        std::string op;
        double threshold = 0.0;
        std::string action;
        std::string module;
        std::chrono::steady_clock::time_point last_fired{};
        bool ever_fired = false;
    };

    struct StreamSnapshot {
        std::string name;
        double last = 0.0;
        double min = 0.0;
        double max = 0.0;
        double avg = 0.0;
        uint64_t count = 0;
        uint64_t dropped = 0;
    };

    StreamSnapshot snapshot_stream(const Stream& s) const;
    void sampler_loop();
    void evaluate_watches();
    static bool glob_match(const std::string& pattern, const std::string& value);

    std::shared_ptr<EventBus> m_event_bus;

    mutable std::mutex m_streams_mutex;
    std::unordered_map<std::string, std::shared_ptr<Stream>> m_streams;
    uint64_t m_next_stream_id = 1;

    mutable std::mutex m_watch_mutex;
    std::unordered_map<uint64_t, Watch> m_watches;
    uint64_t m_next_watch_id = 1;

    mutable std::mutex m_epoch_mutex;
    std::unordered_map<std::string, std::shared_ptr<std::atomic<uint32_t>>> m_epochs;

    std::atomic<bool> m_running{false};
    std::thread m_sampler;
    std::atomic<int> m_tick_ms{200};
};

} // namespace dvargosh
