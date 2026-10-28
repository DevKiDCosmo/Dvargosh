#include "stdnet_reactor.hpp"

#if defined(__APPLE__) && !defined(DVARGOSH_NET_EPOLL)
#define DVARGOSH_NET_KQUEUE 1
#include <sys/event.h>
#else
#define DVARGOSH_NET_EPOLL 1
#include <sys/epoll.h>
#endif
#include <unistd.h>
#include <cerrno>
#include <algorithm>

namespace dvargosh::stdnet {

const char* Reactor::backend_name() {
#if defined(DVARGOSH_NET_KQUEUE)
    return "kqueue";
#else
    return "epoll";
#endif
}

Reactor::Reactor() {
    backend_init();
    m_running = true;
    m_thread = std::thread([this] { run(); });
}

Reactor::~Reactor() {
    stop();
    backend_shutdown();
}

void Reactor::stop() {
    if (!m_running.exchange(false)) return;
    // Wake the poll by a trivial self-pipe substitute: closing the backend is not
    // enough, so post a no-op (poll wakes via short timeout anyway) and join.
    post([] {});
    if (m_thread.joinable()) m_thread.join();
}

// --- posted jobs -------------------------------------------------------------

void Reactor::post(ReactorJob job) {
    {
        std::lock_guard<std::mutex> lock(m_pending_mutex);
        m_pending.push_back(std::move(job));
    }
    // The backend poll uses a bounded timeout, so posted jobs are picked up on
    // the next wake; no self-pipe needed for our workloads.
}

static void drain_pending(std::mutex& m, std::vector<ReactorJob>& pending, std::vector<ReactorJob>& out) {
    std::lock_guard<std::mutex> lock(m);
    out.swap(pending);
}

// --- timers -------------------------------------------------------------------

TimerId Reactor::timer_after(int ms, ReactorJob job) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    Timer t;
    t.id = m_next_timer_id++;
    t.periodic = false;
    t.interval_ms = ms;
    t.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    t.job = std::move(job);
    const TimerId id = t.id;
    m_timers.push_back(std::move(t));
    return id;
}

TimerId Reactor::timer_every(int ms, ReactorJob job) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    Timer t;
    t.id = m_next_timer_id++;
    t.periodic = true;
    t.interval_ms = ms;
    t.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    t.job = std::move(job);
    const TimerId id = t.id;
    m_timers.push_back(std::move(t));
    return id;
}

bool Reactor::cancel_timer(TimerId id) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    for (auto it = m_timers.begin(); it != m_timers.end(); ++it) {
        if (it->id == id) {
            m_timers.erase(it);
            return true;
        }
    }
    return false;
}

int Reactor::next_timeout_ms() {
    // Caller holds no lock; we snapshot under m_state_mutex (const_cast-free path).
    std::lock_guard<std::mutex> lock(m_state_mutex);
    if (!m_timers.empty()) {
        auto now = std::chrono::steady_clock::now();
        auto earliest = m_timers.front().deadline;
        for (const auto& t : m_timers) earliest = std::min(earliest, t.deadline);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(earliest - now).count();
        return static_cast<int>(std::clamp<long long>(ms, 0, 100));
    }
    return 100; // bounded wake for posted jobs
}

void Reactor::run_timers() {
    auto now = std::chrono::steady_clock::now();
    std::vector<ReactorJob> due;
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        for (auto it = m_timers.begin(); it != m_timers.end();) {
            if (it->deadline <= now) {
                due.push_back(it->job);
                if (it->periodic) {
                    it->deadline = now + std::chrono::milliseconds(it->interval_ms);
                    ++it;
                } else {
                    it = m_timers.erase(it);
                }
            } else {
                ++it;
            }
        }
    }
    for (auto& job : due) job(); // outside the lock; may re-arm timers
}

// --- fd watches ------------------------------------------------------------------

bool Reactor::watch_fd(int fd, bool read, bool write, FdHandler handler) {
    Watch w{read, write, std::move(handler)};
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        if (m_watches.count(fd)) return false;
        m_watches[fd] = w;
    }
    return backend_watch(fd, w);
}

void Reactor::modify_fd(int fd, bool read, bool write) {
    Watch w;
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        auto it = m_watches.find(fd);
        if (it == m_watches.end()) return;
        it->second.read = read;
        it->second.write = write;
        w = it->second;
    }
    backend_modify(fd, w);
}

void Reactor::unwatch_fd(int fd) {
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        m_watches.erase(fd);
    }
    backend_unwatch(fd);
}

// --- main loop ----------------------------------------------------------------------

void Reactor::run() {
    std::vector<ReactorJob> jobs;
    while (m_running.load(std::memory_order_relaxed)) {
        backend_poll(next_timeout_ms());

        run_timers();

        jobs.clear();
        drain_pending(m_pending_mutex, m_pending, jobs);
        for (auto& job : jobs) {
            if (job) job();
        }
    }
}

// =====================================================================================
// kqueue backend (macOS)
// =====================================================================================
#if defined(DVARGOSH_NET_KQUEUE)

void Reactor::backend_init() {
    m_backend_fd = ::kqueue();
}

void Reactor::backend_shutdown() {
    if (m_backend_fd >= 0) ::close(m_backend_fd);
    m_backend_fd = -1;
}

bool Reactor::backend_watch(int fd, const Watch& w) {
    struct kevent ev[2];
    int n = 0;
    if (w.read) EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, nullptr);
    if (w.write) EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, nullptr);
    return ::kevent(m_backend_fd, ev, n, nullptr, 0, nullptr) >= 0;
}

void Reactor::backend_modify(int fd, const Watch& w) {
    struct kevent ev[2];
    EV_SET(&ev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&ev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    ::kevent(m_backend_fd, ev, 2, nullptr, 0, nullptr); // remove both (ignore errors)
    backend_watch(fd, w);                               // re-add active filters
}

void Reactor::backend_unwatch(int fd) {
    struct kevent ev[2];
    EV_SET(&ev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&ev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    ::kevent(m_backend_fd, ev, 2, nullptr, 0, nullptr);
}

void Reactor::backend_poll(int timeout_ms) {
    struct kevent events[64];
    struct timespec ts{timeout_ms / 1000, (timeout_ms % 1000) * 1000000L};
    int n = ::kevent(m_backend_fd, nullptr, 0, events, 64, &ts);
    for (int i = 0; i < n; ++i) {
        FdHandler handler;
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            auto it = m_watches.find(static_cast<int>(events[i].ident));
            if (it == m_watches.end()) continue; // unwatched between poll and dispatch
            handler = it->second.handler;
        }
        if (handler) {
            handler(static_cast<int>(events[i].ident),
                    (events[i].filter == EVFILT_READ),
                    (events[i].filter == EVFILT_WRITE),
                    (events[i].flags & EV_EOF) != 0);
        }
    }
}

#else
// =====================================================================================
// epoll backend (Linux)
// =====================================================================================

void Reactor::backend_init() {
    m_backend_fd = ::epoll_create1(0);
}

void Reactor::backend_shutdown() {
    if (m_backend_fd >= 0) ::close(m_backend_fd);
    m_backend_fd = -1;
}

uint32_t ep_events(const Watch& w) {
    return static_cast<uint32_t>((w.read ? EPOLLIN : 0u) | (w.write ? EPOLLOUT : 0u));
}

bool Reactor::backend_watch(int fd, const Watch& w) {
    struct epoll_event ev{};
    ev.events = ep_events(w) | EPOLLET; // edge-triggered, like production servers
    ev.data.fd = fd;
    return ::epoll_ctl(m_backend_fd, EPOLL_CTL_ADD, fd, &ev) == 0;
}

void Reactor::backend_modify(int fd, const Watch& w) {
    struct epoll_event ev{};
    ev.events = ep_events(w) | EPOLLET;
    ev.data.fd = fd;
    ::epoll_ctl(m_backend_fd, EPOLL_CTL_MOD, fd, &ev);
}

void Reactor::backend_unwatch(int fd) {
    ::epoll_ctl(m_backend_fd, EPOLL_CTL_DEL, fd, nullptr);
}

void Reactor::backend_poll(int timeout_ms) {
    struct epoll_event events[64];
    int n = ::epoll_wait(m_backend_fd, events, 64, timeout_ms);
    for (int i = 0; i < n; ++i) {
        FdHandler handler;
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            auto it = m_watches.find(events[i].data.fd);
            if (it == m_watches.end()) continue;
            handler = it->second.handler;
        }
        if (handler) {
            const uint32_t e = events[i].events;
            handler(events[i].data.fd,
                    (e & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0,
                    (e & (EPOLLOUT | EPOLLHUP | EPOLLERR)) != 0,
                    (e & (EPOLLHUP | EPOLLERR)) != 0);
        }
    }
}

#endif

} // namespace dvargosh::stdnet
