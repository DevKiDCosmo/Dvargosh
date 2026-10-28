#pragma once

// stdnet — Reactor: scalable fd event demultiplexing (kqueue on macOS, epoll on
// Linux) with posted jobs and steady high-resolution timers on one event thread.
//
// Backends: DVARGOSH_NET_KQUEUE / DVARGOSH_NET_EPOLL selected by platform.
// io_uring is deliberately reserved (docs: continuation architecture, Phase 3).
// HTTP/2 note lives in stdnet_http; TLS in stdnet_tls.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace dvargosh::stdnet {

using ReactorJob = std::function<void()>;
using FdHandler = std::function<void(int fd, bool readable, bool writable, bool hungup)>;
using TimerId = uint64_t;

class Reactor {
public:
    Reactor();
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    void run();          // blocks on the event thread (started in ctor)
    void stop();

    static const char* backend_name(); // "kqueue" | "epoll"

    // --- fd demultiplexing ------------------------------------------------------
    // handler(fd, readable, writable, hungup); handlers run ON the reactor thread.
    bool watch_fd(int fd, bool read, bool write, FdHandler handler);
    void modify_fd(int fd, bool read, bool write);
    void unwatch_fd(int fd);

    // --- posted jobs (Proactor-style completions) --------------------------------
    void post(ReactorJob job);   // thread-safe; runs on the reactor thread

    // --- steady timers -----------------------------------------------------------
    TimerId timer_after(int ms, ReactorJob job);          // one-shot
    TimerId timer_every(int ms, ReactorJob job);          // periodic until cancel
    bool cancel_timer(TimerId id);

    bool on_reactor_thread() const {
        return std::this_thread::get_id() == m_thread.get_id();
    }

private:
    struct Timer {
        TimerId id = 0;
        bool periodic = false;
        int interval_ms = 0;
        std::chrono::steady_clock::time_point deadline;
        ReactorJob job;
    };

    struct Watch {
        bool read = false;
        bool write = false;
        FdHandler handler;
    };

    void backend_init();
    void backend_shutdown();
    bool backend_watch(int fd, const Watch& w);
    void backend_modify(int fd, const Watch& w);
    void backend_unwatch(int fd);
    // Polls the backend for up to timeout_ms; dispatches ready fd handlers.
    void backend_poll(int timeout_ms);

    void run_timers();
    int next_timeout_ms();

    int m_backend_fd = -1;
    std::thread m_thread;
    std::atomic<bool> m_running{false};

    std::mutex m_state_mutex; // guards watches, timers, posted, next ids
    std::map<int, Watch> m_watches;
    std::vector<Timer> m_timers;
    std::vector<ReactorJob> m_posted;
    uint64_t m_next_timer_id = 1;

    std::mutex m_pending_mutex; // handoff into the reactor thread
    std::vector<ReactorJob> m_pending;
};

} // namespace dvargosh::stdnet
