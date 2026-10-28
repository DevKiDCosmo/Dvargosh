#pragma once

// stdnet — Execution Strand: serialized, thread-safe handler execution.
// Handlers posted to a strand never run concurrently — eliminates explicit
// locking for per-connection state. Backed by a worker thread per strand
// (cheap for the module-scale counts we serve).

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace dvargosh::stdnet {

class Strand : public std::enable_shared_from_this<Strand> {
public:
    using Job = std::function<void()>;

    Strand() {
        m_running = true;
        m_thread = std::thread([this] { loop(); });
    }

    ~Strand() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_running = false;
        }
        m_cv.notify_all();
        if (m_thread.joinable()) m_thread.join();
    }

    Strand(const Strand&) = delete;
    Strand& operator=(const Strand&) = delete;

    // Thread-safe; jobs execute strictly in post order, one at a time.
    void post(Job job) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push_back(std::move(job));
        }
        m_cv.notify_one();
    }

    // True when nothing is queued/running (test convenience).
    bool idle() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty() && !m_busy;
    }

    static std::shared_ptr<Strand> make() { return std::make_shared<Strand>(); }

private:
    void loop() {
        for (;;) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this] { return !m_queue.empty() || !m_running; });
                if (!m_running && m_queue.empty()) return;
                job = std::move(m_queue.front());
                m_queue.pop_front();
                m_busy = true;
            }
            if (job) job(); // outside the lock; exceptions are contained by callers
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_busy = false;
            }
        }
    }

    std::thread m_thread;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<Job> m_queue;
    bool m_running = false;
    bool m_busy = false;
};

} // namespace dvargosh::stdnet
