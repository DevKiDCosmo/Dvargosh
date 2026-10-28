#pragma once

// stdnet — C++20 coroutine support: task<T> plus awaiters for reactor timers
// and posted work. Asynchronous code reads sequentially:
//
//   dvargosh::stdnet::task<int> probe(Reactor& r) {
//       co_await async_delay(r, 100);   // steady timer, non-blocking
//       co_return 42;
//   }

#include <atomic>
#include <coroutine>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <variant>

#include "stdnet_reactor.hpp"

namespace dvargosh::stdnet {

// --- task<T> -------------------------------------------------------------------

template <typename T>
class task;

namespace coro_detail {

struct task_promise_base {
    struct final_awaiter {
        bool await_ready() const noexcept { return false; }
        template <typename P>
        std::coroutine_handle<> await_suspend(P h) noexcept {
            auto cont = h.promise().continuation;
            return cont ? cont : std::noop_coroutine();
        }
        void await_resume() const noexcept {}
    };

    std::coroutine_handle<> continuation = nullptr;
    std::atomic<bool> started{false};

    task_promise_base() = default;
};

} // namespace coro_detail

template <typename T = void>
class [[nodiscard]] task {
public:
    struct promise_type : coro_detail::task_promise_base {
        std::variant<std::monostate, T, std::exception_ptr> result;

        task get_return_object() {
            return task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_always initial_suspend() noexcept { return {}; }
        final_awaiter final_suspend() noexcept { return {}; }
        void return_value(T v) { result.template emplace<1>(std::move(v)); }
        void unhandled_exception() { result.template emplace<2>(std::current_exception()); }
    };

    task() = default;
    explicit task(std::coroutine_handle<promise_type> h) : m_handle(h) {}
    task(task&& o) noexcept : m_handle(std::exchange(o.m_handle, {})) {}
    task& operator=(task&& o) noexcept {
        if (this != &o) {
            if (m_handle) m_handle.destroy();
            m_handle = std::exchange(o.m_handle, {});
        }
        return *this;
    }
    task(const task&) = delete;
    task& operator=(const task&) = delete;

    ~task() {
        if (m_handle) m_handle.destroy();
    }

    auto operator co_await() {
        struct awaiter {
            std::coroutine_handle<promise_type> h;
            bool await_ready() const noexcept { return !h || h.done(); }
            std::coroutine_handle<> await_suspend(std::coroutine_handle<> cont) noexcept {
                h.promise().continuation = cont;
                if (!h.promise().started.exchange(true)) h.resume();
                return std::noop_coroutine();
            }
            T await_resume() {
                auto& r = h.promise().result;
                if (r.index() == 2) std::rethrow_exception(std::get<2>(r));
                return std::move(std::get<1>(r));
            }
        };
        return awaiter{m_handle};
    }

    bool valid() const { return static_cast<bool>(m_handle); }

    // Starts the coroutine if not yet started (lazy tasks).
    void start() {
        if (m_handle && !m_handle.done() && !m_handle.promise().started.exchange(true)) {
            m_handle.resume();
        }
    }

private:
    std::coroutine_handle<promise_type> m_handle = nullptr;
};

// void specialization
template <>
class [[nodiscard]] task<void> {
public:
    struct promise_type : coro_detail::task_promise_base {
        std::exception_ptr error;

        task get_return_object() {
            return task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_always initial_suspend() noexcept { return {}; }
        final_awaiter final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() { error = std::current_exception(); }
    };

    task() = default;
    explicit task(std::coroutine_handle<promise_type> h) : m_handle(h) {}
    task(task&& o) noexcept : m_handle(std::exchange(o.m_handle, {})) {}
    task& operator=(task&& o) noexcept {
        if (this != &o) {
            if (m_handle) m_handle.destroy();
            m_handle = std::exchange(o.m_handle, {});
        }
        return *this;
    }
    task(const task&) = delete;
    task& operator=(const task&) = delete;

    ~task() {
        if (m_handle) m_handle.destroy();
    }

    auto operator co_await() {
        struct awaiter {
            std::coroutine_handle<promise_type> h;
            bool await_ready() const noexcept { return !h || h.done(); }
            std::coroutine_handle<> await_suspend(std::coroutine_handle<> cont) noexcept {
                h.promise().continuation = cont;
                if (!h.promise().started.exchange(true)) h.resume();
                return std::noop_coroutine();
            }
            void await_resume() {
                if (h.promise().error) std::rethrow_exception(h.promise().error);
            }
        };
        return awaiter{m_handle};
    }

    bool valid() const { return static_cast<bool>(m_handle); }

    void start() {
        if (m_handle && !m_handle.done() && !m_handle.promise().started.exchange(true)) {
            m_handle.resume();
        }
    }

private:
    std::coroutine_handle<promise_type> m_handle = nullptr;
};

// --- awaitables -----------------------------------------------------------------

// co_await async_delay(reactor, ms): resumes on the reactor thread after ms.
struct async_delay {
    Reactor& reactor;
    int ms;
    explicit async_delay(Reactor& r, int milliseconds) : reactor(r), ms(milliseconds) {}

    bool await_ready() const noexcept { return ms <= 0; }
    void await_suspend(std::coroutine_handle<> h) {
        reactor.timer_after(ms, [h] { h.resume(); });
    }
    void await_resume() const noexcept {}
};

// co_await async_post(reactor, job): runs job on the reactor thread, then resumes.
struct async_post {
    Reactor& reactor;
    ReactorJob job;
    async_post(Reactor& r, ReactorJob j) : reactor(r), job(std::move(j)) {}

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> h) {
        reactor.post([this, h] {
            if (job) job();
            h.resume();
        });
    }
    void await_resume() const noexcept {}
};

// --- sync driver (tests / service entry points) --------------------------------------

// Blocks the calling thread until the task completes; continuations run on the
// reactor while waiting. Exceptions from the task propagate to the caller.
template <typename T>
T sync_wait(task<T>& t, Reactor& reactor) {
    (void)reactor; // the wait is event-driven via the task's own continuations
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    std::optional<T> value;
    std::exception_ptr error;

    auto runner = [&]() -> task<void> {
        try {
            if constexpr (std::is_void_v<T>) {
                co_await t;
            } else {
                value = co_await t;
            }
        } catch (...) {
            error = std::current_exception();
        }
        {
            std::lock_guard<std::mutex> lock(m);
            done = true;
        }
        cv.notify_all();
    };
    task<void> outer = runner();
    outer.start(); // runs on this thread until the first real suspension

    std::unique_lock<std::mutex> lock(m);
    cv.wait(lock, [&] { return done; });

    if (error) std::rethrow_exception(error);
    if constexpr (!std::is_void_v<T>) {
        return std::move(*value);
    }
}

} // namespace dvargosh::stdnet
