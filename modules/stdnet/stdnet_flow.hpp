#pragma once

// stdnet — Rate limiting (token bucket) and logging hooks.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace dvargosh::stdnet {

// --- TokenBucket: refills at rate tokens/sec up to burst capacity ---------------

class TokenBucket {
public:
    TokenBucket(double rate_per_sec, double burst_capacity)
        : m_rate(rate_per_sec), m_burst(burst_capacity), m_tokens(burst_capacity) {}

    // Consumes n tokens if available; returns false (and consumes nothing) otherwise.
    bool try_consume(double n = 1.0) {
        refill();
        if (m_tokens < n) return false;
        m_tokens -= n;
        return true;
    }

    double available() {
        refill();
        return m_tokens;
    }

private:
    void refill() {
        auto now = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(now - m_last).count();
        if (secs <= 0) return;
        m_last = now;
        m_tokens = std::min(m_burst, m_tokens + secs * m_rate);
    }

    double m_rate;
    double m_burst;
    double m_tokens;
    std::chrono::steady_clock::time_point m_last{std::chrono::steady_clock::now()};
};

// Per-key rate limiter (e.g. per connection id or remote endpoint).
class RateLimiter {
public:
    RateLimiter(double rate_per_sec, double burst_capacity)
        : m_rate(rate_per_sec), m_burst(burst_capacity) {}

    // Reconfigures all future and existing buckets (rate in tokens/sec = KB/s
    // for byte-cost usage). Called rarely (configuration), so a full rebuild
    // of buckets under the lock is acceptable.
    void reset_config(double rate_per_sec, double burst_capacity) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_rate = rate_per_sec;
        m_burst = burst_capacity;
        m_buckets.clear();
    }

    bool allow(uint64_t key, double cost = 1.0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_buckets.find(key);
        if (it == m_buckets.end()) {
            it = m_buckets.emplace(key, TokenBucket(m_rate, m_burst)).first;
        }
        return it->second.try_consume(cost);
    }

    void forget(uint64_t key) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buckets.erase(key);
    }

private:
    double m_rate;
    double m_burst;
    std::mutex m_mutex;
    std::unordered_map<uint64_t, TokenBucket> m_buckets;
};

// --- Logging hooks: extensible callbacks for bytes, latency, errors --------------

class NetHooks {
public:
    using BytesHook = std::function<void(const std::string& direction, const std::string& peer, size_t bytes)>;
    using LatencyHook = std::function<void(const std::string& operation, double ms)>;
    using ErrorHook = std::function<void(const std::string& operation, const std::string& error)>;

    void on_bytes(BytesHook hook) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_bytes.push_back(std::move(hook));
    }
    void on_latency(LatencyHook hook) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_latency.push_back(std::move(hook));
    }
    void on_error(ErrorHook hook) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_errors.push_back(std::move(hook));
    }

    void report_bytes(const std::string& direction, const std::string& peer, size_t bytes) {
        std::vector<BytesHook> hs;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            hs = m_bytes;
        }
        for (auto& h : hs) if (h) h(direction, peer, bytes);
    }
    void report_latency(const std::string& operation, double ms) {
        std::vector<LatencyHook> hs;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            hs = m_latency;
        }
        for (auto& h : hs) if (h) h(operation, ms);
    }
    void report_error(const std::string& operation, const std::string& error) {
        std::vector<ErrorHook> hs;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            hs = m_errors;
        }
        for (auto& h : hs) if (h) h(operation, error);
    }

private:
    std::mutex m_mutex;
    std::vector<BytesHook> m_bytes;
    std::vector<LatencyHook> m_latency;
    std::vector<ErrorHook> m_errors;
};

} // namespace dvargosh::stdnet
