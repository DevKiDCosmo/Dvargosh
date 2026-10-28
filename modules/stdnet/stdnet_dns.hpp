#pragma once

// stdnet — DNS/IP resolution via getaddrinfo with a small TTL cache.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <algorithm>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace dvargosh::stdnet {

class DnsResolver {
public:
    explicit DnsResolver(int cache_ttl_seconds = 30);

    // Resolves host+service to a list of IPv4/IPv6 presentation strings.
    // Thread-safe; caches successful lookups for cache_ttl_seconds.
    std::vector<std::string> resolve(const std::string& host, const std::string& service);

    uint64_t cache_hits() const { return m_cache_hits; }
    uint64_t lookups() const { return m_lookups; }

private:
    struct CacheEntry {
        std::vector<std::string> ips;
        std::chrono::steady_clock::time_point expires;
    };

    int m_ttl_seconds;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, CacheEntry> m_cache;
    std::atomic<uint64_t> m_cache_hits{0};
    std::atomic<uint64_t> m_lookups{0};
};

} // namespace dvargosh::stdnet
