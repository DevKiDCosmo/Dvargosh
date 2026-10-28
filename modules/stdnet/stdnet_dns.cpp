#include "stdnet_dns.hpp"
#include <chrono>
#include <cstring>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

namespace dvargosh::stdnet {

DnsResolver::DnsResolver(int cache_ttl_seconds) : m_ttl_seconds(cache_ttl_seconds) {}

std::vector<std::string> DnsResolver::resolve(const std::string& host, const std::string& service) {
    m_lookups++;

    const std::string key = host + ":" + service;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_cache.find(key);
        if (it != m_cache.end() && std::chrono::steady_clock::now() < it->second.expires) {
            m_cache_hits++;
            return it->second.ips;
        }
    }

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;    // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    int rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &result);
    if (rc != 0 || !result) {
        return {};
    }

    std::vector<std::string> ips;
    for (struct addrinfo* ai = result; ai; ai = ai->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {0};
        const void* addr = nullptr;
        if (ai->ai_family == AF_INET) {
            addr = &reinterpret_cast<struct sockaddr_in*>(ai->ai_addr)->sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            addr = &reinterpret_cast<struct sockaddr_in6*>(ai->ai_addr)->sin6_addr;
        }
        if (addr && ::inet_ntop(ai->ai_family, addr, buf, sizeof(buf))) {
            std::string ip(buf);
            if (std::find(ips.begin(), ips.end(), ip) == ips.end()) {
                ips.push_back(std::move(ip));
            }
        }
    }
    ::freeaddrinfo(result);

    if (!ips.empty() && m_ttl_seconds > 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cache[key] = CacheEntry{
            ips,
            std::chrono::steady_clock::now() + std::chrono::seconds(m_ttl_seconds)
        };
    }
    return ips;
}

} // namespace dvargosh::stdnet
