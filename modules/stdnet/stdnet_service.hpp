#pragma once

// stdnet — service core: connection table, DNS cache, HTTP exchange, telemetry.
// One instance per module (the runtime rejects duplicate module names); accessed
// by the free binder-target functions through set_instance()/instance().

#include "stdnet_uri.hpp"
#include "stdnet_dns.hpp"
#include "stdnet_socket.hpp"
#include "stdnet_http.hpp"
#include "dvargosh/telemetry.hpp"
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace dvargosh::stdnet {

constexpr int kDefaultTimeoutMs = 5000;
constexpr size_t kMaxRecvBytes = 1024 * 1024; // 1 MiB hard cap per read

class NetServiceImpl {
public:
    explicit NetServiceImpl(TelemetryHub* hub) : m_hub(hub), m_dns(30) {}

    // Telemetry (streams: net.bytes_tx / net.bytes_rx / net.connections.opened /
    // net.dns.lookups / net.http.requests — visible in monitor.hub_snapshot).
    void tx(size_t n) { if (m_hub) m_hub->increment("net.bytes_tx", static_cast<double>(n)); }
    void rx(size_t n) { if (m_hub) m_hub->increment("net.bytes_rx", static_cast<double>(n)); }
    void conn_opened() { if (m_hub) m_hub->increment("net.connections.opened"); }
    void dns_lookup() { if (m_hub) m_hub->increment("net.dns.lookups"); }
    void http_request() { if (m_hub) m_hub->increment("net.http.requests"); }

    uint64_t dns_cache_hits() const { return m_dns.cache_hits(); }
    uint64_t dns_lookups() const { return m_dns.lookups(); }

    std::vector<std::string> resolve(const std::string& host, const std::string& service) {
        dns_lookup();
        return m_dns.resolve(host, service.empty() ? "0" : service);
    }

    // --- TCP connection table (module-owned, closed on unload) ---

    int64_t tcp_open(const std::string& host, uint16_t port, int timeout_ms, std::string& error);
    int64_t tcp_send(int64_t conn_id, const void* data, size_t len, std::string& error);
    std::string tcp_recv(int64_t conn_id, size_t max_bytes, int timeout_ms, std::string& error);
    bool tcp_close(int64_t conn_id);
    size_t close_all();

    // --- UDP ---

    bool udp_send(const std::string& host, uint16_t port, const void* data, size_t len, std::string& error);
    bool udp_roundtrip(const std::string& host, uint16_t port, const void* data, size_t len,
                       int timeout_ms, std::string& out, std::string& error);

    // --- HTTP/1.1 (plain TCP, Connection: close) ---

    bool http_exchange(
        const std::string& method,
        const std::string& raw_uri,
        const std::string& extra_headers,
        const std::string& body,
        int timeout_ms,
        bool body_only,
        std::string& out,
        std::string& error
    );

private:
    TelemetryHub* m_hub = nullptr;
    DnsResolver m_dns;
    std::mutex m_conns_mutex;
    std::map<int64_t, std::unique_ptr<TcpSocket>> m_conns;
    int64_t m_next_conn_id = 1;
};

// Process-level instance binding (set by StdNetModule::on_load, cleared on_unload).
void set_instance(std::shared_ptr<NetServiceImpl> svc);
std::shared_ptr<NetServiceImpl> instance();

} // namespace dvargosh::stdnet
