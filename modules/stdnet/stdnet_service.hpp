#pragma once

// stdnet — service core: connection tables, DNS cache, HTTP, telemetry, plus the
// async runtime (reactor, timers, strands, coroutines), UDS, TLS, WebSockets,
// framing, rate limiting, and logging hooks.
// One instance per module (the runtime rejects duplicate module names); accessed
// by the free binder-target functions through set_instance()/instance().

#include "stdnet_uri.hpp"
#include "stdnet_dns.hpp"
#include "stdnet_socket.hpp"
#include "stdnet_http.hpp"
#include "stdnet_reactor.hpp"
#include "stdnet_strand.hpp"
#include "stdnet_buffer.hpp"
#include "stdnet_framing.hpp"
#include "stdnet_flow.hpp"
#include "stdnet_uds.hpp"
#include "stdnet_tls.hpp"
#include "stdnet_ws.hpp"
#include "stdnet_http_server.hpp"
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
    explicit NetServiceImpl(TelemetryHub* hub)
        : m_hub(hub), m_dns(30), m_rate_limiter(1024.0 * 1024.0, 4.0 * 1024.0 * 1024.0) {}

    // Late wiring from on_load (EventBus for async completions).
    void set_event_bus(std::shared_ptr<EventBus> bus) { m_event_bus = std::move(bus); }

    // --- runtime surfaces --------------------------------------------------------

    Reactor& reactor() { return m_reactor; }
    NetHooks& hooks() { return m_hooks; }
    RateLimiter& rate_limiter() { return m_rate_limiter; }
    BufferPool& pool() { return m_pool; }
    void set_rate_enabled(bool on) { m_rate_enabled = on; }
    bool rate_enabled() const { return m_rate_enabled; }

    // Telemetry (streams: net.bytes_tx / net.bytes_rx / net.connections.opened /
    // net.dns.lookups / net.http.requests — visible in monitor.hub_snapshot).
    void tx(size_t n) {
        if (m_hub) m_hub->increment("net.bytes_tx", static_cast<double>(n));
        m_hooks.report_bytes("tx", "", n);
    }
    void rx(size_t n) {
        if (m_hub) m_hub->increment("net.bytes_rx", static_cast<double>(n));
        m_hooks.report_bytes("rx", "", n);
    }
    void conn_opened() { if (m_hub) m_hub->increment("net.connections.opened"); }
    void dns_lookup() { if (m_hub) m_hub->increment("net.dns.lookups"); }
    void http_request() { if (m_hub) m_hub->increment("net.http.requests"); }

    uint64_t dns_cache_hits() const { return m_dns.cache_hits(); }
    uint64_t dns_lookups() const { return m_dns.lookups(); }

    std::vector<std::string> resolve(const std::string& host, const std::string& service) {
        dns_lookup();
        return m_dns.resolve(host, service.empty() ? "0" : service);
    }

    // Reverse lookup (IP -> hostname) via getnameinfo.
    bool resolve_reverse(const std::string& ip, std::string& out_name, std::string& error);

    // Async DNS: resolve on a reactor worker; completion published as
    // net.dns.resolved / net.dns.reverse_resolved events with a caller tag.
    void resolve_async(const std::string& host, const std::string& service, const std::string& tag);
    void resolve_reverse_async(const std::string& ip, const std::string& tag);

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

    // --- Unix domain sockets (own table; ids share the TCP counter space) ---

    int64_t uds_open(const std::string& path, std::string& error);
    int64_t uds_send(int64_t conn_id, const void* data, size_t len, std::string& error);
    std::string uds_recv(int64_t conn_id, size_t max_bytes, int timeout_ms, std::string& error);
    bool uds_close(int64_t conn_id);

    // --- WebSockets (client, over TCP) ---

    int64_t ws_connect(const std::string& raw_uri, int timeout_ms, std::string& error);
    bool ws_send(int64_t conn_id, const std::string& text, std::string& error);
    std::string ws_recv(int64_t conn_id, int timeout_ms, std::string& error); // first Text/Binary frame
    bool ws_close(int64_t conn_id);

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

    // HTTPS via the OpenSSL wrapper when built with TLS support.
    bool https_exchange(
        const std::string& method,
        const std::string& raw_uri,
        const std::string& extra_headers,
        const std::string& body,
        int timeout_ms,
        bool body_only,
        std::string& out,
        std::string& error
    );

    // --- built-in HTTP/1.1 server (echo/JSON handler; loopback only) ---

    bool http_server_listen(uint16_t port, std::string& error);
    bool http_server_stop();
    uint16_t http_server_port() const { return m_http_server ? m_http_server->port() : 0; }

private:
    TelemetryHub* m_hub = nullptr;
    DnsResolver m_dns;
    Reactor m_reactor;
    NetHooks m_hooks;
    RateLimiter m_rate_limiter;
    BufferPool m_pool{4096, 64};
    std::shared_ptr<EventBus> m_event_bus;
    bool m_rate_enabled = false;
    std::unique_ptr<HttpServer> m_http_server;

    std::mutex m_conns_mutex;
    std::map<int64_t, std::unique_ptr<TcpSocket>> m_conns;
    std::map<int64_t, std::unique_ptr<UdsStream>> m_uds_conns;
    std::map<int64_t, std::unique_ptr<WsConnection>> m_ws_conns;
    int64_t m_next_conn_id = 1;

    void publish(const std::string& topic, const std::string& payload);
};

// Process-level instance binding (set by StdNetModule::on_load, cleared on_unload).
void set_instance(std::shared_ptr<NetServiceImpl> svc);
std::shared_ptr<NetServiceImpl> instance();

} // namespace dvargosh::stdnet
