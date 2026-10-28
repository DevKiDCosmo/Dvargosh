#include "stdnet_service.hpp"
#include "dvargosh/event_bus.hpp"
#include "dvargosh/logger.hpp"
#include <algorithm>
#include <cstring>
#include <mutex>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

namespace dvargosh::stdnet {

namespace {
std::mutex g_instance_mutex;
std::shared_ptr<NetServiceImpl> g_instance;
} // namespace

void set_instance(std::shared_ptr<NetServiceImpl> svc) {
    std::lock_guard<std::mutex> lock(g_instance_mutex);
    g_instance = std::move(svc);
}

std::shared_ptr<NetServiceImpl> instance() {
    std::lock_guard<std::mutex> lock(g_instance_mutex);
    return g_instance;
}

// --- async completion events ----------------------------------------------------

void NetServiceImpl::publish(const std::string& topic, const std::string& payload) {
    if (m_event_bus) {
        (void)m_event_bus->publish(topic, Value(payload), "stdnet", nullptr);
    }
}

// --- DNS: reverse + async ----------------------------------------------------------

bool NetServiceImpl::resolve_reverse(const std::string& ip, std::string& out_name, std::string& error) {
    dns_lookup();
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (::inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) {
        error = "not a valid IPv4 literal: " + ip;
        return false;
    }
    char host[NI_MAXHOST] = {0};
    int rc = ::getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
                           host, sizeof(host), nullptr, 0, NI_NAMEREQD);
    if (rc != 0) {
        error = std::string("reverse lookup failed: ") + gai_strerror(rc);
        return false;
    }
    out_name = host;
    return true;
}

void NetServiceImpl::resolve_async(const std::string& host, const std::string& service, const std::string& tag) {
    m_reactor.post([this, host, service, tag] {
        auto ips = resolve(host, service);
        std::string joined;
        for (const auto& ip : ips) {
            if (!joined.empty()) joined += ",";
            joined += ip;
        }
        publish("net.dns.resolved", "tag=" + tag + " host=" + host + " ips=" + (joined.empty() ? "<none>" : joined));
    });
}

void NetServiceImpl::resolve_reverse_async(const std::string& ip, const std::string& tag) {
    m_reactor.post([this, ip, tag] {
        std::string name, error;
        if (resolve_reverse(ip, name, error)) {
            publish("net.dns.reverse_resolved", "tag=" + tag + " ip=" + ip + " name=" + name);
        } else {
            publish("net.dns.reverse_resolved", "tag=" + tag + " ip=" + ip + " error=" + error);
        }
    });
}

// --- TCP connection table ------------------------------------------------------

int64_t NetServiceImpl::tcp_open(const std::string& host, uint16_t port, int timeout_ms, std::string& error) {
    auto sock = std::make_unique<TcpSocket>();
    if (!sock->connect(host, port, timeout_ms, error)) return -1;
    conn_opened();
    std::lock_guard<std::mutex> lock(m_conns_mutex);
    const int64_t id = m_next_conn_id++;
    m_conns[id] = std::move(sock);
    return id;
}

int64_t NetServiceImpl::tcp_send(int64_t conn_id, const void* data, size_t len, std::string& error) {
    std::shared_ptr<TcpSocket> sock;
    {
        std::lock_guard<std::mutex> lock(m_conns_mutex);
        auto it = m_conns.find(conn_id);
        if (it == m_conns.end()) {
            error = "unknown connection id";
            return -1;
        }
        sock = std::shared_ptr<TcpSocket>(it->second.get(), [](TcpSocket*) {}); // non-owning view
    }
    // Rate limiting (when enabled): cost is KB; send refuses rather than stalls.
    if (m_rate_enabled && !m_rate_limiter.allow(static_cast<uint64_t>(conn_id),
                                                static_cast<double>(len) / 1024.0)) {
        error = "rate limit exceeded for connection";
        return -1;
    }
    if (!sock->send_all(data, len, kDefaultTimeoutMs, error)) return -1;
    tx(len);
    return static_cast<int64_t>(len);
}

std::string NetServiceImpl::tcp_recv(int64_t conn_id, size_t max_bytes, int timeout_ms, std::string& error) {
    std::shared_ptr<TcpSocket> sock;
    {
        std::lock_guard<std::mutex> lock(m_conns_mutex);
        auto it = m_conns.find(conn_id);
        if (it == m_conns.end()) {
            error = "unknown connection id";
            return "";
        }
        sock = std::shared_ptr<TcpSocket>(it->second.get(), [](TcpSocket*) {}); // non-owning view
    }
    std::vector<uint8_t> buf;
    if (!sock->recv_some(buf, std::min(max_bytes, kMaxRecvBytes), timeout_ms, error)) return "";
    rx(buf.size());
    return std::string(buf.begin(), buf.end());
}

bool NetServiceImpl::tcp_close(int64_t conn_id) {
    std::lock_guard<std::mutex> lock(m_conns_mutex);
    return m_conns.erase(conn_id) > 0;
}

size_t NetServiceImpl::close_all() {
    std::lock_guard<std::mutex> lock(m_conns_mutex);
    size_t n = m_conns.size() + m_uds_conns.size() + m_ws_conns.size();
    m_conns.clear();
    m_uds_conns.clear();
    m_ws_conns.clear();
    if (m_http_server) {
        m_http_server->stop();
    }
    return n;
}

// --- UDP -----------------------------------------------------------------------

bool NetServiceImpl::udp_send(const std::string& host, uint16_t port, const void* data, size_t len, std::string& error) {
    UdpSocket sock;
    if (!sock.open(error)) return false;
    if (!sock.send_to(host, port, data, len, kDefaultTimeoutMs, error)) return false;
    tx(len);
    return true;
}

bool NetServiceImpl::udp_roundtrip(const std::string& host, uint16_t port, const void* data, size_t len,
                                   int timeout_ms, std::string& out, std::string& error) {
    UdpSocket sock;
    if (!sock.open(error)) return false;
    if (!sock.send_to(host, port, data, len, timeout_ms, error)) return false;
    tx(len);
    std::vector<uint8_t> buf;
    if (!sock.recv_from(buf, std::min(kMaxRecvBytes, static_cast<size_t>(65536)), timeout_ms, error)) return false;
    rx(buf.size());
    out.assign(buf.begin(), buf.end());
    return true;
}

// --- HTTP ----------------------------------------------------------------------

namespace {
std::string trim_h(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1);
}
} // namespace

bool NetServiceImpl::http_exchange(
    const std::string& method,
    const std::string& raw_uri,
    const std::string& extra_headers,
    const std::string& body,
    int timeout_ms,
    bool body_only,
    std::string& out,
    std::string& error
) {
    http_request();
    Uri uri = parse_uri(raw_uri);
    if (!uri.valid) {
        error = uri.error;
        return false;
    }
    if (uri.is_tls_scheme()) {
        error = "stdnet does not implement TLS: use a TLS-terminating proxy for '" + uri.scheme + "' targets";
        return false;
    }
    if (!uri.apply_scheme_defaults()) {
        error = "URI missing port and no default for scheme '" + uri.scheme + "'";
        return false;
    }

    HttpRequest req;
    req.method = method.empty() ? "GET" : method;
    req.target = uri.request_target();
    if (!body.empty() && req.method != "GET" && req.method != "HEAD") {
        req.body.assign(body.begin(), body.end());
    }
    // extra_headers: "Key: Value" lines separated by newline.
    size_t pos = 0;
    while (pos < extra_headers.size()) {
        auto eol = extra_headers.find('\n', pos);
        std::string line = extra_headers.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
        pos = (eol == std::string::npos) ? extra_headers.size() : eol + 1;
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            req.headers[trim_h(line.substr(0, colon))] = trim_h(line.substr(colon + 1));
        }
    }

    const std::string wire = build_http_request(req, uri.host_header());

    TcpSocket sock;
    if (!sock.connect(uri.host, uri.port, timeout_ms, error)) return false;
    if (!sock.send_all(wire.data(), wire.size(), timeout_ms, error)) return false;
    tx(wire.size());

    // Read until peer closes (Connection: close) with a hard size cap.
    std::string raw;
    std::vector<uint8_t> buf;
    while (raw.size() < kMaxRecvBytes) {
        buf.clear();
        if (!sock.recv_some(buf, 65536, timeout_ms, error)) {
            break; // peer closed or timeout: parse what we have
        }
        raw.append(reinterpret_cast<const char*>(buf.data()), buf.size());
        rx(buf.size());
    }
    if (raw.empty()) {
        if (error.empty()) error = "empty response";
        return false;
    }

    HttpResponse resp;
    if (!parse_http_response(raw, resp, error)) return false;
    out = body_only ? resp.body_string() : raw;
    return true;
}

// --- UDS ---------------------------------------------------------------------------

int64_t NetServiceImpl::uds_open(const std::string& path, std::string& error) {
    auto sock = std::make_unique<UdsStream>();
    if (!sock->connect(path, kDefaultTimeoutMs, error)) return -1;
    std::lock_guard<std::mutex> lock(m_conns_mutex);
    const int64_t id = m_next_conn_id++;
    m_uds_conns[id] = std::move(sock);
    return id;
}

int64_t NetServiceImpl::uds_send(int64_t conn_id, const void* data, size_t len, std::string& error) {
    std::shared_ptr<UdsStream> sock;
    {
        std::lock_guard<std::mutex> lock(m_conns_mutex);
        auto it = m_uds_conns.find(conn_id);
        if (it == m_uds_conns.end()) {
            error = "unknown uds connection id";
            return -1;
        }
        sock = std::shared_ptr<UdsStream>(it->second.get(), [](UdsStream*) {});
    }
    if (!sock->send_all(data, len, kDefaultTimeoutMs, error)) return -1;
    tx(len);
    return static_cast<int64_t>(len);
}

std::string NetServiceImpl::uds_recv(int64_t conn_id, size_t max_bytes, int timeout_ms, std::string& error) {
    std::shared_ptr<UdsStream> sock;
    {
        std::lock_guard<std::mutex> lock(m_conns_mutex);
        auto it = m_uds_conns.find(conn_id);
        if (it == m_uds_conns.end()) {
            error = "unknown uds connection id";
            return "";
        }
        sock = std::shared_ptr<UdsStream>(it->second.get(), [](UdsStream*) {});
    }
    std::vector<uint8_t> buf;
    if (!sock->recv_some(buf, std::min(max_bytes, kMaxRecvBytes), timeout_ms, error)) return "";
    rx(buf.size());
    return std::string(buf.begin(), buf.end());
}

bool NetServiceImpl::uds_close(int64_t conn_id) {
    std::lock_guard<std::mutex> lock(m_conns_mutex);
    return m_uds_conns.erase(conn_id) > 0;
}

// --- WebSockets ----------------------------------------------------------------------

int64_t NetServiceImpl::ws_connect(const std::string& raw_uri, int timeout_ms, std::string& error) {
    Uri uri = parse_uri(raw_uri);
    if (!uri.valid) {
        error = uri.error;
        return -1;
    }
    if (uri.is_tls_scheme()) {
        error = "wss (TLS websockets) not supported; use ws:// targets";
        return -1;
    }
    if (!uri.apply_scheme_defaults()) {
        error = "URI missing usable port";
        return -1;
    }

    auto tcp = std::make_unique<TcpSocket>();
    if (!tcp->connect(uri.host, uri.port, timeout_ms, error)) return -1;

    auto ws = std::make_unique<WsConnection>(std::move(*tcp));
    if (!ws->handshake(uri.host_header(), uri.request_target(), timeout_ms, error)) return -1;

    std::lock_guard<std::mutex> lock(m_conns_mutex);
    const int64_t id = m_next_conn_id++;
    m_ws_conns[id] = std::move(ws);
    return id;
}

bool NetServiceImpl::ws_send(int64_t conn_id, const std::string& text, std::string& error) {
    std::shared_ptr<WsConnection> ws;
    {
        std::lock_guard<std::mutex> lock(m_conns_mutex);
        auto it = m_ws_conns.find(conn_id);
        if (it == m_ws_conns.end()) {
            error = "unknown ws connection id";
            return false;
        }
        ws = std::shared_ptr<WsConnection>(it->second.get(), [](WsConnection*) {});
    }
    return ws->send_text(text, error);
}

std::string NetServiceImpl::ws_recv(int64_t conn_id, int timeout_ms, std::string& error) {
    std::shared_ptr<WsConnection> ws;
    {
        std::lock_guard<std::mutex> lock(m_conns_mutex);
        auto it = m_ws_conns.find(conn_id);
        if (it == m_ws_conns.end()) {
            error = "unknown ws connection id";
            return "";
        }
        ws = std::shared_ptr<WsConnection>(it->second.get(), [](WsConnection*) {});
    }
    WsFrame f;
    for (;;) {
        if (!ws->recv_frame(f, timeout_ms, error)) return "";
        if (f.opcode == WsOpcode::Text) return std::string(f.payload.begin(), f.payload.end());
        if (f.opcode == WsOpcode::Binary) return std::string(f.payload.begin(), f.payload.end());
        if (f.opcode == WsOpcode::Close) {
            error = "websocket closed by peer";
            return "";
        }
        // Ping answered inside recv_frame; other control frames skipped.
    }
}

bool NetServiceImpl::ws_close(int64_t conn_id) {
    std::lock_guard<std::mutex> lock(m_conns_mutex);
    return m_ws_conns.erase(conn_id) > 0;
}

// --- HTTPS via OpenSSL ------------------------------------------------------------------

bool NetServiceImpl::https_exchange(
    const std::string& method,
    const std::string& raw_uri,
    const std::string& extra_headers,
    const std::string& body,
    int timeout_ms,
    bool body_only,
    std::string& out,
    std::string& error
) {
    http_request();
    Uri uri = parse_uri(raw_uri);
    if (!uri.valid) {
        error = uri.error;
        return false;
    }
    if (!uri.is_tls_scheme()) {
        error = "https_exchange requires an https:// URI";
        return false;
    }
    if (!uri.apply_scheme_defaults()) {
        error = "URI missing port";
        return false;
    }

    HttpRequest req;
    req.method = method.empty() ? "GET" : method;
    req.target = uri.request_target();
    if (!body.empty() && req.method != "GET" && req.method != "HEAD") {
        req.body.assign(body.begin(), body.end());
    }
    const std::string wire = build_http_request(req, uri.host_header());

    TcpSocket tcp;
    if (!tcp.connect(uri.host, uri.port, timeout_ms, error)) return false;

    TlsSocket tls;
    if (!tls.connect(uri.host, std::move(tcp), timeout_ms, error)) return false;

    if (!tls.send_all(wire.data(), wire.size(), error)) return false;
    tx(wire.size());

    std::string raw;
    std::vector<uint8_t> buf;
    while (raw.size() < kMaxRecvBytes) {
        if (!tls.recv_some(buf, 65536, timeout_ms, error)) break;
        raw.append(reinterpret_cast<const char*>(buf.data()), buf.size());
        rx(buf.size());
    }
    if (raw.empty()) {
        if (error.empty()) error = "empty TLS response";
        return false;
    }
    HttpResponse resp;
    if (!parse_http_response(raw, resp, error)) return false;
    out = body_only ? resp.body_string() : raw;
    return true;
}

// --- built-in HTTP/1.1 server -------------------------------------------------------------

bool NetServiceImpl::http_server_listen(uint16_t port, std::string& error) {
    if (m_http_server && m_http_server->running()) {
        m_http_server->stop();
    }
    m_http_server = std::make_unique<HttpServer>(m_reactor);
    auto handler = [this](const HttpRequest& req) -> HttpResponseSpec {
        http_request();
        // Echo handler: proves request parsing + strand serialization; returns
        // a JSON-ish summary the tests assert on.
        std::string host = req.headers.count("host") ? req.headers.at("host") : "";
        std::string body = "{\"method\":\"" + req.method +
                           "\",\"target\":\"" + req.target +
                           "\",\"host\":\"" + host +
                           "\",\"body_bytes\":" + std::to_string(req.body.size()) + "}";
        HttpResponseSpec spec;
        spec.status = 200;
        spec.reason = "OK";
        spec.content_type = "application/json";
        spec.body = std::move(body);
        return spec;
    };
    return m_http_server->listen(port, std::move(handler), error);
}

bool NetServiceImpl::http_server_stop() {
    if (!m_http_server) return false;
    m_http_server->stop();
    return true;
}

} // namespace dvargosh::stdnet
