#include "stdnet_service.hpp"
#include <algorithm>
#include <mutex>

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
    const size_t n = m_conns.size();
    m_conns.clear();
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

} // namespace dvargosh::stdnet
