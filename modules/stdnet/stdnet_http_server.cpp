#include "stdnet_http_server.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace dvargosh::stdnet {

namespace {
constexpr size_t kMaxHeadBytes = 64 * 1024;

std::string status_reason(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 422: return "Unprocessable Entity";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 503: return "Service Unavailable";
        default: return "Status";
    }
}
} // namespace

bool HttpServer::listen(uint16_t port, HttpHandler handler, std::string& error) {
    stop();
    m_handler = std::move(handler);

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        error = std::string("http server socket: ") + std::strerror(errno);
        return false;
    }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // module services bind loopback only
    addr.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        error = std::string("http server bind: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }
    if (::listen(fd, 16) != 0) {
        error = std::string("http server listen: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }

    socklen_t len = sizeof(addr);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
    m_port = ntohs(addr.sin_port);
    m_listen_fd = fd;

    // Edge-triggered reactor: accept in a loop until EAGAIN.
    m_reactor.watch_fd(fd, true, false, [this](int f, bool r, bool w, bool h) {
        on_listen_event(f, r, w, h);
    });
    return true;
}

void HttpServer::stop() {
    if (m_listen_fd >= 0) {
        m_reactor.unwatch_fd(m_listen_fd);
        ::close(m_listen_fd);
        m_listen_fd = -1;
    }
    for (auto& [fd, conn] : m_conns) {
        m_reactor.unwatch_fd(fd);
        ::close(fd);
    }
    m_conns.clear();
}

void HttpServer::on_listen_event(int fd, bool readable, bool, bool) {
    if (!readable || fd != m_listen_fd) return;
    for (;;) { // drain the accept queue (edge-triggered backend)
        int c = ::accept(fd, nullptr, nullptr);
        if (c < 0) break;
        if (!m_reactor.watch_fd(c, true, false, [this](int f, bool r, bool w, bool h) {
                on_conn_event(f, r, w, h);
            })) {
            ::close(c);
            continue;
        }
        m_conns[c] = std::make_unique<Conn>();
    }
}

void HttpServer::on_conn_event(int fd, bool readable, bool, bool hungup) {
    auto it = m_conns.find(fd);
    if (it == m_conns.end()) return;

    if (hungup && !readable) {
        m_reactor.unwatch_fd(fd);
        ::close(fd);
        m_conns.erase(it);
        return;
    }

    auto& conn = *it->second;
    uint8_t buf[16384];
    bool got = false, err = false;
    while (readable) { // edge-triggered: drain until EAGAIN
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            conn.in.append(buf, static_cast<size_t>(n));
            got = true;
            if (n < static_cast<ssize_t>(sizeof(buf))) break;
            continue;
        }
        if (n == 0) { err = true; break; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        err = true;
        break;
    }
    if (!got && err) {
        m_reactor.unwatch_fd(fd);
        ::close(fd);
        m_conns.erase(it);
        return;
    }
    if (conn.in.empty() || conn.in.size() > kMaxHeadBytes + 32u * 1024u * 1024u) {
        if (conn.in.size() > kMaxHeadBytes + 32u * 1024u * 1024u) conn.closing = true;
        if (!got) return;
    }

    HttpRequest req;
    std::string perr;
    int rc = parse_http_request_stream(conn.in, req, perr);
    if (rc == 0) return; // wait for more bytes
    if (rc < 0) {
        HttpResponseSpec bad;
        bad.status = 400;
        bad.reason = "Bad Request";
        bad.body = perr;
        m_reactor.post([this, fd, spec = std::move(bad)]() mutable {
            m_strand->post([this, fd, spec = std::move(spec)]() mutable {
                write_response_and_close(fd, spec);
            });
        });
        return;
    }

    // Handler runs on the strand — serialized with all other request handling.
    m_reactor.post([this, fd, req = std::move(req)]() mutable {
        m_strand->post([this, fd, req = std::move(req)]() mutable {
            HttpResponseSpec spec;
            try {
                if (m_handler) spec = m_handler(req);
            } catch (const std::exception& e) {
                spec.status = 500;
                spec.reason = "Internal Server Error";
                spec.body = e.what();
            } catch (...) {
                spec.status = 500;
                spec.reason = "Internal Server Error";
                spec.body = "handler exception";
            }
            write_response_and_close(fd, spec);
        });
    });
}

void HttpServer::write_response_and_close(int fd, const HttpResponseSpec& spec) {
    std::string head =
        "HTTP/1.1 " + std::to_string(spec.status) + " " +
        (spec.reason.empty() ? status_reason(spec.status) : spec.reason) + "\r\n" +
        "Content-Type: " + spec.content_type + "\r\n" +
        "Content-Length: " + std::to_string(spec.body.size()) + "\r\n" +
        "Connection: close\r\n";
    for (const auto& [k, v] : spec.extra_headers) {
        head += k + ": " + v + "\r\n";
    }
    head += "\r\n";

    std::string wire = head + spec.body;
    size_t sent = 0;
    while (sent < wire.size()) {
        ssize_t n = ::send(fd, wire.data() + sent, wire.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }

    m_reactor.unwatch_fd(fd);
    ::close(fd);
    m_conns.erase(fd);
}

} // namespace dvargosh::stdnet
