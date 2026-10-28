#include "stdnet_socket.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace dvargosh::stdnet {

int poll_fd(int fd, bool want_read, bool want_write, int timeout_ms) {
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = static_cast<short>((want_read ? POLLIN : 0) | (want_write ? POLLOUT : 0));
    int rc = ::poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return rc;                 // 0 = timeout, -1 = error
    if (pfd.revents & (POLLERR | POLLNVAL)) return -1;
    if (pfd.revents & POLLHUP && !(pfd.revents & (POLLIN | POLLOUT))) return -1;
    return 1;
}

// --- TcpSocket -----------------------------------------------------------------

TcpSocket::~TcpSocket() { close(); }

TcpSocket::TcpSocket(TcpSocket&& o) noexcept : m_fd(o.m_fd), m_peer(std::move(o.m_peer)) {
    o.m_fd = -1;
}

TcpSocket& TcpSocket::operator=(TcpSocket&& o) noexcept {
    if (this != &o) {
        close();
        m_fd = o.m_fd;
        m_peer = std::move(o.m_peer);
        o.m_fd = -1;
    }
    return *this;
}

void TcpSocket::close() {
    if (m_fd >= 0) {
        ::shutdown(m_fd, SHUT_RDWR);
        ::close(m_fd);
        m_fd = -1;
        m_peer.clear();
    }
}

bool TcpSocket::connect(const std::string& host, uint16_t port, int timeout_ms, std::string& error) {
    close();

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = nullptr;

    std::string service = std::to_string(port);
    int rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &result);
    if (rc != 0 || !result) {
        error = "DNS resolution failed for '" + host + "': " + gai_strerror(rc);
        return false;
    }

    for (struct addrinfo* ai = result; ai; ai = ai->ai_next) {
        int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        // Non-blocking connect + poll for the timeout window.
        int flags = ::fcntl(fd, F_GETFL, 0);
        (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int cr = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (cr != 0 && errno != EINPROGRESS) {
            ::close(fd);
            continue;
        }
        if (cr != 0) {
            int pr = poll_fd(fd, false, true, timeout_ms);
            if (pr <= 0) {
                ::close(fd);
                if (pr == 0) error = "connect timed out after " + std::to_string(timeout_ms) + " ms";
                else error = std::string("connect poll error: ") + std::strerror(errno);
                continue;
            }
            int so_err = 0;
            socklen_t len = sizeof(so_err);
            if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) != 0 || so_err != 0) {
                ::close(fd);
                error = std::string("connect failed: ") + std::strerror(so_err ? so_err : errno);
                continue;
            }
        }

        // Back to blocking for straightforward send/recv semantics with
        // per-call poll timeouts guarding each operation.
        (void)::fcntl(fd, F_SETFL, flags);
        m_fd = fd;
        char ip[INET6_ADDRSTRLEN] = {0};
        const void* addr = (ai->ai_family == AF_INET)
            ? static_cast<const void*>(&reinterpret_cast<struct sockaddr_in*>(ai->ai_addr)->sin_addr)
            : static_cast<const void*>(&reinterpret_cast<struct sockaddr_in6*>(ai->ai_addr)->sin6_addr);
        if (::inet_ntop(ai->ai_family, addr, ip, sizeof(ip))) {
            m_peer = std::string(ip) + ":" + service;
        } else {
            m_peer = host + ":" + service;
        }
        ::freeaddrinfo(result);
        return true;
    }

    ::freeaddrinfo(result);
    if (error.empty()) error = "no address family succeeded for connect";
    return false;
}

bool TcpSocket::send_all(const void* data, size_t len, int timeout_ms, std::string& error) {
    if (m_fd < 0) {
        error = "socket not connected";
        return false;
    }
    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    while (sent < len) {
        int pr = poll_fd(m_fd, false, true, timeout_ms);
        if (pr <= 0) {
            error = pr == 0 ? "send timed out" : std::string("send poll error: ") + std::strerror(errno);
            return false;
        }
        ssize_t n = ::send(m_fd, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            error = std::string("send failed: ") + std::strerror(errno);
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool TcpSocket::recv_some(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error) {
    if (m_fd < 0) {
        error = "socket not connected";
        return false;
    }
    int pr = poll_fd(m_fd, true, false, timeout_ms);
    if (pr <= 0) {
        error = pr == 0 ? "recv timed out" : std::string("recv poll error: ") + std::strerror(errno);
        return false;
    }
    out.resize(max_bytes);
    ssize_t n = ::recv(m_fd, out.data(), max_bytes, 0);
    if (n < 0) {
        error = std::string("recv failed: ") + std::strerror(errno);
        return false;
    }
    if (n == 0) {
        error = "connection closed by peer";
        return false;
    }
    out.resize(static_cast<size_t>(n));
    return true;
}

// --- UdpSocket ------------------------------------------------------------------

UdpSocket::~UdpSocket() { close(); }

bool UdpSocket::open(std::string& error) {
    close();
    m_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (m_fd < 0) {
        error = std::string("udp socket: ") + std::strerror(errno);
        return false;
    }
    return true;
}

void UdpSocket::close() {
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
}

bool UdpSocket::send_to(const std::string& host, uint16_t port, const void* data, size_t len, int timeout_ms, std::string& error) {
    (void)timeout_ms;
    if (m_fd < 0 && !open(error)) return false;

    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* result = nullptr;
    int rc = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
    if (rc != 0 || !result) {
        error = "udp resolve failed for '" + host + "': " + gai_strerror(rc);
        return false;
    }
    ssize_t n = ::sendto(m_fd, data, len, 0, result->ai_addr, result->ai_addrlen);
    ::freeaddrinfo(result);
    if (n < 0) {
        error = std::string("udp sendto failed: ") + std::strerror(errno);
        return false;
    }
    return true;
}

bool UdpSocket::recv_from(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error) {
    if (m_fd < 0) {
        error = "udp socket not open";
        return false;
    }
    int pr = poll_fd(m_fd, true, false, timeout_ms);
    if (pr <= 0) {
        error = pr == 0 ? "udp recv timed out" : std::string("udp poll error: ") + std::strerror(errno);
        return false;
    }
    out.resize(max_bytes);
    ssize_t n = ::recv(m_fd, out.data(), max_bytes, 0);
    if (n < 0) {
        error = std::string("udp recv failed: ") + std::strerror(errno);
        return false;
    }
    out.resize(static_cast<size_t>(n));
    return true;
}

} // namespace dvargosh::stdnet
