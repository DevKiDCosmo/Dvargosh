#pragma once

// stdnet — Unix domain sockets: high-speed local IPC (stream + datagram).

#include <unistd.h>

#include <cstdint>
#include <string>
#include <vector>

namespace dvargosh::stdnet {

class UdsStream {
public:
    UdsStream() = default;
    ~UdsStream();
    UdsStream(const UdsStream&) = delete;
    UdsStream& operator=(const UdsStream&) = delete;

    // Connects to a filesystem path socket (AF_UNIX SOCK_STREAM).
    bool connect(const std::string& path, int timeout_ms, std::string& error);
    bool send_all(const void* data, size_t len, int timeout_ms, std::string& error);
    bool recv_some(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error);
    void close();
    bool is_open() const { return m_fd >= 0; }

    // Server-side accept helper: binds+listens on path (unlinking first), returns
    // a listening fd; accepted connections wrap into UdsStream via adopt().
    static bool listen(const std::string& path, int& out_fd, std::string& error);
    static bool accept(int listen_fd, UdsStream& out, std::string& error);
    static void remove_path(const std::string& path) { ::unlink(path.c_str()); }

private:
    explicit UdsStream(int fd) : m_fd(fd) {}
    int m_fd = -1;
};

class UdsDatagram {
public:
    UdsDatagram() = default;
    ~UdsDatagram();
    UdsDatagram(const UdsDatagram&) = delete;
    UdsDatagram& operator=(const UdsDatagram&) = delete;

    bool open(std::string& error);
    bool send_to(const std::string& path, const void* data, size_t len, std::string& error);
    bool recv_from(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error);
    void close();

private:
    int m_fd = -1;
};

} // namespace dvargosh::stdnet

// ---- inline implementation (header-only; internal linkage per TU) ----
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
namespace dvargosh::stdnet {


// --- UdsStream --------------------------------------------------------------------

inline UdsStream::~UdsStream() { close(); }

inline void UdsStream::close() {
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
}

inline bool UdsStream::connect(const std::string& path, int timeout_ms, std::string& error) {
    close();
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        error = std::string("uds socket: ") + std::strerror(errno);
        return false;
    }
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        error = "uds path too long";
        ::close(fd);
        return false;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        error = std::string("uds connect: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }
    (void)timeout_ms; // AF_UNIX connects are local and immediate
    m_fd = fd;
    return true;
}

inline bool UdsStream::send_all(const void* data, size_t len, int timeout_ms, std::string& error) {
    if (m_fd < 0) {
        error = "uds not connected";
        return false;
    }
    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    while (sent < len) {
        struct pollfd pfd{m_fd, POLLOUT, 0};
        if (::poll(&pfd, 1, timeout_ms) <= 0) {
            error = "uds send timed out";
            return false;
        }
        ssize_t n = ::send(m_fd, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            error = std::string("uds send: ") + std::strerror(errno);
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

inline bool UdsStream::recv_some(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error) {
    if (m_fd < 0) {
        error = "uds not connected";
        return false;
    }
    struct pollfd pfd{m_fd, POLLIN, 0};
    if (::poll(&pfd, 1, timeout_ms) <= 0) {
        error = "uds recv timed out";
        return false;
    }
    out.resize(max_bytes);
    ssize_t n = ::recv(m_fd, out.data(), max_bytes, 0);
    if (n < 0) {
        error = std::string("uds recv: ") + std::strerror(errno);
        return false;
    }
    if (n == 0) {
        error = "uds peer closed";
        return false;
    }
    out.resize(static_cast<size_t>(n));
    return true;
}

inline bool UdsStream::listen(const std::string& path, int& out_fd, std::string& error) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        error = std::string("uds listen socket: ") + std::strerror(errno);
        return false;
    }
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        error = "uds path too long";
        ::close(fd);
        return false;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    ::unlink(path.c_str());
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        error = std::string("uds bind: ") + std::strerror(errno);
        ::close(fd);
        return false;
    }
    if (::listen(fd, 8) != 0) {
        error = std::string("uds listen: ") + std::strerror(errno);
        ::close(fd);
        ::unlink(path.c_str());
        return false;
    }
    out_fd = fd;
    return true;
}

inline bool UdsStream::accept(int listen_fd, UdsStream& out, std::string& error) {
    int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0) {
        error = std::string("uds accept: ") + std::strerror(errno);
        return false;
    }
    out.close();
    out.m_fd = fd;
    return true;
}

// --- UdsDatagram --------------------------------------------------------------------

inline UdsDatagram::~UdsDatagram() { close(); }

inline bool UdsDatagram::open(std::string& error) {
    close();
    m_fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if (m_fd < 0) {
        error = std::string("uds dgram socket: ") + std::strerror(errno);
        return false;
    }
    return true;
}

inline void UdsDatagram::close() {
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
}

inline bool UdsDatagram::send_to(const std::string& path, const void* data, size_t len, std::string& error) {
    if (m_fd < 0 && !open(error)) return false;
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        error = "uds path too long";
        return false;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    ssize_t n = ::sendto(m_fd, data, len, 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (n < 0) {
        error = std::string("uds sendto: ") + std::strerror(errno);
        return false;
    }
    return true;
}

inline bool UdsDatagram::recv_from(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error) {
    if (m_fd < 0) {
        error = "uds dgram not open";
        return false;
    }
    struct pollfd pfd{m_fd, POLLIN, 0};
    if (::poll(&pfd, 1, timeout_ms) <= 0) {
        error = "uds dgram recv timed out";
        return false;
    }
    out.resize(max_bytes);
    ssize_t n = ::recv(m_fd, out.data(), max_bytes, 0);
    if (n < 0) {
        error = std::string("uds dgram recv: ") + std::strerror(errno);
        return false;
    }
    out.resize(static_cast<size_t>(n));
    return true;
}

} // namespace dvargosh::stdnet