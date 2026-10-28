#pragma once

// stdnet — RAII TCP/UDP sockets with timeout semantics (POSIX; macOS + Linux).

#include <cstdint>
#include <string>
#include <vector>

namespace dvargosh::stdnet {

class TcpSocket {
public:
    TcpSocket() = default;
    ~TcpSocket();
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&& o) noexcept;
    TcpSocket& operator=(TcpSocket&& o) noexcept;

    // Resolves via getaddrinfo (all family), connects with timeout (poll on
    // non-blocking socket). Returns false + fills error on failure.
    bool connect(const std::string& host, uint16_t port, int timeout_ms, std::string& error);
    bool send_all(const void* data, size_t len, int timeout_ms, std::string& error);
    // Receives up to max_bytes; returns false on timeout/error (error says which).
    bool recv_some(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error);
    void close();
    bool is_open() const { return m_fd >= 0; }
    int fd() const { return m_fd; }
    const std::string& peer() const { return m_peer; }

private:
    int m_fd = -1;
    std::string m_peer;
};

class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    bool open(std::string& error); // AF_INET datagram socket
    // One-shot send + optional wait-for-reply on the same socket.
    bool send_to(const std::string& host, uint16_t port, const void* data, size_t len, int timeout_ms, std::string& error);
    bool recv_from(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error);
    void close();
    int fd() const { return m_fd; }

private:
    int m_fd = -1;
};

// Poll helper shared by both: returns >0 if fd ready, 0 on timeout, -1 on error.
int poll_fd(int fd, bool want_read, bool want_write, int timeout_ms);

} // namespace dvargosh::stdnet
