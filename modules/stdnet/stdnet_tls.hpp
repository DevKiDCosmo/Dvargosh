#pragma once

// stdnet — TLS/SSL wrapper via OpenSSL (secure transport layer).
// Enabled when CMake finds OpenSSL (DVARGOSH_HAVE_OPENSSL); otherwise every
// operation fails with an honest "TLS support not built" error.

#include "stdnet_socket.hpp"
#include <string>
#include <vector>

namespace dvargosh::stdnet {

bool tls_available();

class TlsSocket {
public:
    TlsSocket() = default;
    ~TlsSocket();
    TlsSocket(const TlsSocket&) = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;

    // Wraps an established (blocking) TCP connection in a TLS client handshake.
    bool connect(const std::string& host, TcpSocket&& tcp, int timeout_ms, std::string& error);
    bool send_all(const void* data, size_t len, std::string& error);
    bool recv_some(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error);
    void close();
    const std::string& tls_version() const { return m_version; }

private:
    void* m_ssl = nullptr;  // SSL*
    void* m_ctx = nullptr;  // SSL_CTX*
    std::string m_version;
};

} // namespace dvargosh::stdnet
