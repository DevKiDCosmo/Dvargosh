#include "stdnet_tls.hpp"

#if defined(DVARGOSH_HAVE_OPENSSL)
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

#include <poll.h>
#include <cstring>

namespace dvargosh::stdnet {

bool tls_available() {
#if defined(DVARGOSH_HAVE_OPENSSL)
    return true;
#else
    return false;
#endif
}

#if defined(DVARGOSH_HAVE_OPENSSL)

namespace {
std::string ssl_error_string(const char* what) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(what) + ": " + (buf[0] ? buf : "unknown OpenSSL error");
}
} // namespace

TlsSocket::~TlsSocket() { close(); }

void TlsSocket::close() {
    if (m_ssl) {
        SSL_shutdown(static_cast<SSL*>(m_ssl));
        SSL_free(static_cast<SSL*>(m_ssl));
        m_ssl = nullptr;
    }
    if (m_ctx) {
        SSL_CTX_free(static_cast<SSL_CTX*>(m_ctx));
        m_ctx = nullptr;
    }
}

bool TlsSocket::connect(const std::string& host, TcpSocket&& tcp, int /*timeout_ms*/, std::string& error) {
    close();
    if (!tcp.is_open()) {
        error = "TLS connect requires an established TCP connection";
        return false;
    }

    m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx) {
        error = ssl_error_string("SSL_CTX_new");
        return false;
    }
    SSL_CTX_set_verify(static_cast<SSL_CTX*>(m_ctx), SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(static_cast<SSL_CTX*>(m_ctx)) != 1) {
        // System trust store unavailable; certificate verification will fail
        // explicitly rather than silently disabling security.
    }

    SSL* ssl = SSL_new(static_cast<SSL_CTX*>(m_ctx));
    if (!ssl) {
        error = ssl_error_string("SSL_new");
        close();
        return false;
    }
    SSL_set_fd(ssl, tcp.fd());
    // SNI for virtual hosts.
    SSL_set_tlsext_host_name(ssl, host.c_str());
    // Hostname verification against the certificate SAN.
    SSL_set1_host(ssl, host.c_str());

    if (SSL_connect(ssl) != 1) {
        error = ssl_error_string("TLS handshake");
        SSL_free(ssl);
        SSL_CTX_free(static_cast<SSL_CTX*>(m_ctx));
        m_ctx = nullptr;
        return false;
    }

    // Detach the TCP fd: the SSL object manages it from here (released on
    // SSL_free via our close(); the TcpSocket guard gives up ownership).
    (void)tcp.release();
    m_ssl = ssl;
    m_version = SSL_get_version(ssl);
    return true;
}

bool TlsSocket::send_all(const void* data, size_t len, std::string& error) {
    SSL* ssl = static_cast<SSL*>(m_ssl);
    if (!ssl) {
        error = "TLS not connected";
        return false;
    }
    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, p + sent, static_cast<int>(len - sent));
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            error = "TLS send failed (err=" + std::to_string(err) + ")";
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool TlsSocket::recv_some(std::vector<uint8_t>& out, size_t max_bytes, int timeout_ms, std::string& error) {
    SSL* ssl = static_cast<SSL*>(m_ssl);
    if (!ssl) {
        error = "TLS not connected";
        return false;
    }
    out.resize(max_bytes);
    int n = SSL_read(ssl, out.data(), static_cast<int>(max_bytes));
    if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            error = "TLS recv timed out";
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            error = "TLS connection closed by peer";
        } else {
            error = "TLS recv failed (err=" + std::to_string(err) + ")";
        }
        return false;
    }
    out.resize(static_cast<size_t>(n));
    return true;
}

#else // !DVARGOSH_HAVE_OPENSSL

TlsSocket::~TlsSocket() = default;

bool TlsSocket::connect(const std::string&, TcpSocket&&, int, std::string& error) {
    error = "TLS support not built (OpenSSL not found at configure time)";
    return false;
}
bool TlsSocket::send_all(const void*, size_t, std::string& error) {
    error = "TLS support not built";
    return false;
}
bool TlsSocket::recv_some(std::vector<uint8_t>&, size_t, int, std::string& error) {
    error = "TLS support not built";
    return false;
}
void TlsSocket::close() {}

#endif // DVARGOSH_HAVE_OPENSSL

} // namespace dvargosh::stdnet
