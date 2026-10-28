#pragma once

// stdnet — URI parsing (RFC 3986 subset, sufficient for scheme://host[:port]/path?query#fragment)

#include <cstdint>
#include <string>

namespace dvargosh::stdnet {

struct Uri {
    std::string scheme;
    std::string host;
    uint16_t port = 0;      // 0 = not specified (caller applies scheme default)
    std::string path;
    std::string query;
    std::string fragment;
    std::string userinfo;   // user[:password] — never echoed back by services

    bool valid = false;
    std::string error;

    // Applies scheme defaults (http -> 80). Returns false for schemes we do not
    // support at the transport layer (https: no TLS in stdnet, honestly reported).
    bool apply_scheme_defaults();
    bool is_tls_scheme() const { return scheme == "https" || scheme == "wss"; }
    std::string host_header() const; // host[:port] with default ports omitted
    std::string request_target() const; // path[?query], "/" when empty
    std::string to_display() const;     // structured dump for RPC consumers
};

Uri parse_uri(const std::string& raw);

} // namespace dvargosh::stdnet
