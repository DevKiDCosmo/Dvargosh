#include "stdnet_uri.hpp"
#include <cstdlib>

namespace dvargosh::stdnet {

Uri parse_uri(const std::string& raw) {
    Uri u;
    std::string rest = raw;

    // scheme
    auto scheme_end = rest.find("://");
    if (scheme_end == std::string::npos) {
        u.error = "URI missing 'scheme://' prefix: " + raw;
        return u;
    }
    u.scheme = rest.substr(0, scheme_end);
    if (u.scheme.empty()) {
        u.error = "URI has empty scheme";
        return u;
    }
    for (char c : u.scheme) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '.') {
            u.error = "URI scheme contains invalid character";
            return u;
        }
    }
    rest = rest.substr(scheme_end + 3);

    // fragment
    auto frag = rest.find('#');
    if (frag != std::string::npos) {
        u.fragment = rest.substr(frag + 1);
        rest = rest.substr(0, frag);
    }

    // query
    auto q = rest.find('?');
    if (q != std::string::npos) {
        u.query = rest.substr(q + 1);
        rest = rest.substr(0, q);
    }

    // path
    auto slash = rest.find('/');
    if (slash != std::string::npos) {
        u.path = rest.substr(slash);
        rest = rest.substr(0, slash);
    }

    // userinfo@host[:port]
    auto at = rest.rfind('@');
    if (at != std::string::npos) {
        u.userinfo = rest.substr(0, at);
        rest = rest.substr(at + 1);
    }

    if (rest.empty()) {
        u.error = "URI has empty host";
        return u;
    }

    // IPv6 literal [::1]:8080
    if (!rest.empty() && rest.front() == '[') {
        auto close = rest.find(']');
        if (close == std::string::npos) {
            u.error = "URI IPv6 literal missing ']'";
            return u;
        }
        u.host = rest.substr(1, close - 1);
        std::string port_part = rest.substr(close + 1);
        if (!port_part.empty()) {
            if (port_part.front() != ':') {
                u.error = "URI has trailing garbage after IPv6 literal";
                return u;
            }
            std::string p = port_part.substr(1);
            char* endp = nullptr;
            unsigned long val = std::strtoul(p.c_str(), &endp, 10);
            if (!endp || *endp != '\0' || val == 0 || val > 65535) {
                u.error = "URI port invalid";
                return u;
            }
            u.port = static_cast<uint16_t>(val);
        }
    } else {
        auto colon = rest.rfind(':');
        if (colon != std::string::npos && rest.find(':') == colon) {
            // exactly one colon -> host:port
            u.host = rest.substr(0, colon);
            std::string p = rest.substr(colon + 1);
            char* endp = nullptr;
            unsigned long val = std::strtoul(p.c_str(), &endp, 10);
            if (p.empty() || !endp || *endp != '\0' || val == 0 || val > 65535) {
                u.error = "URI port invalid";
                return u;
            }
            u.port = static_cast<uint16_t>(val);
        } else {
            u.host = rest;
        }
    }

    if (u.host.empty()) {
        u.error = "URI has empty host";
        return u;
    }

    u.valid = true;
    return u;
}

bool Uri::apply_scheme_defaults() {
    if (!valid) return false;
    if (port == 0) {
        if (scheme == "http") port = 80;
        else if (scheme == "https") port = 443;
        else if (scheme == "ws") port = 80;
        else if (scheme == "wss") port = 443;
    }
    return port != 0;
}

std::string Uri::host_header() const {
    bool default_port = (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
    if (default_port) return host;
    return host + ":" + std::to_string(port);
}

std::string Uri::request_target() const {
    std::string t = path.empty() ? "/" : path;
    if (!query.empty()) t += "?" + query;
    return t;
}

std::string Uri::to_display() const {
    std::string s = "{scheme=" + scheme + ", host=" + host;
    s += ", port=" + std::to_string(port);
    s += ", path=" + (path.empty() ? "/" : path);
    s += ", query=" + (query.empty() ? std::string("<none>") : query);
    s += ", fragment=" + (fragment.empty() ? std::string("<none>") : fragment);
    s += ", userinfo=" + (userinfo.empty() ? std::string("<none>") : std::string("<redacted>"));
    s += "}";
    return s;
}

} // namespace dvargosh::stdnet
