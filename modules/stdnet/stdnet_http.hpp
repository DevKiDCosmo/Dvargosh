#pragma once

// stdnet — HTTP/1.1 request packaging and response parsing (no TLS; plain TCP).

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "stdnet_buffer.hpp"

namespace dvargosh::stdnet {

struct HttpRequest {
    std::string method = "GET";
    std::string target = "/";        // path?query
    std::unordered_map<std::string, std::string> headers; // keys lowercased
    std::vector<uint8_t> body;

    std::string header(const std::string& lower_name) const {
        auto it = headers.find(lower_name);
        return it == headers.end() ? "" : it->second;
    }
};

struct HttpResponse {
    int status = 0;
    std::string reason;
    std::unordered_map<std::string, std::string> headers; // keys lowercased
    std::vector<uint8_t> body;

    std::string header(const std::string& lower_name) const {
        auto it = headers.find(lower_name);
        return it == headers.end() ? "" : it->second;
    }
    std::string body_string() const { return std::string(body.begin(), body.end()); }
};

// Builds the wire-format request (adds Host, Content-Length, Connection: close).
std::string build_http_request(const HttpRequest& req, const std::string& host_header);

// Parses a full raw response. Handles Content-Length, read-to-close, and
// chunked transfer decoding. Returns false + reason on malformed input.
bool parse_http_response(const std::string& raw, HttpResponse& out, std::string& error);

// Streaming request parser for servers: 1 = complete request, 0 = need more
// bytes, -1 = malformed. Uses the zero-copy DynamicBuffer window.
int parse_http_request_stream(DynamicBuffer& in, HttpRequest& out, std::string& error);

} // namespace dvargosh::stdnet
