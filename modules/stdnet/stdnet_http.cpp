#include "stdnet_http.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace dvargosh::stdnet {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string trim_ws(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

} // namespace

std::string build_http_request(const HttpRequest& req, const std::string& host_header) {
    std::ostringstream out;
    out << req.method << " " << req.target << " HTTP/1.1\r\n";
    out << "Host: " << host_header << "\r\n";

    bool has_ua = false, has_conn = false, has_cl = false;
    for (const auto& [k, v] : req.headers) {
        std::string lk = to_lower(k);
        if (lk == "host") continue; // authoritative from the URI
        if (lk == "user-agent") has_ua = true;
        if (lk == "connection") has_conn = true;
        if (lk == "content-length") has_cl = true;
        out << k << ": " << v << "\r\n";
    }
    if (!has_ua) out << "User-Agent: dvargosh-stdnet/1.0\r\n";
    if (!has_conn) out << "Connection: close\r\n";
    if (!has_cl && !req.body.empty()) out << "Content-Length: " << req.body.size() << "\r\n";
    out << "\r\n";
    std::string head = out.str();
    head.append(reinterpret_cast<const char*>(req.body.data()), req.body.size());
    return head;
}

bool parse_http_response(const std::string& raw, HttpResponse& out, std::string& error) {
    // Split head/body at CRLFCRLF (be lenient about LFLF).
    size_t sep = raw.find("\r\n\r\n");
    size_t sep_len = 4;
    if (sep == std::string::npos) {
        sep = raw.find("\n\n");
        sep_len = 2;
    }
    if (sep == std::string::npos) {
        error = "response has no header/body separator";
        return false;
    }
    std::string head = raw.substr(0, sep);
    std::string body = raw.substr(sep + sep_len);

    // Status line: HTTP/1.1 200 OK
    auto first_eol = head.find('\n');
    std::string status_line = trim_ws(first_eol == std::string::npos ? head : head.substr(0, first_eol));
    if (status_line.rfind("HTTP/", 0) != 0) {
        error = "not an HTTP response: '" + status_line.substr(0, 32) + "'";
        return false;
    }
    {
        std::istringstream sl(status_line);
        std::string version;
        sl >> version >> out.status;
        std::getline(sl, out.reason);
        out.reason = trim_ws(out.reason);
        if (out.status < 100 || out.status > 599) {
            error = "invalid HTTP status: " + std::to_string(out.status);
            return false;
        }
    }

    // Headers
    size_t pos = (first_eol == std::string::npos) ? head.size() : first_eol + 1;
    while (pos < head.size()) {
        auto eol = head.find('\n', pos);
        std::string line = trim_ws(eol == std::string::npos ? head.substr(pos) : head.substr(pos, eol - pos));
        pos = (eol == std::string::npos) ? head.size() : eol + 1;
        if (line.empty()) continue;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        out.headers[to_lower(trim_ws(line.substr(0, colon)))] = trim_ws(line.substr(colon + 1));
    }

    // Body framing
    std::string te = to_lower(out.header("transfer-encoding"));
    if (te.find("chunked") != std::string::npos) {
        // Decode chunked: <hex-size>\r\n<data>\r\n ... 0\r\n(\r\n)
        size_t p = 0;
        bool done = false;
        while (!done && p < body.size()) {
            auto eol = body.find("\r\n", p);
            if (eol == std::string::npos) break;
            unsigned long long sz = std::strtoull(body.substr(p, eol - p).c_str(), nullptr, 16);
            p = eol + 2;
            if (sz == 0) { done = true; break; }
            if (p + sz > body.size()) {
                error = "truncated chunked body";
                return false;
            }
            out.body.insert(out.body.end(), body.begin() + static_cast<long>(p), body.begin() + static_cast<long>(p + sz));
            p += sz + 2; // skip data + CRLF
        }
    } else {
        std::string cl = out.header("content-length");
        if (!cl.empty()) {
            unsigned long long want = std::strtoull(cl.c_str(), nullptr, 10);
            // Accept short bodies (peer may have closed early) but never over-read.
            size_t take = std::min<size_t>(static_cast<size_t>(want), body.size());
            out.body.assign(body.begin(), body.begin() + static_cast<long>(take));
        } else {
            out.body.assign(body.begin(), body.end()); // read-to-close framing
        }
    }
    return true;
}

} // namespace dvargosh::stdnet
