#pragma once

// stdnet — WebSockets (RFC 6455): frame encode/decode, opening handshake
// helpers, and a blocking client over the TCP/TLS layers.

#include "stdnet_buffer.hpp"
#include "stdnet_socket.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace dvargosh::stdnet {

enum class WsOpcode : uint8_t {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
};

struct WsFrame {
    WsOpcode opcode = WsOpcode::Text;
    bool fin = true;
    std::vector<uint8_t> payload;
};

// --- frame codec (client frames are masked per RFC 6455) ---------------------------

inline void ws_encode_frame(WsFrame frame, DynamicBuffer& out, bool mask);

// Extracts one frame; returns 1 = ok, 0 = need more bytes, -1 = protocol error.
inline int ws_try_decode(DynamicBuffer& in, WsFrame& out);

// --- opening handshake ----------------------------------------------------------------

// Sec-WebSocket-Accept value for a given Sec-WebSocket-Key (base64(SHA1(key + GUID))).
inline std::string ws_accept_key(const std::string& client_key);

// Generates a client handshake request (wire format) for path with a random key.
inline std::string ws_client_handshake(const std::string& host_header, const std::string& path, std::string& out_client_key);

// Validates a 101 response; returns true when accept key matches.
inline bool ws_verify_handshake_response(const std::string& response, const std::string& client_key, std::string& error);

// --- blocking client (transport-agnostic send/recv callbacks keep it testable) -----------

class WsConnection {
public:
    explicit WsConnection(TcpSocket&& tcp) : m_tcp(std::move(tcp)) {}

    // Completes the client handshake over the established TCP connection.
    bool handshake(const std::string& host_header, const std::string& path, int timeout_ms, std::string& error);
    bool send_text(const std::string& text, std::string& error);
    bool send_pong(const std::vector<uint8_t>& payload, std::string& error);
    // Returns next non-Ping frame (Pings are answered internally); false on close/error.
    bool recv_frame(WsFrame& out, int timeout_ms, std::string& error);
    void close();

private:
    TcpSocket m_tcp;
    DynamicBuffer m_in;
};

} // namespace dvargosh::stdnet

// ---- inline implementation (header-only; internal linkage per TU) ----
#include <cstring>
#include <ctime>
namespace dvargosh::stdnet {


namespace { constexpr int kWsTimeoutMs = 5000; }

// --- SHA-1 (RFC 3174) — only needed for the WS handshake (non-cryptographic use) -------


static struct Sha1 {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint64_t total_bits = 0;
    uint8_t buf[64] = {0};
    size_t buf_len = 0;

    static uint32_t rotl(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

    void block(const uint8_t* p) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
                   (uint32_t(p[i * 4 + 2]) << 8) | uint32_t(p[i * 4 + 3]);
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t tmp = rotl(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    void update(const uint8_t* p, size_t n) {
        total_bits += uint64_t(n) * 8;
        while (n > 0) {
            size_t take = std::min(n, sizeof(buf) - buf_len);
            std::memcpy(buf + buf_len, p, take);
            buf_len += take;
            p += take;
            n -= take;
            if (buf_len == 64) {
                block(buf);
                buf_len = 0;
            }
        }
    }

    std::string final_hex() {
        uint64_t bits = total_bits;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buf_len != 56) update(&zero, 1);
        uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) lenb[i] = uint8_t(bits >> (56 - i * 8));
        update(lenb, 8);
        std::string out;
        out.reserve(40);
        char hex[3];
        for (int i = 0; i < 5; ++i) {
            for (int b = 3; b >= 0; --b) {
                std::snprintf(hex, sizeof(hex), "%02x", uint8_t(h[i] >> (b * 8)));
                out += hex;
            }
        }
        return out;
    }
};

// --- base64 (RFC 4648) -------------------------------------------------------------------

static const char kBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out += kBase64[(v >> 18) & 63];
        out += kBase64[(v >> 12) & 63];
        out += kBase64[(v >> 6) & 63];
        out += kBase64[v & 63];
    }
    if (i < len) {
        uint32_t v = uint32_t(data[i]) << 16;
        if (i + 1 < len) v |= uint32_t(data[i + 1]) << 8;
        out += kBase64[(v >> 18) & 63];
        out += kBase64[(v >> 12) & 63];
        out += (i + 1 < len) ? kBase64[(v >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

static uint32_t random_u32() {
    static std::atomic<uint32_t> counter{0};
    return static_cast<uint32_t>(std::time(nullptr)) ^ counter.fetch_add(0x9E3779B9) ^
           (static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&counter)) & 0xFFFF);
}


// --- frame codec --------------------------------------------------------------------------

inline void ws_encode_frame(WsFrame frame, DynamicBuffer& out, bool mask) {
    uint8_t b0 = static_cast<uint8_t>(frame.opcode);
    if (frame.fin) b0 |= 0x80;
    out.append(&b0, 1);

    uint64_t len = frame.payload.size();
    uint8_t b1 = mask ? 0x80 : 0x00;
    if (len < 126) {
        b1 |= static_cast<uint8_t>(len);
        out.append(&b1, 1);
    } else if (len <= 0xFFFF) {
        b1 |= 126;
        out.append(&b1, 1);
        uint8_t ext[2] = {uint8_t(len >> 8), uint8_t(len & 0xFF)};
        out.append(ext, 2);
    } else {
        b1 |= 127;
        out.append(&b1, 1);
        uint8_t ext[8];
        for (int i = 0; i < 8; ++i) ext[i] = uint8_t(len >> (56 - i * 8));
        out.append(ext, 8);
    }

    if (mask) {
        uint8_t key[4];
        for (int i = 0; i < 4; ++i) key[i] = uint8_t(random_u32() >> (i * 8));
        out.append(key, 4);
        std::vector<uint8_t> masked(frame.payload.size());
        for (size_t i = 0; i < frame.payload.size(); ++i) {
            masked[i] = frame.payload[i] ^ key[i % 4];
        }
        out.append(masked.data(), masked.size());
    } else {
        out.append(frame.payload.data(), frame.payload.size());
    }
}

inline int ws_try_decode(DynamicBuffer& in, WsFrame& out) {
    if (in.size() < 2) return 0;
    const uint8_t* p = in.data();
    uint8_t b0 = p[0], b1 = p[1];
    bool masked = (b1 & 0x80) != 0;
    uint64_t len = b1 & 0x7F;
    size_t header = 2;
    if (len == 126) {
        if (in.size() < 4) return 0;
        len = (uint64_t(p[2]) << 8) | p[3];
        header = 4;
    } else if (len == 127) {
        if (in.size() < 10) return 0;
        len = 0;
        for (int i = 0; i < 8; ++i) len = (len << 8) | p[2 + i];
        header = 10;
    }
    constexpr uint64_t kMaxWsPayload = 32u * 1024u * 1024u;
    if (len > kMaxWsPayload) return -1;
    if (in.size() < header + (masked ? 4 : 0) + len) return 0;

    out.opcode = static_cast<WsOpcode>(b0 & 0x0F);
    out.fin = (b0 & 0x80) != 0;
    out.payload.resize(static_cast<size_t>(len));
    const uint8_t* src = p + header;
    if (masked) {
        const uint8_t* key = src;
        src += 4;
        for (uint64_t i = 0; i < len; ++i) {
            out.payload[static_cast<size_t>(i)] = src[i] ^ key[i % 4];
        }
    } else {
        std::memcpy(out.payload.data(), src, static_cast<size_t>(len));
    }
    in.consume(header + (masked ? 4 : 0) + static_cast<size_t>(len));
    return 1;
}

// --- handshake -------------------------------------------------------------------------------

inline std::string ws_accept_key(const std::string& client_key) {
    static const char kGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    Sha1 sha;
    sha.update(reinterpret_cast<const uint8_t*>(client_key.data()), client_key.size());
    sha.update(reinterpret_cast<const uint8_t*>(kGuid), std::strlen(kGuid));
    std::string hex = sha.final_hex();

    uint8_t digest[20];
    for (int i = 0; i < 20; ++i) {
        digest[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
    return base64_encode(digest, 20);
}

inline std::string ws_client_handshake(const std::string& host_header, const std::string& path, std::string& out_client_key) {
    // 16 random-ish bytes for the key (uniqueness, not secrecy).
    uint8_t raw[16];
    for (int i = 0; i < 4; ++i) {
        uint32_t r = random_u32();
        raw[i * 4] = uint8_t(r); raw[i * 4 + 1] = uint8_t(r >> 8);
        raw[i * 4 + 2] = uint8_t(r >> 16); raw[i * 4 + 3] = uint8_t(r >> 24);
    }
    out_client_key = base64_encode(raw, 16);

    std::string req;
    req += "GET " + (path.empty() ? std::string("/") : path) + " HTTP/1.1\r\n";
    req += "Host: " + host_header + "\r\n";
    req += "Upgrade: websocket\r\n";
    req += "Connection: Upgrade\r\n";
    req += "Sec-WebSocket-Key: " + out_client_key + "\r\n";
    req += "Sec-WebSocket-Version: 13\r\n";
    req += "\r\n";
    return req;
}

inline bool ws_verify_handshake_response(const std::string& response, const std::string& client_key, std::string& error) {
    auto find_header = [&](const char* name) -> std::string {
        std::string needle = std::string(name) + ":";
        size_t pos = 0;
        while (pos < response.size()) {
            auto eol = response.find('\n', pos);
            std::string line = response.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
            // trim CR
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (line.size() > needle.size() && line.compare(0, needle.size(), needle) == 0) {
                size_t v = line.find_first_not_of(" \t", needle.size());
                return v == std::string::npos ? "" : line.substr(v);
            }
            if (eol == std::string::npos) break;
            pos = eol + 1;
        }
        return "";
    };

    if (response.rfind("HTTP/1.1 101", 0) != 0 && response.rfind("HTTP/1.0 101", 0) != 0) {
        error = "websocket handshake rejected (no 101)";
        return false;
    }
    std::string accept = find_header("Sec-WebSocket-Accept");
    std::string expected = ws_accept_key(client_key);
    if (accept.empty() || accept != expected) {
        error = "websocket accept key mismatch";
        return false;
    }
    return true;
}

// --- blocking client ---------------------------------------------------------------------------

inline bool WsConnection::handshake(const std::string& host_header, const std::string& path, int timeout_ms, std::string& error) {
    std::string client_key;
    std::string req = ws_client_handshake(host_header, path, client_key);
    if (!m_tcp.send_all(req.data(), req.size(), timeout_ms, error)) return false;

    std::string response;
    std::vector<uint8_t> buf;
    while (response.find("\r\n\r\n") == std::string::npos) {
        if (!m_tcp.recv_some(buf, 4096, timeout_ms, error)) return false;
        response.append(reinterpret_cast<const char*>(buf.data()), buf.size());
        if (response.size() > 64 * 1024) {
            error = "websocket handshake response too large";
            return false;
        }
    }
    return ws_verify_handshake_response(response, client_key, error);
}

inline bool WsConnection::send_text(const std::string& text, std::string& error) {
    DynamicBuffer out;
    WsFrame f;
    f.opcode = WsOpcode::Text;
    f.fin = true;
    f.payload.assign(text.begin(), text.end());
    ws_encode_frame(std::move(f), out, /*mask=*/true); // client->server frames are masked
    return m_tcp.send_all(out.data(), out.size(), kWsTimeoutMs, error);
}

inline bool WsConnection::send_pong(const std::vector<uint8_t>& payload, std::string& error) {
    DynamicBuffer out;
    WsFrame f;
    f.opcode = WsOpcode::Pong;
    f.fin = true;
    f.payload = payload;
    ws_encode_frame(std::move(f), out, true);
    return m_tcp.send_all(out.data(), out.size(), kWsTimeoutMs, error);
}

inline bool WsConnection::recv_frame(WsFrame& out, int timeout_ms, std::string& error) {
    for (;;) {
        int rc = ws_try_decode(m_in, out);
        if (rc == 1) return true;
        if (rc < 0) {
            error = "websocket protocol error";
            return false;
        }
        std::vector<uint8_t> buf;
        if (!m_tcp.recv_some(buf, 65536, timeout_ms, error)) return false;
        m_in.append(buf.data(), buf.size());
    }
}

inline void WsConnection::close() {
    m_tcp.close();
}

} // namespace dvargosh::stdnet