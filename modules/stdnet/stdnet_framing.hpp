#pragma once

// stdnet — Message framing over DynamicBuffer: length-prefixed (u32 big-endian)
// and delimiter-based stream framing, zero-copy parse via the buffer window.

#include "stdnet_buffer.hpp"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace dvargosh::stdnet {

// --- length-prefixed framing: [4-byte BE length][payload] -------------------------

namespace length_prefix {

// Attempts to extract one message; returns false when more bytes are needed.
inline bool try_pop(DynamicBuffer& buf, std::vector<uint8_t>& out) {
    if (buf.size() < 4) return false;
    uint32_t len = 0;
    std::memcpy(&len, buf.data(), 4);
    len = __builtin_bswap32(len);
    constexpr uint32_t kMaxFrame = 64u * 1024u * 1024u; // sanity cap: 64 MiB
    if (len > kMaxFrame) return false;
    if (buf.size() < 4u + len) return false;
    out.assign(buf.data() + 4, buf.data() + 4 + len);
    buf.consume(4u + len);
    return true;
}

inline void append_frame(DynamicBuffer& buf, const void* data, size_t len) {
    uint32_t be = __builtin_bswap32(static_cast<uint32_t>(len));
    buf.append(&be, 4);
    buf.append(data, len);
}

} // namespace length_prefix

// --- delimiter framing: payload + terminator ----------------------------------------

namespace delimited {

inline bool try_pop(DynamicBuffer& buf, std::vector<uint8_t>& out, uint8_t delimiter = '\n') {
    const uint8_t* base = buf.data();
    for (size_t i = 0; i < buf.size(); ++i) {
        if (base[i] == delimiter) {
            out.assign(base, base + i);
            buf.consume(i + 1);
            return true;
        }
    }
    return false;
}

inline void append_frame(DynamicBuffer& buf, const void* data, size_t len, uint8_t delimiter = '\n') {
    buf.append(data, len);
    buf.append(&delimiter, 1);
}

} // namespace delimited

} // namespace dvargosh::stdnet
