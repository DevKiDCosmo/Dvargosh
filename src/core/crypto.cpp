#include "dvargosh/crypto.hpp"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace dvargosh {

namespace {

// SHA-256 implementation following FIPS PUB 180-4
inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

struct SHA256Context {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t datalen;

    void init() {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        bitlen = 0;
        datalen = 0;
    }

    void transform(const uint8_t* data) {
        uint32_t m[64];
        for (int i = 0, j = 0; i < 16; ++i, j += 4) {
            m[i] = ((uint32_t)data[j] << 24) |
                   ((uint32_t)data[j + 1] << 16) |
                   ((uint32_t)data[j + 2] << 8) |
                   ((uint32_t)data[j + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            m[i] = gamma1(m[i - 2]) + m[i - 7] + gamma0(m[i - 15]) + m[i - 16];
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + m[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[datalen++] = data[i];
            if (datalen == 64) {
                transform(buffer);
                bitlen += 512;
                datalen = 0;
            }
        }
    }

    void final(uint8_t hash[32]) {
        size_t i = datalen;

        if (datalen < 56) {
            buffer[i++] = 0x80;
            while (i < 56) buffer[i++] = 0x00;
        } else {
            buffer[i++] = 0x80;
            while (i < 64) buffer[i++] = 0x00;
            transform(buffer);
            memset(buffer, 0, 56);
        }

        bitlen += (uint64_t)datalen * 8;
        buffer[63] = (uint8_t)(bitlen);
        buffer[62] = (uint8_t)(bitlen >> 8);
        buffer[61] = (uint8_t)(bitlen >> 16);
        buffer[60] = (uint8_t)(bitlen >> 24);
        buffer[59] = (uint8_t)(bitlen >> 32);
        buffer[58] = (uint8_t)(bitlen >> 40);
        buffer[57] = (uint8_t)(bitlen >> 48);
        buffer[56] = (uint8_t)(bitlen >> 56);
        transform(buffer);

        for (i = 0; i < 4; ++i) {
            hash[i]      = (state[0] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 20] = (state[5] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 24] = (state[6] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 28] = (state[7] >> (24 - i * 8)) & 0x000000ff;
        }
    }
};

} // anonymous namespace

std::vector<uint8_t> Crypto::sha256(const void* data, size_t length) {
    SHA256Context ctx;
    ctx.init();
    ctx.update(reinterpret_cast<const uint8_t*>(data), length);
    std::vector<uint8_t> out(32);
    ctx.final(out.data());
    return out;
}

std::string Crypto::sha256_hex(const void* data, size_t length) {
    auto hash = sha256(data, length);
    return to_hex(hash);
}

std::string Crypto::sha256_hex(const std::string& input) {
    return sha256_hex(input.data(), input.size());
}

Result<std::string> Crypto::sha256_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return Result<std::string>::failure(StatusCode::NotFound, "Could not open file: " + filepath);
    }

    SHA256Context ctx;
    ctx.init();
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        ctx.update(reinterpret_cast<const uint8_t*>(buffer), file.gcount());
    }

    std::vector<uint8_t> hash(32);
    ctx.final(hash.data());
    return Result<std::string>::success(to_hex(hash));
}

std::vector<uint8_t> Crypto::hmac_sha256(const std::string& key, const void* data, size_t length) {
    const size_t block_size = 64;
    std::vector<uint8_t> key_pad(block_size, 0);

    if (key.size() > block_size) {
        auto key_hash = sha256(key.data(), key.size());
        std::memcpy(key_pad.data(), key_hash.data(), key_hash.size());
    } else {
        std::memcpy(key_pad.data(), key.data(), key.size());
    }

    std::vector<uint8_t> ipad(block_size);
    std::vector<uint8_t> opad(block_size);
    for (size_t i = 0; i < block_size; ++i) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5c;
    }

    // Inner hash: H(ipad || data)
    SHA256Context inner_ctx;
    inner_ctx.init();
    inner_ctx.update(ipad.data(), ipad.size());
    inner_ctx.update(reinterpret_cast<const uint8_t*>(data), length);
    std::vector<uint8_t> inner_hash(32);
    inner_ctx.final(inner_hash.data());

    // Outer hash: H(opad || inner_hash)
    SHA256Context outer_ctx;
    outer_ctx.init();
    outer_ctx.update(opad.data(), opad.size());
    outer_ctx.update(inner_hash.data(), inner_hash.size());
    std::vector<uint8_t> result(32);
    outer_ctx.final(result.data());

    return result;
}

std::string Crypto::hmac_sha256_hex(const std::string& key, const void* data, size_t length) {
    return to_hex(hmac_sha256(key, data, length));
}

std::string Crypto::hmac_sha256_hex(const std::string& key, const std::string& data) {
    return hmac_sha256_hex(key, data.data(), data.size());
}

Result<std::string> Crypto::sign_file(const std::string& secret_key, const std::string& filepath) {
    auto file_hash_res = sha256_file(filepath);
    if (!file_hash_res.is_ok()) {
        return file_hash_res;
    }
    std::string digest = file_hash_res.value();
    std::string sig = hmac_sha256_hex(secret_key, digest);
    return Result<std::string>::success(sig);
}

bool Crypto::verify_file_signature(const std::string& secret_key, const std::string& filepath, const std::string& signature_hex) {
    auto expected_res = sign_file(secret_key, filepath);
    if (!expected_res.is_ok()) return false;
    return constant_time_compare(expected_res.value(), signature_hex);
}

bool Crypto::constant_time_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= (static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]));
    }
    return diff == 0;
}

std::string Crypto::to_hex(const uint8_t* data, size_t length) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string Crypto::to_hex(const std::vector<uint8_t>& data) {
    return to_hex(data.data(), data.size());
}

std::vector<uint8_t> Crypto::from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t b = static_cast<uint8_t>(std::strtoul(byte_str.c_str(), nullptr, 16));
        bytes.push_back(b);
    }
    return bytes;
}

} // namespace dvargosh
