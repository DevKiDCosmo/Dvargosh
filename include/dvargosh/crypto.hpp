#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace dvargosh {

class Crypto {
public:
    // Computes raw SHA-256 hash (32 bytes)
    static std::vector<uint8_t> sha256(const void* data, size_t length);
    static std::string sha256_hex(const void* data, size_t length);
    static std::string sha256_hex(const std::string& input);

    // Hash file contents
    static Result<std::string> sha256_file(const std::string& filepath);

    // HMAC-SHA256
    static std::vector<uint8_t> hmac_sha256(const std::string& key, const void* data, size_t length);
    static std::string hmac_sha256_hex(const std::string& key, const void* data, size_t length);
    static std::string hmac_sha256_hex(const std::string& key, const std::string& data);

    // Module file signing & verification
    static Result<std::string> sign_file(const std::string& secret_key, const std::string& filepath);
    static bool verify_file_signature(const std::string& secret_key, const std::string& filepath, const std::string& signature_hex);

    // Constant-time string equality check to prevent timing attacks
    static bool constant_time_compare(const std::string& a, const std::string& b);

    // Utility: bytes to hex string and hex string to bytes
    static std::string to_hex(const uint8_t* data, size_t length);
    static std::string to_hex(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> from_hex(const std::string& hex);
};

} // namespace dvargosh
