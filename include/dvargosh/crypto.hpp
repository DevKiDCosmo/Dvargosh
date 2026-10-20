#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace dvargosh {

/**
 * @brief Cryptographic Primitives, HMAC-SHA256 Verification, and Timing-Attack Safe Comparisons.
 *
 * Implements NIST FIPS 180-4 SHA-256 and RFC 2104 HMAC-SHA256 for module binary signing,
 * integrity verification, and tamper detection.
 */
class Crypto {
public:
    /**
     * @brief Computes raw SHA-256 hash (32 bytes).
     * @param data Pointer to input buffer.
     * @param length Number of bytes in input buffer.
     * @return 32-byte binary digest.
     */
    static std::vector<uint8_t> sha256(const void* data, size_t length);

    /** @brief Computes SHA-256 hash and returns it as a 64-character lowercase hexadecimal string. */
    static std::string sha256_hex(const void* data, size_t length);
    static std::string sha256_hex(const std::string& input);

    /**
     * @brief Streams and hashes the entire contents of a file on disk.
     * @param filepath Path to the file to hash.
     * @return Result containing 64-character hex hash, or failure status.
     */
    static Result<std::string> sha256_file(const std::string& filepath);

    /**
     * @brief Computes RFC 2104 HMAC-SHA256 over input buffer using a secret key.
     * @param key Secret key string.
     * @param data Pointer to input buffer.
     * @param length Number of bytes in input buffer.
     * @return 32-byte binary HMAC digest.
     */
    static std::vector<uint8_t> hmac_sha256(const std::string& key, const void* data, size_t length);
    static std::string hmac_sha256_hex(const std::string& key, const void* data, size_t length);
    static std::string hmac_sha256_hex(const std::string& key, const std::string& data);

    /**
     * @brief Cryptographically signs a shared library (.dylib / .so) file using HMAC-SHA256.
     * @param secret_key The master signing secret.
     * @param filepath Absolute or relative path to the binary file.
     * @return Result containing 64-character hexadecimal signature string.
     */
    static Result<std::string> sign_file(const std::string& secret_key, const std::string& filepath);

    /**
     * @brief Verifies the cryptographic HMAC-SHA256 signature of a binary file using constant-time comparison.
     * @param secret_key The master signing secret.
     * @param filepath Path to the binary file.
     * @param signature_hex Expected 64-character hexadecimal signature string.
     * @return True if signature is valid; false if tampered or invalid.
     */
    static bool verify_file_signature(const std::string& secret_key, const std::string& filepath, const std::string& signature_hex);

    /**
     * @brief Constant-time string equality check to prevent side-channel timing attacks.
     * Executes in deterministic time regardless of where differences occur.
     */
    static bool constant_time_compare(const std::string& a, const std::string& b);

    static std::string to_hex(const uint8_t* data, size_t length);
    static std::string to_hex(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> from_hex(const std::string& hex);
};

} // namespace dvargosh
