#include "test_framework.hpp"
#include "dvargosh/crypto.hpp"

using namespace dvargosh;

TEST_CASE(test_sha256_nist_vectors) {
    // Empty string SHA256 test
    std::string empty_hash = Crypto::sha256_hex("");
    ASSERT_EQ(empty_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // Standard vector "abc"
    std::string abc_hash = Crypto::sha256_hex("abc");
    ASSERT_EQ(abc_hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE(test_hmac_sha256) {
    std::string key = "secret_key";
    std::string data = "The quick brown fox jumps over the lazy dog";
    std::string hmac = Crypto::hmac_sha256_hex(key, data);
    ASSERT_FALSE(hmac.empty());
    ASSERT_EQ(hmac.size(), 64);

    // Deterministic verify
    std::string hmac2 = Crypto::hmac_sha256_hex(key, data);
    ASSERT_EQ(hmac, hmac2);

    // Key sensitivity
    std::string hmac3 = Crypto::hmac_sha256_hex("different_key", data);
    ASSERT_FALSE(hmac == hmac3);
}

TEST_CASE(test_constant_time_compare) {
    std::string a = "aabbccddeeff";
    std::string b = "aabbccddeeff";
    std::string c = "aabbccddeef0";

    ASSERT_TRUE(Crypto::constant_time_compare(a, b));
    ASSERT_FALSE(Crypto::constant_time_compare(a, c));
}
