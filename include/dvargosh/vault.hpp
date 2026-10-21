#pragma once

#include "types.hpp"
#include "secured_memory.hpp"
#include "crypto.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace dvargosh {

class DomainManager;

/**
 * @brief Security enforcement levels for Vault instances.
 */
enum class VaultSecurityLevel {
    Standard,     ///< Domain-isolated access enforcement.
    Strict,       ///< Requires exact owning domain match (or universal system privilege).
    Sealed,       ///< Hardware page-protected via mprotect(PROT_READ). No writes permitted while sealed.
    TamperProof   ///< Hardware write protection combined with HMAC-SHA256 cryptographic integrity verification.
};

inline const char* vault_security_level_to_string(VaultSecurityLevel level) {
    switch (level) {
        case VaultSecurityLevel::Standard: return "Standard";
        case VaultSecurityLevel::Strict: return "Strict";
        case VaultSecurityLevel::Sealed: return "Sealed";
        case VaultSecurityLevel::TamperProof: return "TamperProof";
        default: return "Unknown";
    }
}

/**
 * @brief Comprehensive configuration and metadata for a secured Vault container.
 */
struct VaultConfig {
    std::string name;                                              ///< Unique vault identifier.
    std::string owner_domain;                                      ///< Domain owning this vault.
    std::string owner_module;                                      ///< Module owning this vault.
    size_t capacity_bytes = 64 * 1024;                             ///< Capacity (default: 64 KB).
    VaultSecurityLevel security_level = VaultSecurityLevel::Strict;///< Security level.
    bool use_guard_pages = true;                                   ///< Enable hardware PROT_NONE guard pages.
    bool auto_seal_on_write = true;                                ///< Automatically hardware-seal memory after each write.
    std::string description;                                       ///< Human-readable vault description.
};

/**
 * @brief High-security cryptographic vault backed by hardware-guarded secured memory.
 *
 * Implements:
 * 1. Automatic Execution Domain Resolution: Caller identity is resolved via thread-local
 *    ExecutionContext; attempts to impersonate or spoof caller domains trigger immediate rejection.
 * 2. Hardware Page Sealing: Uses mprotect(PROT_READ) to prevent any memory modification while sealed.
 * 3. Cryptographic Tamper Verification: Uses SHA-256 checksums to detect in-memory tampering.
 * 4. Zero Raw Pointer Exposure: Secrets are written and read strictly via validated methods.
 */
class Vault {
public:
    /**
     * @brief Factory creating a new Vault instance.
     * @param config Vault configuration parameters.
     * @param space Optional pre-allocated SecuredMemorySpace. If null, a new one is allocated.
     * @return Result containing shared_ptr to initialized Vault, or failure code.
     */
    static Result<std::shared_ptr<Vault>> create(
        VaultConfig config,
        std::unique_ptr<SecuredMemorySpace> space = nullptr
    );

    ~Vault();

    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    const VaultConfig& config() const noexcept { return m_config; }
    const std::string& name() const noexcept { return m_config.name; }
    const std::string& owner_domain() const noexcept { return m_config.owner_domain; }
    const std::string& owner_module() const noexcept { return m_config.owner_module; }

    bool is_sealed() const noexcept { return m_sealed; }

    /**
     * @brief Hardware-seals the vault memory by setting pages to PROT_READ.
     * Direct pointer writes will trigger hardware SIGSEGV.
     */
    Result<void> seal();

    /**
     * @brief Unseals the vault for authorized modification.
     * Caller domain is automatically verified against owner_domain.
     */
    Result<void> unseal();

    /**
     * @brief Unloads, sanitizes, and frees the vault's safe memory pages and cryptographic slots.
     */
    void unload();

    /**
     * @brief Safely writes a secret into the hardware-guarded vault.
     * Verifies that the currently executing domain matches owner_domain.
     * Computes SHA-256 checksum and auto-seals if configured.
     * @param key Secret identifier key.
     * @param secret_data Secret payload string.
     */
    Result<void> write_secret(const std::string& key, const std::string& secret_data);

    /**
     * @brief Reads a secret from the vault.
     * Automatically verifies caller domain permissions and checks cryptographic integrity.
     * @param key Secret identifier key.
     * @return Result containing the secret string, or failure code.
     */
    Result<std::string> read_secret(const std::string& key) const;

    /**
     * @brief Checks if a secret key exists in the vault.
     */
    bool has_secret(const std::string& key) const;

    /**
     * @brief Lists all stored secret keys in the vault.
     */
    std::vector<std::string> list_keys() const;

    /**
     * @brief Verifies cryptographic integrity of all stored secrets against recorded checksums.
     * @return Result<bool> true if all intact, failure with StatusCode::SecurityTampering if corrupted.
     */
    Result<bool> verify_integrity() const;

    size_t capacity() const;
    size_t used_bytes() const;
    size_t secret_count() const;

    void set_domain_manager(DomainManager* dm) { m_domain_mgr = dm; }

private:
    Vault(VaultConfig config, std::unique_ptr<SecuredMemorySpace> space);

    Result<void> check_caller_access(bool write_mode) const;
    void apply_hardware_protection(bool read_only);

    struct SecretSlot {
        size_t offset = 0;
        size_t size = 0;
        std::string checksum;
    };

    VaultConfig m_config;
    std::unique_ptr<SecuredMemorySpace> m_space;
    bool m_sealed = false;
    DomainManager* m_domain_mgr = nullptr;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, SecretSlot> m_slots;
};

} // namespace dvargosh
