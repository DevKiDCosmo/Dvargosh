#include "dvargosh/vault.hpp"
#include "dvargosh/execution_context.hpp"
#include "dvargosh/domain.hpp"
#include "dvargosh/logger.hpp"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>

namespace dvargosh {

Result<std::shared_ptr<Vault>> Vault::create(
    VaultConfig config,
    std::unique_ptr<SecuredMemorySpace> space
) {
    if (config.name.empty()) {
        return Result<std::shared_ptr<Vault>>::failure(StatusCode::InvalidArg, "Vault name cannot be empty");
    }

    if (!space) {
        SecuredMemoryConfig mem_cfg;
        mem_cfg.container_name = "vault_" + config.name;
        mem_cfg.capacity_bytes = config.capacity_bytes > 0 ? config.capacity_bytes : 64 * 1024;
        mem_cfg.use_guard_pages = config.use_guard_pages;
        mem_cfg.scrub_on_destroy = true;

        SecurityPolicy mem_policy = SecurityPolicy::strict();
        mem_policy.permissions().grant(Permission::SecuredMemory);

        auto space_res = SecuredMemorySpace::create(mem_cfg, mem_policy);
        if (!space_res.is_ok()) {
            return Result<std::shared_ptr<Vault>>::failure(space_res.status(), space_res.error_message());
        }
        space = std::move(space_res.value());
    }

    auto vault = std::shared_ptr<Vault>(new Vault(std::move(config), std::move(space)));
    if (vault->m_config.auto_seal_on_write) {
        vault->seal();
    }
    return Result<std::shared_ptr<Vault>>::success(vault);
}

Vault::Vault(VaultConfig config, std::unique_ptr<SecuredMemorySpace> space)
    : m_config(std::move(config)), m_space(std::move(space)) {}

Vault::~Vault() {
    unload();
}

void Vault::unload() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_space) {
        apply_hardware_protection(false);
        m_space->unload();
        m_space.reset();
    }
    m_slots.clear();
    m_sealed = false;
}

void Vault::apply_hardware_protection(bool read_only) {
    if (!m_space || !m_space->raw_base() || m_space->capacity() == 0) return;
    int prot = read_only ? PROT_READ : (PROT_READ | PROT_WRITE);
    mprotect(m_space->raw_base(), m_space->capacity(), prot);
    m_sealed = read_only;
}

Result<void> Vault::seal() {
    std::lock_guard<std::mutex> lock(m_mutex);
    apply_hardware_protection(true);
    return Result<void>::success();
}

Result<void> Vault::unseal() {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto auth = check_caller_access(true);
    if (!auth.is_ok()) {
        return auth;
    }
    apply_hardware_protection(false);
    return Result<void>::success();
}

Result<void> Vault::check_caller_access(bool write_mode) const {
    std::string caller = ExecutionContext::current_domain();

    // System context holds universal administrative privileges
    if (caller == "system" || ExecutionContext::is_system()) {
        return Result<void>::success();
    }

    // Owner domain has full read/write access
    if (caller == m_config.owner_domain) {
        return Result<void>::success();
    }

    // If writing, strict ownership is enforced: non-owners cannot write into foreign vaults
    if (write_mode) {
        log_error("CRITICAL SECURITY VIOLATION: Domain '", caller,
                  "' attempted unauthorized write to Vault '", m_config.name,
                  "' owned by '", m_config.owner_domain, "'.");
        return Result<void>::failure(
            StatusCode::PermissionDenied,
            "Security Violation: Domain '" + caller + "' is unauthorized to write to Vault '" +
            m_config.name + "' owned by '" + m_config.owner_domain + "'."
        );
    }

    // For reading: verify cross-domain policy via DomainManager if available
    if (m_domain_mgr) {
        if (!m_domain_mgr->check_cross_domain_access(caller, m_config.owner_domain)) {
            log_error("CROSS-DOMAIN VIOLATION: Domain '", caller,
                      "' unauthorized to read secrets from Vault '", m_config.name,
                      "' owned by '", m_config.owner_domain, "'.");
            return Result<void>::failure(
                StatusCode::PermissionDenied,
                "Cross-Domain Violation: Domain '" + caller + "' is unauthorized to access Vault '" +
                m_config.name + "' owned by '" + m_config.owner_domain + "'."
            );
        }
        return Result<void>::success();
    }

    // Fallback: strict ownership check if DomainManager is absent
    return Result<void>::failure(
        StatusCode::PermissionDenied,
        "Security Violation: Domain '" + caller + "' is not permitted to access Vault '" +
        m_config.name + "' owned by '" + m_config.owner_domain + "'."
    );
}

Result<void> Vault::write_secret(const std::string& key, const std::string& secret_data) {
    if (key.empty()) {
        return Result<void>::failure(StatusCode::InvalidArg, "Secret key cannot be empty");
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    // 1. Authorize executing domain
    auto auth = check_caller_access(true);
    if (!auth.is_ok()) {
        return auth;
    }

    if (!m_space) {
        return Result<void>::failure(StatusCode::NullPointer, "Vault secured memory space is not initialized");
    }

    // 2. Temporarily unseal memory pages for writing
    bool was_sealed = m_sealed;
    if (was_sealed) {
        apply_hardware_protection(false);
    }

    // 3. Allocate slot in secured memory arena
    size_t needed = secret_data.size();
    if (needed > m_space->remaining_bytes()) {
        if (was_sealed) apply_hardware_protection(true);
        return Result<void>::failure(
            StatusCode::QuotaExceeded,
            "Vault capacity exceeded for key '" + key + "'. Needed " + std::to_string(needed) +
            " bytes, remaining " + std::to_string(m_space->remaining_bytes()) + " bytes."
        );
    }

    size_t offset = m_space->used_bytes();
    void* dest = m_space->allocate(needed);
    if (!dest) {
        if (was_sealed) apply_hardware_protection(true);
        return Result<void>::failure(StatusCode::OutOfMemory, "Failed to allocate memory block in vault");
    }

    std::memcpy(dest, secret_data.data(), needed);

    // 4. Compute cryptographic integrity checksum
    std::string checksum = Crypto::sha256_hex(secret_data);

    SecretSlot slot;
    slot.offset = offset;
    slot.size = needed;
    slot.checksum = std::move(checksum);
    m_slots[key] = std::move(slot);

    // 5. Hardware-reseal memory pages
    if (m_config.auto_seal_on_write || was_sealed) {
        apply_hardware_protection(true);
    }

    return Result<void>::success();
}

Result<std::string> Vault::read_secret(const std::string& key) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    // 1. Authorize caller domain
    auto auth = check_caller_access(false);
    if (!auth.is_ok()) {
        return Result<std::string>::failure(auth.status(), auth.error_message());
    }

    auto it = m_slots.find(key);
    if (it == m_slots.end()) {
        return Result<std::string>::failure(StatusCode::NotFound, "Secret key '" + key + "' not found in vault");
    }

    if (!m_space || !m_space->raw_base()) {
        return Result<std::string>::failure(StatusCode::NullPointer, "Vault secured memory is null");
    }

    const SecretSlot& slot = it->second;
    const char* base = static_cast<const char*>(m_space->raw_base());
    const char* data_ptr = base + slot.offset;
    std::string secret(data_ptr, slot.size);

    // 2. Verify cryptographic tamper detection
    std::string actual_hash = Crypto::sha256_hex(secret);
    if (actual_hash != slot.checksum) {
        log_error("CRITICAL TAMPER ALERT: Vault '", m_config.name,
                  "' key '", key, "' checksum mismatch! Expected ", slot.checksum,
                  ", got ", actual_hash);
        return Result<std::string>::failure(
            StatusCode::SecurityTampering,
            "CRITICAL SECURITY COMPROMISE: Vault data tampering detected for key '" + key + "'!"
        );
    }

    return Result<std::string>::success(std::move(secret));
}

bool Vault::has_secret(const std::string& key) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_slots.find(key) != m_slots.end();
}

std::vector<std::string> Vault::list_keys() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> keys;
    keys.reserve(m_slots.size());
    for (const auto& [k, _] : m_slots) {
        keys.push_back(k);
    }
    return keys;
}

Result<bool> Vault::verify_integrity() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_space || !m_space->raw_base()) {
        return Result<bool>::failure(StatusCode::NullPointer, "Vault secured memory is null");
    }

    const char* base = static_cast<const char*>(m_space->raw_base());
    for (const auto& [k, slot] : m_slots) {
        std::string secret(base + slot.offset, slot.size);
        std::string actual_hash = Crypto::sha256_hex(secret);
        if (actual_hash != slot.checksum) {
            log_error("TAMPER DETECTED in Vault '", m_config.name, "' key '", k, "'");
            return Result<bool>::failure(
                StatusCode::SecurityTampering,
                "Tampered data detected in Vault '" + m_config.name + "' for key '" + k + "'"
            );
        }
    }
    return Result<bool>::success(true);
}

size_t Vault::capacity() const {
    return m_space ? m_space->capacity() : 0;
}

size_t Vault::used_bytes() const {
    return m_space ? m_space->used_bytes() : 0;
}

size_t Vault::secret_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_slots.size();
}

} // namespace dvargosh
