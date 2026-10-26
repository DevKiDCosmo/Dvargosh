#pragma once

#include "types.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

namespace dvargosh {

/**
 * @brief Discrete capabilities and operational privileges enforced by the Dvargosh security kernel.
 */
enum class Permission : uint32_t {
    None             = 0,
    MemoryExpand     = 1 << 0,  ///< Capability to request expansion of memory limits
    FileIO           = 1 << 1,  ///< Direct read/write filesystem access
    NetworkAccess    = 1 << 2,  ///< Raw socket and network endpoint communication
    ServiceRegister  = 1 << 3,  ///< Ability to register public services in the registry
    DynamicInvoke    = 1 << 4,  ///< Dynamically invoke foreign services across domain boundaries
    EventPublish     = 1 << 5,  ///< Broadcast events onto the central event bus
    EventSubscribe   = 1 << 6,  ///< Subscribe to system-wide event topics
    SecuredMemory    = 1 << 7,  ///< Allocate hardware-isolated, page-guarded memory containers
    SystemInfo       = 1 << 8,  ///< Introspect host hardware and CPU telemetry
    Admin            = 0xFFFFFFFF ///< Full administrative privileges
};

inline Permission operator|(Permission a, Permission b) {
    return static_cast<Permission>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline Permission operator&(Permission a, Permission b) {
    return static_cast<Permission>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline Permission operator~(Permission a) {
    return static_cast<Permission>(~static_cast<uint32_t>(a));
}

const char* permission_to_string(Permission p);
Permission string_to_permission(const std::string& str);

/**
 * @brief Bitmask container representing a composite set of Granted Permissions.
 */
class PermissionSet {
public:
    PermissionSet() : m_mask(Permission::None) {}
    PermissionSet(Permission mask) : m_mask(mask) {}
    PermissionSet(std::initializer_list<Permission> perms);

    void grant(Permission p) { m_mask = m_mask | p; }
    void revoke(Permission p) { m_mask = static_cast<Permission>(static_cast<uint32_t>(m_mask) & ~static_cast<uint32_t>(p)); }
    bool has(Permission p) const noexcept {
        uint32_t req = static_cast<uint32_t>(p);
        return (static_cast<uint32_t>(m_mask) & req) == req;
    }

    Permission raw_mask() const noexcept { return m_mask; }
    PermissionSet intersect_with(const PermissionSet& other) const noexcept {
        return PermissionSet(static_cast<Permission>(static_cast<uint32_t>(m_mask) & static_cast<uint32_t>(other.m_mask)));
    }
    std::vector<std::string> to_strings() const;
    static PermissionSet from_strings(const std::vector<std::string>& list);

    static PermissionSet all() { return PermissionSet(Permission::Admin); }
    static PermissionSet none() { return PermissionSet(Permission::None); }
    static PermissionSet standard_module();

private:
    Permission m_mask;
};

/**
 * @brief Active Security Policy governing permissions, memory quotas, and cross-module checks.
 */
class SecurityPolicy {
public:
    SecurityPolicy();
    SecurityPolicy(PermissionSet perms, size_t max_mem_bytes);

    const PermissionSet& permissions() const noexcept { return m_permissions; }
    PermissionSet& permissions() noexcept { return m_permissions; }
    size_t max_memory_bytes() const noexcept { return m_max_memory_bytes; }
    void set_max_memory_bytes(size_t bytes) { m_max_memory_bytes = bytes; }

    Result<void> check(Permission p, const std::string& module_name) const;
    void enforce(Permission p, const std::string& module_name) const;

    static SecurityPolicy strict();
    static SecurityPolicy standard();
    static SecurityPolicy permissive();

private:
    PermissionSet m_permissions;
    size_t m_max_memory_bytes = 16 * 1024 * 1024;
};

} // namespace dvargosh
