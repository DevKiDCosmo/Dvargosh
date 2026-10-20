#pragma once

#include "types.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

namespace dvargosh {

enum class Permission : uint32_t {
    None             = 0,
    MemoryExpand     = 1 << 0,  // Request expansion of memory bounds
    FileIO           = 1 << 1,  // Read/write to disk
    NetworkAccess    = 1 << 2,  // Sockets / network
    ServiceRegister  = 1 << 3,  // Register public services
    DynamicInvoke    = 1 << 4,  // Dynamically invoke foreign services
    EventPublish     = 1 << 5,  // Broadcast events to system
    EventSubscribe   = 1 << 6,  // Receive system events
    SecuredMemory    = 1 << 7,  // Allocate hardware-isolated secured memory
    SystemInfo       = 1 << 8,  // Introspect host hardware/system
    Admin            = 0xFFFFFFFF
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
    std::vector<std::string> to_strings() const;
    static PermissionSet from_strings(const std::vector<std::string>& list);

    static PermissionSet all() { return PermissionSet(Permission::Admin); }
    static PermissionSet none() { return PermissionSet(Permission::None); }
    static PermissionSet standard_module();

private:
    Permission m_mask;
};

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
    size_t m_max_memory_bytes = 16 * 1024 * 1024; // 16 MB default quota
};

} // namespace dvargosh
