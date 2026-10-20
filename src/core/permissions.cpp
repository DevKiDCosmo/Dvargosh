#include "dvargosh/permissions.hpp"
#include <sstream>

namespace dvargosh {

const char* permission_to_string(Permission p) {
    switch (p) {
        case Permission::None: return "None";
        case Permission::MemoryExpand: return "MemoryExpand";
        case Permission::FileIO: return "FileIO";
        case Permission::NetworkAccess: return "NetworkAccess";
        case Permission::ServiceRegister: return "ServiceRegister";
        case Permission::DynamicInvoke: return "DynamicInvoke";
        case Permission::EventPublish: return "EventPublish";
        case Permission::EventSubscribe: return "EventSubscribe";
        case Permission::SecuredMemory: return "SecuredMemory";
        case Permission::SystemInfo: return "SystemInfo";
        case Permission::Admin: return "Admin";
        default: return "CustomPermission";
    }
}

Permission string_to_permission(const std::string& str) {
    if (str == "MemoryExpand") return Permission::MemoryExpand;
    if (str == "FileIO") return Permission::FileIO;
    if (str == "NetworkAccess") return Permission::NetworkAccess;
    if (str == "ServiceRegister") return Permission::ServiceRegister;
    if (str == "DynamicInvoke") return Permission::DynamicInvoke;
    if (str == "EventPublish") return Permission::EventPublish;
    if (str == "EventSubscribe") return Permission::EventSubscribe;
    if (str == "SecuredMemory") return Permission::SecuredMemory;
    if (str == "SystemInfo") return Permission::SystemInfo;
    if (str == "Admin") return Permission::Admin;
    return Permission::None;
}

PermissionSet::PermissionSet(std::initializer_list<Permission> perms) : m_mask(Permission::None) {
    for (auto p : perms) {
        grant(p);
    }
}

std::vector<std::string> PermissionSet::to_strings() const {
    std::vector<std::string> res;
    if (has(Permission::Admin)) {
        res.push_back("Admin");
        return res;
    }
    const Permission checks[] = {
        Permission::MemoryExpand,
        Permission::FileIO,
        Permission::NetworkAccess,
        Permission::ServiceRegister,
        Permission::DynamicInvoke,
        Permission::EventPublish,
        Permission::EventSubscribe,
        Permission::SecuredMemory,
        Permission::SystemInfo
    };
    for (auto p : checks) {
        if (has(p)) {
            res.push_back(permission_to_string(p));
        }
    }
    return res;
}

PermissionSet PermissionSet::from_strings(const std::vector<std::string>& list) {
    PermissionSet set;
    for (const auto& s : list) {
        set.grant(string_to_permission(s));
    }
    return set;
}

PermissionSet PermissionSet::standard_module() {
    return PermissionSet({
        Permission::ServiceRegister,
        Permission::DynamicInvoke,
        Permission::EventPublish,
        Permission::EventSubscribe,
        Permission::SecuredMemory
    });
}

SecurityPolicy::SecurityPolicy()
    : m_permissions(PermissionSet::standard_module()),
      m_max_memory_bytes(16 * 1024 * 1024) {}

SecurityPolicy::SecurityPolicy(PermissionSet perms, size_t max_mem_bytes)
    : m_permissions(perms),
      m_max_memory_bytes(max_mem_bytes) {}

Result<void> SecurityPolicy::check(Permission p, const std::string& module_name) const {
    if (m_permissions.has(p)) {
        return Result<void>::success();
    }
    std::ostringstream ss;
    ss << "Module '" << module_name << "' denied permission '" << permission_to_string(p) << "'";
    return Result<void>::failure(StatusCode::PermissionDenied, ss.str());
}

void SecurityPolicy::enforce(Permission p, const std::string& module_name) const {
    auto res = check(p, module_name);
    if (!res.is_ok()) {
        throw SecurityException(res.error_message());
    }
}

SecurityPolicy SecurityPolicy::strict() {
    return SecurityPolicy(
        PermissionSet({Permission::SecuredMemory}),
        2 * 1024 * 1024 // 2 MB strict limit
    );
}

SecurityPolicy SecurityPolicy::standard() {
    return SecurityPolicy(
        PermissionSet::standard_module(),
        16 * 1024 * 1024 // 16 MB limit
    );
}

SecurityPolicy SecurityPolicy::permissive() {
    return SecurityPolicy(
        PermissionSet::all(),
        256 * 1024 * 1024 // 256 MB limit
    );
}

} // namespace dvargosh
