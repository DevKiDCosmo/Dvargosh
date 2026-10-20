#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include "secured_memory.hpp"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include <mutex>

namespace dvargosh {

class Domain {
public:
    Domain(
        std::string name,
        SecurityPolicy policy,
        std::unique_ptr<SecuredMemorySpace> secured_space = nullptr
    );
    ~Domain() = default;

    const std::string& name() const noexcept { return m_name; }
    const SecurityPolicy& policy() const noexcept { return m_policy; }
    SecurityPolicy& policy() noexcept { return m_policy; }

    SecuredMemorySpace* secured_space() noexcept { return m_secured_space.get(); }
    const SecuredMemorySpace* secured_space() const noexcept { return m_secured_space.get(); }

    void set_secured_space(std::unique_ptr<SecuredMemorySpace> space) {
        m_secured_space = std::move(space);
    }

    // Cross-Domain Access Rules
    void allow_access_to(const std::string& target_domain);
    void revoke_access_to(const std::string& target_domain);
    bool can_access_domain(const std::string& target_domain) const;
    const std::unordered_set<std::string>& allowed_targets() const noexcept { return m_allowed_targets; }

    // Associated modules & services
    void add_module(const std::string& mod_name);
    void remove_module(const std::string& mod_name);
    bool has_module(const std::string& mod_name) const;
    const std::vector<std::string>& modules() const noexcept { return m_modules; }

    void add_service(const std::string& svc_name);
    void remove_service(const std::string& svc_name);
    const std::vector<std::string>& services() const noexcept { return m_services; }

private:
    std::string m_name;
    SecurityPolicy m_policy;
    std::unique_ptr<SecuredMemorySpace> m_secured_space;
    std::unordered_set<std::string> m_allowed_targets;
    std::vector<std::string> m_modules;
    std::vector<std::string> m_services;
};

class ModuleLoader; // Forward declaration

class DomainManager {
public:
    DomainManager();
    ~DomainManager() = default;

    // Domain creation & registration
    Result<Domain*> create_domain(
        const std::string& domain_name,
        const SecurityPolicy& policy = SecurityPolicy::standard(),
        size_t secured_memory_bytes = 0,
        bool use_guard_pages = true
    );

    Domain* get_domain(const std::string& domain_name);
    const Domain* get_domain(const std::string& domain_name) const;
    bool has_domain(const std::string& domain_name) const;

    // Cross-Domain Permissions
    Result<void> allow_cross_domain(const std::string& from_domain, const std::string& to_domain);
    bool check_cross_domain_access(const std::string& from_domain, const std::string& to_domain) const;

    // Domain-level secured memory access
    SecuredMemorySpace* get_domain_space(const std::string& domain_name);

    // Explicit function to init a secured memory space for a domain (as requested)
    Result<SecuredMemorySpace*> init_domain_space(
        const std::string& domain_name,
        size_t capacity_bytes = 4 * 1024 * 1024,
        bool use_guard_pages = true
    );

    // Domain-wide plug and unplug
    Result<size_t> unplug_domain(const std::string& domain_name, ModuleLoader& loader);

    std::vector<std::string> list_domains() const;
    void dump_report() const;

private:
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::unique_ptr<Domain>> m_domains;
};

// Global top-level factory to initialize a secured domain space directly
Result<std::unique_ptr<SecuredMemorySpace>> init_domain_secured_space(
    const std::string& domain_name,
    size_t capacity_bytes = 4 * 1024 * 1024,
    bool enable_guard_pages = true
);

} // namespace dvargosh
