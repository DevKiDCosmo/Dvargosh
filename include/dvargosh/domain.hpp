#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include "secured_memory.hpp"
#include "vault.hpp"
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include <mutex>

namespace dvargosh {

/**
 * @brief Represents a logical subsystem domain boundary within the Dvargosh runtime.
 *
 * A Domain groups modules and services together under a common isolation boundary,
 * security policy, and dedicated hardware-guarded memory container.
 */
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

    void allow_access_to(const std::string& target_domain);
    void revoke_access_to(const std::string& target_domain);
    void blacklist_domain(const std::string& target_domain);
    void unblacklist_domain(const std::string& target_domain);
    bool is_domain_blacklisted(const std::string& target_domain) const;
    bool can_access_domain(const std::string& target_domain) const;
    const std::unordered_set<std::string>& allowed_targets() const noexcept { return m_allowed_targets; }
    const std::unordered_set<std::string>& blacklisted_targets() const noexcept { return m_blacklisted_targets; }

    Result<void> unload_secured_space();
    Result<void> unload_vaults();

    void add_module(const std::string& mod_name);
    void remove_module(const std::string& mod_name);
    bool has_module(const std::string& mod_name) const;
    const std::vector<std::string>& modules() const noexcept { return m_modules; }

    void add_service(const std::string& svc_name);
    void remove_service(const std::string& svc_name);
    const std::vector<std::string>& services() const noexcept { return m_services; }

    Result<void> add_vault(std::shared_ptr<Vault> vault);
    std::shared_ptr<Vault> get_vault(const std::string& vault_name) const;
    const std::unordered_map<std::string, std::shared_ptr<Vault>>& vaults() const noexcept { return m_vaults; }

private:
    std::string m_name;
    SecurityPolicy m_policy;
    std::unique_ptr<SecuredMemorySpace> m_secured_space;
    std::unordered_set<std::string> m_allowed_targets;
    std::unordered_set<std::string> m_blacklisted_targets;
    std::vector<std::string> m_modules;
    std::vector<std::string> m_services;
    std::unordered_map<std::string, std::shared_ptr<Vault>> m_vaults;
};

class ModuleLoader; // Forward declaration

/**
 * @brief Thread-safe manager for system-wide domains, cross-domain access matrices,
 * and subsystem memory allocations.
 */
class DomainManager {
public:
    DomainManager();
    ~DomainManager() = default;

    Result<Domain*> create_domain(
        const std::string& domain_name,
        const SecurityPolicy& policy = SecurityPolicy::standard(),
        size_t secured_memory_bytes = 0,
        bool use_guard_pages = true
    );

    Domain* get_domain(const std::string& domain_name);
    const Domain* get_domain(const std::string& domain_name) const;
    bool has_domain(const std::string& domain_name) const;

    Result<void> allow_cross_domain(const std::string& from_domain, const std::string& to_domain);
    Result<void> blacklist_domain(const std::string& from_domain, const std::string& to_domain);
    Result<void> unblacklist_domain(const std::string& from_domain, const std::string& to_domain);
    bool is_cross_domain_blacklisted(const std::string& from_domain, const std::string& to_domain) const;
    bool check_cross_domain_access(const std::string& from_domain, const std::string& to_domain) const;

    /**
     * @brief Inter-module coarse permission grant.
     * Grants permission for callers in from_domain to access any exported service in to_module.
     * Configured as a bidirectional cross-module grant between from_domain and to_module.
     * @param from_domain Calling subsystem domain.
     * @param to_module Target module name.
     */
    Result<void> allow_cross_module(const std::string& from_domain, const std::string& to_module);

    /**
     * @brief Inter-module fine-grained permission grant.
     * Grants unidirectional permission for from_domain to access specifically target_domain in target_module.
     * @param from_domain Calling subsystem domain.
     * @param target_domain Target subsystem domain in target_module.
     * @param target_module Target module name.
     */
    Result<void> allow_cross_module_specific(
        const std::string& from_domain,
        const std::string& target_domain,
        const std::string& target_module
    );

    /**
     * @brief Ingress permission grant.
     * Explicitly allows incoming calls from from_module.
     * @param from_module Calling module permitted to enter.
     */
    Result<void> allow_access_to(const std::string& from_module);

    /**
     * @brief Ingress fine-grained permission grant.
     * Explicitly allows incoming calls specifically from from_domain of from_module.
     * @param from_domain Calling subsystem domain.
     * @param from_module Calling module name.
     */
    Result<void> allow_access_to_specific(const std::string& from_domain, const std::string& from_module);

    /**
     * @brief Ingress wildcard grant.
     * Allows all incoming cross-module calls without requiring explicit per-module allow rules.
     */
    Result<void> allow_all_income();

    /**
     * @brief Unified cross-domain and cross-module execution access validator.
     * Evaluates wildcard openness, system privilege, blacklists, intra-module unidirectional rules,
     * inter-module egress grants, and inter-module ingress grants.
     * @param from_module Source module initiating the execution.
     * @param from_domain Source subsystem domain initiating the execution.
     * @param to_module Target module hosting the service.
     * @param to_domain Target subsystem domain hosting the service.
     * @return true if execution is permitted, false otherwise.
     */
    bool check_execution_access(
        const std::string& from_module,
        const std::string& from_domain,
        const std::string& to_module,
        const std::string& to_domain
    ) const;

    Result<void> unload_domain_space(const std::string& domain_name);
    Result<void> unload_domain_vaults(const std::string& domain_name);

    SecuredMemorySpace* get_domain_space(const std::string& domain_name);
    Result<SecuredMemorySpace*> get_domain_space(const std::string& domain_name, const std::string& caller_domain);

    Result<std::shared_ptr<Vault>> create_vault(const VaultConfig& config);
    std::shared_ptr<Vault> get_vault(const std::string& vault_name) const;
    Result<std::shared_ptr<Vault>> get_domain_vault(const std::string& domain_name, const std::string& vault_name = "default");
    std::vector<std::shared_ptr<Vault>> list_all_vaults() const;
    std::vector<std::shared_ptr<Vault>> list_domain_vaults(const std::string& domain_name) const;

    Result<SecuredMemorySpace*> init_domain_space(
        const std::string& domain_name,
        size_t capacity_bytes = 4 * 1024 * 1024,
        bool use_guard_pages = true
    );

    Result<size_t> unplug_domain(const std::string& domain_name, ModuleLoader& loader);

    std::vector<std::string> list_domains() const;
    void dump_report() const;
    void dump_memory_report() const;

private:
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::unique_ptr<Domain>> m_domains;

    // Isolation Matrix Storage
    bool m_allow_all_income = false;
    std::unordered_map<std::string, std::unordered_set<std::string>> m_intra_domain_allows;
    std::unordered_map<std::string, std::unordered_set<std::string>> m_cross_module_allows;
    std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_set<std::string>>> m_cross_module_specific_allows;
    std::unordered_set<std::string> m_ingress_allowed_modules;
    std::unordered_map<std::string, std::unordered_set<std::string>> m_ingress_specific_allows;
};

Result<std::unique_ptr<SecuredMemorySpace>> init_domain_secured_space(
    const std::string& domain_name,
    size_t capacity_bytes = 4 * 1024 * 1024,
    bool enable_guard_pages = true
);

} // namespace dvargosh
