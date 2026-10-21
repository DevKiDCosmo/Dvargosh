#include "dvargosh/domain.hpp"
#include "dvargosh/module_loader.hpp"
#include "dvargosh/execution_context.hpp"
#include "dvargosh/logger.hpp"
#include <iostream>
#include <algorithm>

namespace dvargosh {

/* ========================================================================= */
/* Domain                                                                    */
/* ========================================================================= */

Domain::Domain(
    std::string name,
    SecurityPolicy policy,
    std::unique_ptr<SecuredMemorySpace> secured_space
) : m_name(std::move(name)),
    m_policy(std::move(policy)),
    m_secured_space(std::move(secured_space)) {
    // A domain always has access to itself
    m_allowed_targets.insert(m_name);
}

void Domain::allow_access_to(const std::string& target_domain) {
    m_allowed_targets.insert(target_domain);
}

void Domain::revoke_access_to(const std::string& target_domain) {
    if (target_domain != m_name) {
        m_allowed_targets.erase(target_domain);
    }
}

void Domain::blacklist_domain(const std::string& target_domain) {
    m_blacklisted_targets.insert(target_domain);
}

void Domain::unblacklist_domain(const std::string& target_domain) {
    m_blacklisted_targets.erase(target_domain);
}

bool Domain::is_domain_blacklisted(const std::string& target_domain) const {
    if (m_blacklisted_targets.find("*") != m_blacklisted_targets.end()) return true;
    return m_blacklisted_targets.find(target_domain) != m_blacklisted_targets.end();
}

bool Domain::can_access_domain(const std::string& target_domain) const {
    if (target_domain.empty()) return false;
    if (is_domain_blacklisted(target_domain)) return false;
    if (target_domain == m_name) return true;
    if (m_allowed_targets.find("*") != m_allowed_targets.end()) return true;
    if (m_allowed_targets.find(target_domain) != m_allowed_targets.end()) return true;
    if (target_domain == "*" || (target_domain.size() >= 2 && target_domain.substr(target_domain.size() - 2) == ".*")) {
        return true;
    }
    return false;
}

Result<void> Domain::unload_secured_space() {
    if (m_secured_space) {
        m_secured_space->unload();
        m_secured_space.reset();
    }
    return Result<void>::success();
}

Result<void> Domain::unload_vaults() {
    for (auto& [_, vault] : m_vaults) {
        if (vault) {
            vault->unload();
        }
    }
    m_vaults.clear();
    return Result<void>::success();
}

void Domain::add_module(const std::string& mod_name) {
    if (std::find(m_modules.begin(), m_modules.end(), mod_name) == m_modules.end()) {
        m_modules.push_back(mod_name);
    }
}

void Domain::remove_module(const std::string& mod_name) {
    m_modules.erase(std::remove(m_modules.begin(), m_modules.end(), mod_name), m_modules.end());
}

bool Domain::has_module(const std::string& mod_name) const {
    return std::find(m_modules.begin(), m_modules.end(), mod_name) != m_modules.end();
}

void Domain::add_service(const std::string& svc_name) {
    if (std::find(m_services.begin(), m_services.end(), svc_name) == m_services.end()) {
        m_services.push_back(svc_name);
    }
}

void Domain::remove_service(const std::string& svc_name) {
    m_services.erase(std::remove(m_services.begin(), m_services.end(), svc_name), m_services.end());
}

Result<void> Domain::add_vault(std::shared_ptr<Vault> vault) {
    if (!vault) return Result<void>::failure(StatusCode::NullPointer, "Vault pointer cannot be null");
    m_vaults[vault->name()] = std::move(vault);
    return Result<void>::success();
}

std::shared_ptr<Vault> Domain::get_vault(const std::string& vault_name) const {
    auto it = m_vaults.find(vault_name);
    return it != m_vaults.end() ? it->second : nullptr;
}

/* ========================================================================= */
/* DomainManager                                                             */
/* ========================================================================= */

DomainManager::DomainManager() {
    // Create standard default domains
    create_domain("system", SecurityPolicy::permissive());
    create_domain("core", SecurityPolicy::permissive());
    create_domain("default", SecurityPolicy::standard());

    // System domain has universal access to all domains
    allow_cross_domain("system", "*");
}

Result<Domain*> DomainManager::create_domain(
    const std::string& domain_name,
    const SecurityPolicy& policy,
    size_t secured_memory_bytes,
    bool use_guard_pages
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_domains.find(domain_name) != m_domains.end()) {
        return Result<Domain*>::failure(StatusCode::AlreadyExists, "Domain '" + domain_name + "' already exists");
    }

    std::unique_ptr<SecuredMemorySpace> sec_space = nullptr;
    if (secured_memory_bytes > 0) {
        SecuredMemoryConfig cfg;
        cfg.container_name = "domain_" + domain_name;
        cfg.capacity_bytes = secured_memory_bytes;
        cfg.use_guard_pages = use_guard_pages;

        SecurityPolicy mem_policy = policy;
        mem_policy.permissions().grant(Permission::SecuredMemory);
        auto space_res = SecuredMemorySpace::create(cfg, mem_policy);
        if (space_res.is_ok()) {
            sec_space = std::move(space_res.value());
        }
    }

    auto domain = std::make_unique<Domain>(domain_name, policy, std::move(sec_space));
    Domain* ptr = domain.get();
    m_domains[domain_name] = std::move(domain);

    return Result<Domain*>::success(ptr);
}

Domain* DomainManager::get_domain(const std::string& domain_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(domain_name);
    return (it != m_domains.end()) ? it->second.get() : nullptr;
}

const Domain* DomainManager::get_domain(const std::string& domain_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(domain_name);
    return (it != m_domains.end()) ? it->second.get() : nullptr;
}

bool DomainManager::has_domain(const std::string& domain_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_domains.find(domain_name) != m_domains.end();
}

Result<void> DomainManager::allow_cross_domain(const std::string& from_domain, const std::string& to_domain) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(from_domain);
    if (it == m_domains.end()) {
        // Auto-create domain with standard policy if it does not exist yet
        auto domain = std::make_unique<Domain>(from_domain, SecurityPolicy::standard(), nullptr);
        domain->allow_access_to(to_domain);
        m_domains[from_domain] = std::move(domain);
        return Result<void>::success();
    }
    it->second->allow_access_to(to_domain);
    return Result<void>::success();
}

Result<void> DomainManager::blacklist_domain(const std::string& from_domain, const std::string& to_domain) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(from_domain);
    if (it == m_domains.end()) {
        auto domain = std::make_unique<Domain>(from_domain, SecurityPolicy::standard(), nullptr);
        domain->blacklist_domain(to_domain);
        m_domains[from_domain] = std::move(domain);
        return Result<void>::success();
    }
    it->second->blacklist_domain(to_domain);
    return Result<void>::success();
}

Result<void> DomainManager::unblacklist_domain(const std::string& from_domain, const std::string& to_domain) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(from_domain);
    if (it != m_domains.end()) {
        it->second->unblacklist_domain(to_domain);
    }
    return Result<void>::success();
}

bool DomainManager::is_cross_domain_blacklisted(const std::string& from_domain, const std::string& to_domain) const {
    if (from_domain.empty() || to_domain.empty()) return false;
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(from_domain);
    return it != m_domains.end() && it->second->is_domain_blacklisted(to_domain);
}

bool DomainManager::check_cross_domain_access(const std::string& from_domain, const std::string& to_domain) const {
    if (from_domain.empty() || to_domain.empty()) return false;
    if (from_domain == "system") return true;
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(from_domain);
    if (it == m_domains.end()) {
        // Unmanaged / unknown callers can only access public wildcard services
        return (to_domain == "*" || (to_domain.size() >= 2 && to_domain.substr(to_domain.size() - 2) == ".*"));
    }
    return it->second->can_access_domain(to_domain);
}

Result<void> DomainManager::unload_domain_space(const std::string& domain_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(domain_name);
    if (it == m_domains.end()) {
        return Result<void>::failure(StatusCode::NotFound, "Domain '" + domain_name + "' not found");
    }
    return it->second->unload_secured_space();
}

Result<void> DomainManager::unload_domain_vaults(const std::string& domain_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(domain_name);
    if (it == m_domains.end()) {
        return Result<void>::failure(StatusCode::NotFound, "Domain '" + domain_name + "' not found");
    }
    return it->second->unload_vaults();
}

SecuredMemorySpace* DomainManager::get_domain_space(const std::string& domain_name) {
    if (domain_name.empty()) return nullptr;
    if (ExecutionContext::frame_depth() > 0) {
        std::string caller = ExecutionContext::current_domain();
        if (caller != "system" && caller != domain_name) {
            if (!check_cross_domain_access(caller, domain_name)) {
                log_error("CROSS-DOMAIN VIOLATION: Current domain '", caller,
                          "' is not authorized to acquire raw pointer to domain space '", domain_name, "'.");
                return nullptr;
            }
        }
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(domain_name);
    if (it != m_domains.end()) {
        return it->second->secured_space();
    }
    return nullptr;
}

Result<SecuredMemorySpace*> DomainManager::get_domain_space(
    const std::string& domain_name,
    const std::string& caller_domain
) {
    if (domain_name.empty()) {
        return Result<SecuredMemorySpace*>::failure(StatusCode::InvalidArg, "Target domain name cannot be empty");
    }
    std::string effective_caller = caller_domain;
    if (effective_caller.empty()) {
        effective_caller = ExecutionContext::current_domain();
    } else {
        auto tamper = ExecutionContext::verify_not_tampered(caller_domain);
        if (!tamper.is_ok()) {
            return Result<SecuredMemorySpace*>::failure(tamper.status(), tamper.error_message());
        }
    }

    if (effective_caller.empty() || (effective_caller != "system" && effective_caller != domain_name)) {
        if (effective_caller.empty() || !check_cross_domain_access(effective_caller, domain_name)) {
            return Result<SecuredMemorySpace*>::failure(
                StatusCode::PermissionDenied,
                "Cross-Domain Violation: Domain '" + (effective_caller.empty() ? "<empty>" : effective_caller) +
                "' is unauthorized to access secured memory space of domain '" + domain_name + "'"
            );
        }
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(domain_name);
    if (it == m_domains.end() || !it->second->secured_space()) {
        return Result<SecuredMemorySpace*>::failure(StatusCode::NotFound, "No secured memory space found in domain '" + domain_name + "'");
    }
    return Result<SecuredMemorySpace*>::success(it->second->secured_space());
}

Result<std::shared_ptr<Vault>> DomainManager::create_vault(const VaultConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(config.owner_domain);
    if (it == m_domains.end()) {
        return Result<std::shared_ptr<Vault>>::failure(
            StatusCode::NotFound, "Cannot create vault: owner domain '" + config.owner_domain + "' does not exist"
        );
    }

    auto vault_res = Vault::create(config);
    if (!vault_res.is_ok()) {
        return vault_res;
    }

    vault_res.value()->set_domain_manager(this);
    it->second->add_vault(vault_res.value());
    return vault_res;
}

std::shared_ptr<Vault> DomainManager::get_vault(const std::string& vault_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [_, domain] : m_domains) {
        auto v = domain->get_vault(vault_name);
        if (v) return v;
    }
    return nullptr;
}

Result<std::shared_ptr<Vault>> DomainManager::get_domain_vault(
    const std::string& domain_name,
    const std::string& vault_name
) {
    if (domain_name.empty()) {
        return Result<std::shared_ptr<Vault>>::failure(StatusCode::InvalidArg, "Target domain name cannot be empty");
    }
    if (ExecutionContext::frame_depth() > 0) {
        std::string caller = ExecutionContext::current_domain();
        if (caller != "system" && caller != domain_name) {
            if (!check_cross_domain_access(caller, domain_name)) {
                return Result<std::shared_ptr<Vault>>::failure(
                    StatusCode::PermissionDenied,
                    "Cross-Domain Violation: Domain '" + caller + "' cannot access vaults in domain '" + domain_name + "'"
                );
            }
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(domain_name);
    if (it == m_domains.end()) {
        return Result<std::shared_ptr<Vault>>::failure(StatusCode::NotFound, "Domain '" + domain_name + "' not found");
    }

    auto v = it->second->get_vault(vault_name);
    if (!v) {
        return Result<std::shared_ptr<Vault>>::failure(StatusCode::NotFound, "Vault '" + vault_name + "' not found in domain '" + domain_name + "'");
    }
    return Result<std::shared_ptr<Vault>>::success(v);
}

Result<SecuredMemorySpace*> DomainManager::init_domain_space(
    const std::string& domain_name,
    size_t capacity_bytes,
    bool use_guard_pages
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_domains.find(domain_name);
    if (it == m_domains.end()) {
        return Result<SecuredMemorySpace*>::failure(StatusCode::NotFound, "Domain '" + domain_name + "' not found");
    }

    SecuredMemoryConfig cfg;
    cfg.container_name = "domain_" + domain_name;
    cfg.capacity_bytes = capacity_bytes;
    cfg.use_guard_pages = use_guard_pages;

    SecurityPolicy policy = it->second->policy();
    policy.permissions().grant(Permission::SecuredMemory);

    auto space_res = SecuredMemorySpace::create(cfg, policy);
    if (!space_res.is_ok()) {
        return Result<SecuredMemorySpace*>::failure(space_res.status(), space_res.error_message());
    }

    SecuredMemorySpace* ptr = space_res.value().get();
    it->second->set_secured_space(std::move(space_res.value()));
    return Result<SecuredMemorySpace*>::success(ptr);
}

Result<size_t> DomainManager::unplug_domain(const std::string& domain_name, ModuleLoader& loader) {
    std::vector<std::string> modules_to_unload;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_domains.find(domain_name);
        if (it == m_domains.end()) {
            return Result<size_t>::failure(StatusCode::NotFound, "Domain '" + domain_name + "' not found");
        }
        modules_to_unload = it->second->modules();
    }

    size_t count = 0;
    for (const auto& mod : modules_to_unload) {
        if (loader.is_loaded(mod)) {
            auto res = loader.unload_module(mod);
            if (res.is_ok()) {
                count++;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_domains.find(domain_name);
        if (it != m_domains.end()) {
            for (const auto& mod : modules_to_unload) {
                it->second->remove_module(mod);
            }
            // Explicitly unload safe pages, secured memory spaces, and vaults upon domain unplug
            it->second->unload_secured_space();
            it->second->unload_vaults();
        }
    }

    return Result<size_t>::success(count);
}

std::vector<std::shared_ptr<Vault>> DomainManager::list_all_vaults() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::shared_ptr<Vault>> list;
    for (const auto& [_, domain] : m_domains) {
        for (const auto& [__, vault] : domain->vaults()) {
            if (vault) list.push_back(vault);
        }
    }
    return list;
}

std::vector<std::shared_ptr<Vault>> DomainManager::list_domain_vaults(const std::string& domain_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::shared_ptr<Vault>> list;
    auto it = m_domains.find(domain_name);
    if (it != m_domains.end()) {
        for (const auto& [_, vault] : it->second->vaults()) {
            if (vault) list.push_back(vault);
        }
    }
    return list;
}

void DomainManager::dump_memory_report() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << "\n┌────────────────────────────────────────────────────────────────────────┐\n";
    std::cout << "│                 DVARGOSH DOMAIN & VAULT MEMORY REPORT                  │\n";
    std::cout << "├──────────────────┬──────────────┬──────────────┬───────────────────────┤\n";
    std::cout << "│ Domain Name      │ Capacity     │ Used Memory  │ Active Vaults         │\n";
    std::cout << "├──────────────────┼──────────────┼──────────────┼───────────────────────┤\n";
    for (const auto& [name, d] : m_domains) {
        std::string cap_str = d->secured_space() ? std::to_string(d->secured_space()->capacity() / 1024) + " KB" : "None";
        std::string used_str = d->secured_space() ? std::to_string(d->secured_space()->used_bytes()) + " B" : "0 B";
        std::string vault_str = std::to_string(d->vaults().size()) + " vault(s)";

        std::cout << "│ " << name;
        for (size_t i = name.length(); i < 16; ++i) std::cout << " ";
        std::cout << " │ " << cap_str;
        for (size_t i = cap_str.length(); i < 12; ++i) std::cout << " ";
        std::cout << " │ " << used_str;
        for (size_t i = used_str.length(); i < 12; ++i) std::cout << " ";
        std::cout << " │ " << vault_str;
        for (size_t i = vault_str.length(); i < 21; ++i) std::cout << " ";
        std::cout << " │\n";
    }
    std::cout << "└──────────────────┴──────────────┴──────────────┴───────────────────────┘\n\n";
}

std::vector<std::string> DomainManager::list_domains() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> list;
    for (const auto& [name, _] : m_domains) {
        list.push_back(name);
    }
    return list;
}

void DomainManager::dump_report() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << "\n┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│                 DVARGOSH DOMAIN REGISTRY                    │\n";
    std::cout << "├──────────────┬────────────┬─────────────┬───────────────────┤\n";
    std::cout << "│ Domain Name  │ Modules    │ Services    │ Secured Memory    │\n";
    std::cout << "├──────────────┼────────────┼─────────────┼───────────────────┤\n";
    for (const auto& [name, d] : m_domains) {
        std::string mem_str = "None";
        if (d->secured_space()) {
            mem_str = std::to_string(d->secured_space()->capacity() / 1024) + " KB";
        }
        std::cout << "│ " << name;
        for (size_t i = name.length(); i < 12; ++i) std::cout << " ";
        std::cout << " │ " << d->modules().size();
        std::cout << (d->modules().size() < 10 ? "         │ " : "        │ ");
        std::cout << d->services().size();
        std::cout << (d->services().size() < 10 ? "          │ " : "         │ ");
        std::cout << mem_str;
        for (size_t i = mem_str.length(); i < 17; ++i) std::cout << " ";
        std::cout << " │\n";
    }
    std::cout << "└──────────────┴────────────┴─────────────┴───────────────────┘\n\n";
}

Result<std::unique_ptr<SecuredMemorySpace>> init_domain_secured_space(
    const std::string& domain_name,
    size_t capacity_bytes,
    bool enable_guard_pages
) {
    return init_secured_memory_space("domain_" + domain_name, capacity_bytes, enable_guard_pages);
}

} // namespace dvargosh
