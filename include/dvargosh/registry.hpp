#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <mutex>
#include <typeindex>

namespace dvargosh {

class DomainManager;
class SecuredMemorySpace;

using DynamicMethodFn = std::function<Result<Value>(const std::vector<Value>& args)>;
using UnresolvedHandler = std::function<Result<Value>(
    const std::string& method_name,
    const std::vector<Value>& args,
    const std::string& caller_domain
)>;

struct ServiceDescriptor {
    std::string name;
    Version version;
    std::string provider_module;
    std::string domain;
    std::type_index type_index;
    std::shared_ptr<void> instance;

    ServiceDescriptor(
        std::string n,
        Version v,
        std::string p,
        std::string d,
        std::type_index ti,
        std::shared_ptr<void> inst
    ) : name(std::move(n)),
        version(v),
        provider_module(std::move(p)),
        domain(std::move(d)),
        type_index(ti),
        instance(std::move(inst)) {}
};

struct MethodDescriptor {
    std::string name;
    std::string description;
    std::string provider_module;
    std::string domain;
    DynamicMethodFn fn;
};

class Registry {
public:
    Registry();
    ~Registry();

    void set_domain_manager(DomainManager* dm) { m_domain_mgr = dm; }
    DomainManager* domain_manager() const noexcept { return m_domain_mgr; }

    // Fallback handler for unresolved functions / services
    void set_unresolved_handler(UnresolvedHandler handler) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_unresolved_handler = std::move(handler);
    }

    // Register a typed service interface with domain
    template<typename Interface>
    Result<void> register_service(
        const std::string& service_name,
        std::shared_ptr<Interface> service_impl,
        Version version,
        const std::string& provider_module,
        const std::string& domain = "default",
        const SecurityPolicy* policy = nullptr
    ) {
        if (policy) {
            auto perm_res = policy->check(Permission::ServiceRegister, provider_module);
            if (!perm_res.is_ok()) return perm_res;
        }

        if (!service_impl) {
            return Result<void>::failure(StatusCode::NullPointer, "Service implementation cannot be null");
        }

        std::string scoped_domain = domain;
        if (scoped_domain == "*") {
            scoped_domain = provider_module + ".*";
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_services.find(service_name) != m_services.end()) {
            return Result<void>::failure(StatusCode::AlreadyExists, "Service '" + service_name + "' already registered");
        }

        m_services.insert_or_assign(
            service_name,
            ServiceDescriptor(
                service_name,
                version,
                provider_module,
                scoped_domain,
                std::type_index(typeid(Interface)),
                std::static_pointer_cast<void>(service_impl)
            )
        );
        return Result<void>::success();
    }

    // Retrieve typed service interface
    template<typename Interface>
    Result<std::shared_ptr<Interface>> get_service(
        const std::string& service_name,
        const std::string& caller_domain = ""
    ) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_services.find(service_name);
        if (it == m_services.end()) {
            return Result<std::shared_ptr<Interface>>::failure(
                StatusCode::NotFound, "Service '" + service_name + "' not found in registry"
            );
        }

        // Domain access check
        if (!caller_domain.empty() && m_domain_mgr) {
            if (!check_domain_access(caller_domain, it->second.domain)) {
                return Result<std::shared_ptr<Interface>>::failure(
                    StatusCode::PermissionDenied,
                    "Cross-Domain Violation: Domain '" + caller_domain + "' cannot access service in domain '" + it->second.domain + "'"
                );
            }
        }

        if (it->second.type_index != std::type_index(typeid(Interface))) {
            return Result<std::shared_ptr<Interface>>::failure(
                StatusCode::TypeMismatch, "Service '" + service_name + "' type mismatch requested vs registered"
            );
        }

        return Result<std::shared_ptr<Interface>>::success(
            std::static_pointer_cast<Interface>(it->second.instance)
        );
    }

    Result<void> unregister_service(const std::string& service_name);
    bool has_service(const std::string& service_name, Version min_version = Version{0,0,0}) const;
    std::string get_service_domain(const std::string& service_name) const;

    // --- Dynamic Global Calling / RPC ---
    Result<void> register_method(
        const std::string& method_name,
        const std::string& description,
        const std::string& provider_module,
        const std::string& domain,
        DynamicMethodFn fn,
        const SecurityPolicy* policy = nullptr
    );

    Result<void> register_method(
        const std::string& method_name,
        const std::string& description,
        const std::string& provider_module,
        DynamicMethodFn fn,
        const SecurityPolicy* policy = nullptr
    ) {
        return register_method(method_name, description, provider_module, "default", std::move(fn), policy);
    }

    Result<void> unregister_method(const std::string& method_name);
    bool has_method(const std::string& method_name) const;
    std::string get_method_domain(const std::string& method_name) const;

    // --- Alias Resolution for Namespace Distinguishment ---
    Result<void> register_alias(const std::string& alias, const std::string& target_method);
    bool has_alias(const std::string& alias) const;
    std::string resolve_method_name(const std::string& name_or_alias) const;

    Result<Value> invoke(
        const std::string& method_name,
        const std::vector<Value>& args = {},
        const std::string& caller_module = "",
        const std::string& caller_domain = "",
        const SecurityPolicy* caller_policy = nullptr
    );

    // Bulk cleanup for a module on hot-unplug
    size_t unregister_provider(const std::string& provider_module);

    bool check_domain_access(const std::string& from_domain, const std::string& to_domain) const;

    std::vector<std::string> list_methods() const;
    std::vector<std::string> list_services() const;
    bool has_provider(const std::string& provider_module) const;
    size_t service_count() const;
    size_t method_count() const;
    void dump_report() const;

private:
    std::string find_similar_method(const std::string& target) const;

    mutable std::mutex m_mutex;
    DomainManager* m_domain_mgr = nullptr;
    UnresolvedHandler m_unresolved_handler = nullptr;
    std::unordered_map<std::string, ServiceDescriptor> m_services;
    std::unordered_map<std::string, MethodDescriptor> m_methods;
    std::unordered_map<std::string, std::string> m_aliases;
};

} // namespace dvargosh
