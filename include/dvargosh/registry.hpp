#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <mutex>
#include <any>
#include <typeindex>

namespace dvargosh {

using DynamicMethodFn = std::function<Result<Value>(const std::vector<Value>& args)>;

struct ServiceDescriptor {
    std::string name;
    Version version;
    std::string provider_module;
    std::type_index type_index;
    std::shared_ptr<void> instance;

    ServiceDescriptor(std::string n, Version v, std::string p, std::type_index ti, std::shared_ptr<void> inst)
        : name(std::move(n)), version(v), provider_module(std::move(p)), type_index(ti), instance(std::move(inst)) {}
};

struct MethodDescriptor {
    std::string name;
    std::string description;
    std::string provider_module;
    DynamicMethodFn fn;
};

class Registry {
public:
    Registry();
    ~Registry();

    // Register a typed service interface
    template<typename Interface>
    Result<void> register_service(
        const std::string& service_name,
        std::shared_ptr<Interface> service_impl,
        Version version,
        const std::string& provider_module,
        const SecurityPolicy* policy = nullptr
    ) {
        if (policy) {
            auto perm_res = policy->check(Permission::ServiceRegister, provider_module);
            if (!perm_res.is_ok()) return perm_res;
        }

        if (!service_impl) {
            return Result<void>::failure(StatusCode::NullPointer, "Service implementation cannot be null");
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
                std::type_index(typeid(Interface)),
                std::static_pointer_cast<void>(service_impl)
            )
        );
        return Result<void>::success();
    }

    // Retrieve typed service interface
    template<typename Interface>
    Result<std::shared_ptr<Interface>> get_service(const std::string& service_name) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_services.find(service_name);
        if (it == m_services.end()) {
            return Result<std::shared_ptr<Interface>>::failure(
                StatusCode::NotFound, "Service '" + service_name + "' not found in registry"
            );
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

    // --- Dynamic Global Calling / RPC ---
    Result<void> register_method(
        const std::string& method_name,
        const std::string& description,
        const std::string& provider_module,
        DynamicMethodFn fn,
        const SecurityPolicy* policy = nullptr
    );

    Result<void> unregister_method(const std::string& method_name);

    Result<Value> invoke(
        const std::string& method_name,
        const std::vector<Value>& args = {},
        const std::string& caller_module = "system",
        const SecurityPolicy* caller_policy = nullptr
    );

    // Bulk cleanup for a module on hot-unplug
    size_t unregister_provider(const std::string& provider_module);

    size_t service_count() const;
    size_t method_count() const;
    void dump_report() const;

private:
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, ServiceDescriptor> m_services;
    std::unordered_map<std::string, MethodDescriptor> m_methods;
};

} // namespace dvargosh
