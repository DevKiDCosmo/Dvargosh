#include "dvargosh/registry.hpp"
#include <iostream>

namespace dvargosh {

Registry::Registry() = default;
Registry::~Registry() = default;

Result<void> Registry::unregister_service(const std::string& service_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_services.find(service_name);
    if (it == m_services.end()) {
        return Result<void>::failure(StatusCode::NotFound, "Service '" + service_name + "' not found");
    }
    m_services.erase(it);
    return Result<void>::success();
}

bool Registry::has_service(const std::string& service_name, Version min_version) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_services.find(service_name);
    if (it == m_services.end()) return false;
    return it->second.version >= min_version;
}

Result<void> Registry::register_method(
    const std::string& method_name,
    const std::string& description,
    const std::string& provider_module,
    DynamicMethodFn fn,
    const SecurityPolicy* policy
) {
    if (policy) {
        auto perm_res = policy->check(Permission::ServiceRegister, provider_module);
        if (!perm_res.is_ok()) return perm_res;
    }

    if (!fn) {
        return Result<void>::failure(StatusCode::NullPointer, "Method function cannot be null");
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_methods.find(method_name) != m_methods.end()) {
        return Result<void>::failure(StatusCode::AlreadyExists, "Method '" + method_name + "' already registered");
    }

    MethodDescriptor desc;
    desc.name = method_name;
    desc.description = description;
    desc.provider_module = provider_module;
    desc.fn = std::move(fn);

    m_methods[method_name] = std::move(desc);
    return Result<void>::success();
}

Result<void> Registry::unregister_method(const std::string& method_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_methods.find(method_name);
    if (it == m_methods.end()) {
        return Result<void>::failure(StatusCode::NotFound, "Method '" + method_name + "' not found");
    }
    m_methods.erase(it);
    return Result<void>::success();
}

Result<Value> Registry::invoke(
    const std::string& method_name,
    const std::vector<Value>& args,
    const std::string& caller_module,
    const SecurityPolicy* caller_policy
) {
    if (caller_policy) {
        auto perm_res = caller_policy->check(Permission::DynamicInvoke, caller_module);
        if (!perm_res.is_ok()) {
            return Result<Value>::failure(perm_res.status(), perm_res.error_message());
        }
    }

    DynamicMethodFn fn;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_methods.find(method_name);
        if (it == m_methods.end()) {
            return Result<Value>::failure(StatusCode::NotFound, "Method '" + method_name + "' not found in registry");
        }
        fn = it->second.fn;
    }

    try {
        return fn(args);
    } catch (const DvargoshException& e) {
        return Result<Value>::failure(e.code(), e.what());
    } catch (const std::exception& e) {
        return Result<Value>::failure(StatusCode::InvocationFailed, std::string("Method invocation error: ") + e.what());
    } catch (...) {
        return Result<Value>::failure(StatusCode::InvocationFailed, "Unknown error during method invocation");
    }
}

size_t Registry::unregister_provider(const std::string& provider_module) {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count = 0;

    for (auto it = m_services.begin(); it != m_services.end();) {
        if (it->second.provider_module == provider_module) {
            it = m_services.erase(it);
            count++;
        } else {
            ++it;
        }
    }

    for (auto it = m_methods.begin(); it != m_methods.end();) {
        if (it->second.provider_module == provider_module) {
            it = m_methods.erase(it);
            count++;
        } else {
            ++it;
        }
    }

    return count;
}

size_t Registry::service_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_services.size();
}

size_t Registry::method_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_methods.size();
}

void Registry::dump_report() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << "--- [Global Service Registry] ---\n";
    std::cout << "  Services (" << m_services.size() << "):\n";
    for (const auto& [name, s] : m_services) {
        std::cout << "    * '" << name << "' v" << s.version.to_string()
                  << " (Provider: " << s.provider_module << ")\n";
    }
    std::cout << "  Dynamic Methods (" << m_methods.size() << "):\n";
    for (const auto& [name, m] : m_methods) {
        std::cout << "    * '" << name << "': " << m.description
                  << " (Provider: " << m.provider_module << ")\n";
    }
    std::cout << "-----------------------------------\n";
}

} // namespace dvargosh
