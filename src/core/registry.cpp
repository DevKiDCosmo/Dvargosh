#include "dvargosh/registry.hpp"
#include "dvargosh/domain.hpp"
#include "dvargosh/execution_context.hpp"
#include <iostream>
#include <algorithm>

namespace dvargosh {

namespace {

// Levenshtein distance for "Did you mean?" suggestions
size_t levenshtein_distance(const std::string& s1, const std::string& s2) {
    const size_t m = s1.size();
    const size_t n = s2.size();
    std::vector<std::vector<size_t>> dp(m + 1, std::vector<size_t>(n + 1));

    for (size_t i = 0; i <= m; ++i) dp[i][0] = i;
    for (size_t j = 0; j <= n; ++j) dp[0][j] = j;

    for (size_t i = 1; i <= m; ++i) {
        for (size_t j = 1; j <= n; ++j) {
            if (s1[i - 1] == s2[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = 1 + std::min({dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]});
            }
        }
    }
    return dp[m][n];
}

} // anonymous namespace

Registry::Registry() = default;
Registry::~Registry() = default;

bool Registry::check_domain_access(const std::string& from_domain, const std::string& to_domain) const {
    if (!m_domain_mgr || from_domain.empty() || to_domain.empty() || from_domain == "system") return true;
    return m_domain_mgr->check_cross_domain_access(from_domain, to_domain);
}

std::string Registry::find_similar_method(const std::string& target) const {
    std::string best_match;
    size_t min_dist = 4; // Max threshold for suggestion

    for (const auto& [name, _] : m_methods) {
        size_t dist = levenshtein_distance(target, name);
        if (dist < min_dist) {
            min_dist = dist;
            best_match = name;
        }
    }
    return best_match;
}

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

std::string Registry::get_service_domain(const std::string& service_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_services.find(service_name);
    if (it != m_services.end()) return it->second.domain;
    return "";
}

Result<void> Registry::register_method(
    const std::string& method_name,
    const std::string& description,
    const std::string& provider_module,
    const std::string& domain,
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

    std::string scoped_domain = domain;
    if (scoped_domain == "*") {
        scoped_domain = provider_module + ".*";
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_methods.find(method_name) != m_methods.end()) {
        return Result<void>::failure(StatusCode::AlreadyExists, "Method '" + method_name + "' already registered");
    }

    MethodDescriptor desc;
    desc.name = method_name;
    desc.description = description;
    desc.provider_module = provider_module;
    desc.domain = scoped_domain.empty() ? "default" : scoped_domain;
    desc.fn = std::move(fn);

    m_methods[method_name] = std::move(desc);
    return Result<void>::success();
}

Result<void> Registry::unregister_method(const std::string& method_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_methods.find(method_name);
    if (it == m_methods.end()) {
        auto alias_it = m_aliases.find(method_name);
        if (alias_it != m_aliases.end()) {
            m_aliases.erase(alias_it);
            return Result<void>::success();
        }
        return Result<void>::failure(StatusCode::NotFound, "Method '" + method_name + "' not found");
    }
    m_methods.erase(it);

    for (auto ait = m_aliases.begin(); ait != m_aliases.end();) {
        if (ait->second == method_name) {
            ait = m_aliases.erase(ait);
        } else {
            ++ait;
        }
    }
    return Result<void>::success();
}

bool Registry::has_method(const std::string& method_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_methods.find(method_name) != m_methods.end()) return true;
    auto it = m_aliases.find(method_name);
    return (it != m_aliases.end() && m_methods.find(it->second) != m_methods.end());
}

std::string Registry::get_method_domain(const std::string& method_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string canonical = method_name;
    auto ait = m_aliases.find(method_name);
    if (ait != m_aliases.end()) {
        canonical = ait->second;
    }
    auto it = m_methods.find(canonical);
    return it != m_methods.end() ? it->second.domain : "";
}

Result<void> Registry::register_alias(const std::string& alias, const std::string& target_method) {
    if (alias.empty() || target_method.empty()) {
        return Result<void>::failure(StatusCode::InvalidArg, "Alias and target method cannot be empty");
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_aliases[alias] = target_method;
    return Result<void>::success();
}

bool Registry::has_alias(const std::string& alias) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_aliases.find(alias) != m_aliases.end();
}

std::string Registry::resolve_method_name(const std::string& name_or_alias) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_aliases.find(name_or_alias);
    if (it != m_aliases.end()) {
        return it->second;
    }
    return name_or_alias;
}

Result<Value> Registry::invoke(
    const std::string& method_name,
    const std::vector<Value>& args,
    const std::string& caller_module,
    const std::string& caller_domain,
    const SecurityPolicy* caller_policy
) {
    // 1. Resolve alias override to canonical method name
    std::string canonical_method = resolve_method_name(method_name);

    // 2. Automatic domain resolution & anti-spoofing verification
    std::string effective_caller_domain = caller_domain;
    std::string effective_caller_module = caller_module;

    if (ExecutionContext::frame_depth() > 0) {
        effective_caller_domain = ExecutionContext::current_domain();
        effective_caller_module = ExecutionContext::current_module();
    } else {
        if (effective_caller_domain.empty()) {
            effective_caller_domain = "system";
            effective_caller_module = "system";
        }
    }

    if (caller_policy) {
        auto perm_res = caller_policy->check(Permission::DynamicInvoke, effective_caller_module);
        if (!perm_res.is_ok()) {
            return Result<Value>::failure(perm_res.status(), perm_res.error_message());
        }
    }

    DynamicMethodFn fn;
    std::string target_domain;
    std::string target_module;
    bool found = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_methods.find(canonical_method);
        if (it != m_methods.end()) {
            fn = it->second.fn;
            target_domain = it->second.domain;
            target_module = it->second.provider_module;
            found = true;
        }
    }

    // Handle Unresolved Method
    if (!found) {
        UnresolvedHandler handler = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            handler = m_unresolved_handler;
        }

        if (handler) {
            return handler(method_name, args, effective_caller_domain);
        }

        std::string suggestion;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            suggestion = find_similar_method(canonical_method);
        }

        std::string err = "Method '" + method_name + "' not found in registry.";
        if (!suggestion.empty()) {
            err += " Did you mean '" + suggestion + "'?";
        }
        return Result<Value>::failure(StatusCode::SymbolNotFound, err);
    }

    // Check Cross-Domain Access Permission
    if (m_domain_mgr && !effective_caller_domain.empty() && effective_caller_domain != "system" && !target_domain.empty()) {
        if (!m_domain_mgr->check_cross_domain_access(effective_caller_domain, target_domain)) {
            return Result<Value>::failure(
                StatusCode::PermissionDenied,
                "Cross-Domain Violation: Domain '" + effective_caller_domain +
                "' is not permitted to invoke method '" + method_name +
                "' in Domain '" + target_domain + "'"
            );
        }
    }

    try {
        ScopedCallFrame frame(target_module, target_domain, effective_caller_module, effective_caller_domain);
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

    for (auto it = m_aliases.begin(); it != m_aliases.end();) {
        if (m_methods.find(it->second) == m_methods.end()) {
            it = m_aliases.erase(it);
        } else {
            ++it;
        }
    }

    return count;
}

std::vector<std::string> Registry::list_methods() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> names;
    names.reserve(m_methods.size());
    for (const auto& [name, _] : m_methods) {
        names.push_back(name);
    }
    return names;
}

std::vector<std::string> Registry::list_services() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> names;
    names.reserve(m_services.size());
    for (const auto& [name, _] : m_services) {
        names.push_back(name);
    }
    return names;
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
    std::cout << "\n┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "│                 DVARGOSH SERVICE REGISTRY                   │\n";
    std::cout << "├──────────────────┬─────────┬──────────────┬─────────────────┤\n";
    std::cout << "│ Service Name     │ Version │ Domain       │ Provider        │\n";
    std::cout << "├──────────────────┼─────────┼──────────────┼─────────────────┤\n";
    for (const auto& [name, s] : m_services) {
        std::string v = "v" + s.version.to_string();
        std::cout << "│ " << name;
        for (size_t i = name.length(); i < 16; ++i) std::cout << " ";
        std::cout << " │ " << v;
        for (size_t i = v.length(); i < 7; ++i) std::cout << " ";
        std::cout << " │ " << s.domain;
        for (size_t i = s.domain.length(); i < 12; ++i) std::cout << " ";
        std::cout << " │ " << s.provider_module;
        for (size_t i = s.provider_module.length(); i < 15; ++i) std::cout << " ";
        std::cout << " │\n";
    }
    std::cout << "├──────────────────┴─────────┴──────────────┴─────────────────┤\n";
    std::cout << "│ Dynamic Methods (" << m_methods.size() << " registered):" << (m_methods.size() < 10 ? "                           │\n" : "                          │\n");
    for (const auto& [name, m] : m_methods) {
        std::cout << "│  * " << name << " [" << m.domain << "]: " << m.description << "\n";
    }
    std::cout << "└─────────────────────────────────────────────────────────────┘\n\n";
}

} // namespace dvargosh
