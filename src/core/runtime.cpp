#include "dvargosh/runtime.hpp"
#include "dvargosh/di_container.hpp"
#include "dvargosh/registry.hpp"
#include "dvargosh/execution_context.hpp"
#include "dvargosh/logger.hpp"
#include <dlfcn.h>
#include <algorithm>

namespace dvargosh {

std::mutex& Runtime::mutex() {
    static std::mutex s_mutex;
    return s_mutex;
}

std::unordered_map<std::string, ModuleContext*>& Runtime::contexts() {
    static std::unordered_map<std::string, ModuleContext*> s_contexts;
    return s_contexts;
}

Registry*& Runtime::registry_instance() {
    static Registry* s_reg = nullptr;
    return s_reg;
}

DIContainer*& Runtime::container_instance() {
    static DIContainer* s_di = nullptr;
    return s_di;
}

void Runtime::register_module_context(const std::string& module_name, ModuleContext* ctx) {
    std::lock_guard<std::mutex> lock(mutex());
    contexts()[module_name] = ctx;
}

void Runtime::unregister_module_context(const std::string& module_name) {
    std::lock_guard<std::mutex> lock(mutex());
    contexts().erase(module_name);
}

bool Runtime::has_module(const std::string& module_name) {
    std::lock_guard<std::mutex> lock(mutex());
    return contexts().find(module_name) != contexts().end();
}

ModuleContext* Runtime::get_context() {
    // 1. Resolve from active execution frame if available
    if (ExecutionContext::frame_depth() > 0) {
        std::string mod = ExecutionContext::current_module();
        if (!mod.empty() && mod != "untrusted" && mod != "system") {
            std::lock_guard<std::mutex> lock(mutex());
            auto it = contexts().find(mod);
            if (it != contexts().end()) return it->second;
        }
    }

    // 2. Resolve caller binary dynamically using dladdr on caller return address
    void* caller_addr = __builtin_return_address(0);
    Dl_info info;
    if (dladdr(caller_addr, &info) && info.dli_fname) {
        std::string fname = info.dli_fname;
        std::lock_guard<std::mutex> lock(mutex());
        for (const auto& [name, ctx] : contexts()) {
            if (fname.find(name) != std::string::npos) {
                return ctx;
            }
        }
        // Normalize name check (e.g. hello_world vs helloWorld)
        for (const auto& [name, ctx] : contexts()) {
            std::string norm_name = name;
            norm_name.erase(std::remove(norm_name.begin(), norm_name.end(), '_'), norm_name.end());
            std::string f_lower = fname;
            std::transform(f_lower.begin(), f_lower.end(), f_lower.begin(), ::tolower);
            std::transform(norm_name.begin(), norm_name.end(), norm_name.begin(), ::tolower);
            if (f_lower.find(norm_name) != std::string::npos) {
                return ctx;
            }
        }
    }

    // 3. Fallback: if only one module context is loaded in host, return it
    std::lock_guard<std::mutex> lock(mutex());
    if (contexts().size() == 1) {
        return contexts().begin()->second;
    }

    return nullptr;
}

ModuleContext* Runtime::get_context(const std::string& module_name) {
    if (module_name.empty()) {
        return get_context();
    }
    // Anti-hijacking check: caller cannot fetch foreign module context
    if (ExecutionContext::frame_depth() > 0) {
        std::string caller = ExecutionContext::current_module();
        if (!caller.empty() && caller != "untrusted" && caller != "system" && caller != module_name) {
            log_error("SECURITY ALERT: Module '", caller,
                      "' attempted unauthorized access to context of foreign module '", module_name, "'. Access denied.");
            return nullptr;
        }
    }
    std::lock_guard<std::mutex> lock(mutex());
    auto it = contexts().find(module_name);
    return (it != contexts().end()) ? it->second : nullptr;
}

ModuleContext* Runtime::current_context() {
    if (ExecutionContext::frame_depth() == 0) {
        return nullptr;
    }
    auto val = ExecutionContext::validate_stack_integrity();
    if (!val.is_ok()) {
        log_error("Runtime::current_context: Stack tampering detected!");
        return nullptr;
    }
    std::string mod = ExecutionContext::current_module();
    if (mod.empty() || mod == "untrusted") return nullptr;
    return get_context(mod);
}

void Runtime::set_active_registry(Registry* reg) {
    std::lock_guard<std::mutex> lock(mutex());
    registry_instance() = reg;
}

Registry* Runtime::active_registry() {
    std::lock_guard<std::mutex> lock(mutex());
    return registry_instance();
}

void Runtime::set_active_container(DIContainer* di) {
    std::lock_guard<std::mutex> lock(mutex());
    container_instance() = di;
}

DIContainer* Runtime::active_container() {
    std::lock_guard<std::mutex> lock(mutex());
    return container_instance();
}

} // namespace dvargosh
