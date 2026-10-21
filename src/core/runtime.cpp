#include "dvargosh/runtime.hpp"
#include "dvargosh/di_container.hpp"
#include "dvargosh/registry.hpp"

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

ModuleContext* Runtime::get_context(const std::string& module_name) {
    std::lock_guard<std::mutex> lock(mutex());
    auto it = contexts().find(module_name);
    return (it != contexts().end()) ? it->second : nullptr;
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
