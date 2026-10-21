#pragma once

#include "types.hpp"
#include <string>
#include <unordered_map>
#include <mutex>

namespace dvargosh {

class ModuleContext;
class Registry;
class DIContainer;

/**
 * @brief Global Runtime Context and Service Locator for loaded modules.
 *
 * Allows in-module service functions to access their active ModuleContext or
 * the central Service Registry without constructing detached DIContainers.
 */
class Runtime {
public:
    static void register_module_context(const std::string& module_name, ModuleContext* ctx);
    static void unregister_module_context(const std::string& module_name);
    static ModuleContext* get_context(const std::string& module_name);

    static void set_active_registry(Registry* reg);
    static Registry* active_registry();

    static void set_active_container(DIContainer* di);
    static DIContainer* active_container();

private:
    static std::mutex& mutex();
    static std::unordered_map<std::string, ModuleContext*>& contexts();
    static Registry*& registry_instance();
    static DIContainer*& container_instance();
};

} // namespace dvargosh
