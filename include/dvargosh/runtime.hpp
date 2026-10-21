#pragma once

#include "types.hpp"
#include <string>
#include <unordered_map>
#include <mutex>

namespace dvargosh {

class ModuleContext;
class SubContext;
class Registry;
class DIContainer;

/**
 * @brief Global Runtime Context and Service Locator for loaded modules.
 *
 * Allows in-module service functions to access their active ModuleContext or
 * the central Service Registry without constructing detached DIContainers.
 * Enforces cryptographic anti-hijacking to prevent foreign modules from stealing contexts.
 */
class Runtime {
public:
    static void register_module_context(const std::string& module_name, ModuleContext* ctx);
    static void unregister_module_context(const std::string& module_name);

    /**
     * @brief Retrieves the active injected ModuleContext pointer for the calling module.
     * Automatically and securely resolves the calling module from the active execution frame
     * or binary text segment (dladdr). Zero-parameter, zero possibility of spoofing.
     */
    static ModuleContext* get_context();

    /**
     * @brief Retrieves the active injected ModuleContext pointer for a module.
     * Enforces anti-hijacking: if the calling module does not match module_name,
     * access is strictly denied (returns nullptr).
     */
    static ModuleContext* get_context(const std::string& module_name);

    /**
     * @brief Automatically resolves the active ModuleContext of the calling module
     * from the thread-local ExecutionContext. Zero-parameter, anti-tamper protected.
     */
    static ModuleContext* current_context();

    /**
     * @brief Automatically resolves the active SubContext of the calling module and domain
     * from the thread-local ExecutionContext. Zero-parameter, anti-tamper protected.
     */
    static SubContext* current_subcontext();

    /**
     * @brief Retrieves a SubContext by module name and domain name, enforcing caller checks.
     */
    static SubContext* get_subcontext(const std::string& module_name, const std::string& domain_name);

    /** @brief Registers a SubContext in the global tracking registry by its HMAC-SHA256 hash. */
    static void register_subcontext(const std::string& hash, SubContext* ctx);

    /** @brief Unregisters a SubContext from the global tracking registry by its hash. */
    static void unregister_subcontext(const std::string& hash);

    /** @brief Retrieves a SubContext directly by its HMAC-SHA256 tracking hash. */
    static SubContext* get_subcontext_by_hash(const std::string& hash);

    static void set_active_registry(Registry* reg);
    static Registry* active_registry();

    static void set_active_container(DIContainer* di);
    static DIContainer* active_container();

private:
    static std::mutex& mutex();
    static std::unordered_map<std::string, ModuleContext*>& contexts();
    static std::unordered_map<std::string, SubContext*>& subcontexts_by_hash();
    static Registry*& registry_instance();
    static DIContainer*& container_instance();
};

} // namespace dvargosh
