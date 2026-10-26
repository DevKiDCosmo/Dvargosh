#pragma once

#include "types.hpp"
#include "module.hpp"
#include "di_container.hpp"
#include "crypto.hpp"
#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace dvargosh {

struct ModuleLoaderConfig {
    bool enforce_signatures = false;
    std::string secret_signing_key = "";
    SecurityPolicy default_policy = SecurityPolicy::standard();
    size_t secured_memory_size = 4 * 1024 * 1024;
};

struct LoadedModule {
    std::string name;
    std::string domain = "default";
    std::string filepath;
    Version version;
    void* lib_handle = nullptr;
    IModule* instance = nullptr;
    ModuleDestroyFn destroy_fn = nullptr;
    std::unique_ptr<ModuleContext> context;
    bool is_dynamic = true;
};

struct DiscoveredModuleInfo {
    std::string name;
    std::string filename;
    std::string full_path;
    std::string build_id;
    std::string abi_version;
    std::string domain;
    std::vector<std::string> supported_domains;
    bool is_valid = false;
};

/**
 * @brief Parses a signatures.json file (filename → hex HMAC) into the sig map.
 * Exposed for fuzzing/tests: the file is local disk input parsed by hand-rolled
 * string scanning, i.e. an untrusted-input surface.
 */
void load_signatures_from_file(const std::string& path, std::unordered_map<std::string, std::string>& sigs);

class ModuleLoader {
public:
    explicit ModuleLoader(std::shared_ptr<DIContainer> di, ModuleLoaderConfig config = {});
    ~ModuleLoader();

    // Universal Recognition & Auto-Discovery
    // Scans all search paths for libraries exporting Dvargosh magic header, name, and build_id
    std::vector<DiscoveredModuleInfo> discover_all_modules();
    const DiscoveredModuleInfo* get_discovered_info(const std::string& name_or_filename) const;

    // Load from dynamic library (.dylib / .so)
    Result<void> load_from_file(
        const std::string& filepath,
        const std::string& signature_override = "",
        const SecurityPolicy* custom_policy = nullptr
    );

    // Load module by name OR filename with signature: searches configured search paths
    // Usage: loader.load("math", "signature_hex") OR loader.load("libmod_math.dylib", "signature_hex")
    Result<void> load(
        const std::string& name_or_filename,
        const std::string& signature = "",
        const SecurityPolicy* custom_policy = nullptr
    );

    // Search paths management
    void add_search_path(const std::string& path);
    const std::vector<std::string>& search_paths() const noexcept { return m_search_paths; }
    Result<std::string> find_module_file(const std::string& name_or_filename) const;

    /**
     * @brief Automatically discovers and loads all modules found in configured search paths.
     * @param secret_key Optional HMAC-SHA256 signing key (uses config signing key if empty).
     * @return Number of modules successfully loaded.
     */
    Result<size_t> auto_load_all(const std::string& secret_key = "");

    /**
     * @brief Automatically loads modules matching a pattern (e.g. "crypto_*", "*demo*").
     * @param pattern Glob or substring filter pattern.
     * @param secret_key Optional HMAC-SHA256 signing key.
     * @return Number of matching modules successfully loaded.
     */
    Result<size_t> auto_load_matching(const std::string& pattern, const std::string& secret_key = "");

    /**
     * @brief Automatically discovers and loads the module providing a specific domain.
     * @param domain_name Target domain identifier (e.g. "accelerator:hash", "demo_pkg:vault").
     * @param secret_key Optional HMAC-SHA256 signing key.
     * @return Success if the provider module was resolved and loaded, or error if not found.
     */
    Result<void> auto_load_domain(const std::string& domain_name, const std::string& secret_key = "");

    // Register & load a static / in-memory module
    Result<void> load_static_module(
        std::unique_ptr<IModule> mod,
        const SecurityPolicy* custom_policy = nullptr
    );

    // Unload a module cleanly (hot-unplug)
    Result<void> unload_module(const std::string& module_name);

    // Reload a module (hot-reload)
    Result<void> reload_module(const std::string& module_name, const std::string& signature = "");

    // Query status
    bool is_loaded(const std::string& module_name) const;
    std::vector<std::string> loaded_modules() const;
    const LoadedModule* get_module_info(const std::string& module_name) const;

    void set_signing_key(const std::string& key) { m_config.secret_signing_key = key; }
    void set_enforce_signatures(bool enforce) { m_config.enforce_signatures = enforce; }
    const ModuleLoaderConfig& config() const noexcept { return m_config; }

    void dump_report() const;

private:
    std::shared_ptr<DIContainer> m_di;
    ModuleLoaderConfig m_config;
    std::vector<std::string> m_search_paths;
    std::unordered_map<std::string, DiscoveredModuleInfo> m_discovered_by_name;
    std::unordered_map<std::string, DiscoveredModuleInfo> m_discovered_by_filename;
    std::unordered_map<std::string, std::string> m_known_signatures;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, LoadedModule> m_loaded_modules;
};

} // namespace dvargosh
