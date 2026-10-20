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

class ModuleLoader {
public:
    explicit ModuleLoader(std::shared_ptr<DIContainer> di, ModuleLoaderConfig config = {});
    ~ModuleLoader();

    // Load from dynamic library (.dylib / .so)
    Result<void> load_from_file(
        const std::string& filepath,
        const std::string& signature_override = "",
        const SecurityPolicy* custom_policy = nullptr
    );

    // Load module by name with signature: searches configured search paths
    // Usage: loader.load("math", "signature_hex")
    Result<void> load(
        const std::string& module_name,
        const std::string& signature,
        const SecurityPolicy* custom_policy = nullptr
    );

    // Search paths management
    void add_search_path(const std::string& path);
    const std::vector<std::string>& search_paths() const noexcept { return m_search_paths; }
    Result<std::string> find_module_file(const std::string& module_name) const;

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
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, LoadedModule> m_loaded_modules;
};

} // namespace dvargosh
