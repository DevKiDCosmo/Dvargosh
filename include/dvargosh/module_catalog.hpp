#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>

namespace dvargosh {

class ModuleLoader;

struct ModuleDescriptor {
    std::string name;
    std::string filename; // Base filename without directory (e.g. "libmod_logger")
    std::string domain = "default";
    Version version = Version{1, 0, 0};
    std::string description;
    PermissionSet permissions = PermissionSet::standard_module();
    size_t secured_memory_size = 4 * 1024 * 1024;
};

class ModuleCatalog {
public:
    ModuleCatalog() = default;
    ~ModuleCatalog() = default;

    // Declarative registration
    void register_module(ModuleDescriptor desc);

    const ModuleDescriptor* find(const std::string& name) const;
    std::vector<ModuleDescriptor> list_all() const;
    std::vector<ModuleDescriptor> list_by_domain(const std::string& domain) const;

    // Batch operations - plug and play easily
    Result<size_t> load_all(
        ModuleLoader& loader,
        const std::string& modules_dir,
        const std::string& signing_key = ""
    );

    Result<size_t> load_domain(
        const std::string& domain,
        ModuleLoader& loader,
        const std::string& modules_dir,
        const std::string& signing_key = ""
    );

    Result<size_t> unload_domain(const std::string& domain, ModuleLoader& loader);
    Result<size_t> unload_all(ModuleLoader& loader);

    void dump_report() const;

private:
    std::unordered_map<std::string, ModuleDescriptor> m_descriptors;
};

// Declarative registration function in standalone file to register standard modules easily
void register_standard_modules(ModuleCatalog& catalog);

} // namespace dvargosh
