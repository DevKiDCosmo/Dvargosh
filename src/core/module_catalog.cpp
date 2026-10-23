#include "dvargosh/module_catalog.hpp"
#include "dvargosh/module_loader.hpp"
#include "dvargosh/crypto.hpp"
#include <iostream>

namespace dvargosh {

void ModuleCatalog::register_module(ModuleDescriptor desc) {
    m_descriptors[desc.name] = std::move(desc);
}

const ModuleDescriptor* ModuleCatalog::find(const std::string& name) const {
    auto it = m_descriptors.find(name);
    return (it != m_descriptors.end()) ? &it->second : nullptr;
}

std::vector<ModuleDescriptor> ModuleCatalog::list_all() const {
    std::vector<ModuleDescriptor> res;
    res.reserve(m_descriptors.size());
    for (const auto& [_, desc] : m_descriptors) {
        res.push_back(desc);
    }
    return res;
}

std::vector<ModuleDescriptor> ModuleCatalog::list_by_domain(const std::string& domain) const {
    std::vector<ModuleDescriptor> res;
    for (const auto& [_, desc] : m_descriptors) {
        if (desc.domain == domain) {
            res.push_back(desc);
        }
    }
    return res;
}

bool ModuleCatalog::exist_domain(const std::string_view& module) const {
    for (const auto& [_, desc] : m_descriptors) {
        if (desc.name == module || desc.domain == module) {
            return true;
        }
    }
    return false;
}

Result<size_t> ModuleCatalog::load_all(
    ModuleLoader& loader,
    const std::string& modules_dir,
    const std::string& signing_key
) {
#if defined(__APPLE__)
    std::string ext = ".dylib";
#else
    std::string ext = ".so";
#endif

    size_t count = 0;
    for (const auto& [name, desc] : m_descriptors) {
        if (loader.is_loaded(name)) continue;

        std::string filename = desc.filename;
        if (filename.find(ext) == std::string::npos) {
            filename += ext;
        }
        std::string full_path = modules_dir + "/" + filename;

        std::string sig = "";
        if (!signing_key.empty()) {
            auto sig_res = Crypto::sign_file(signing_key, full_path);
            if (sig_res.is_ok()) {
                sig = sig_res.value();
            }
        }

        SecurityPolicy policy(desc.permissions, desc.secured_memory_size * 2);
        auto load_res = loader.load_from_file(full_path, sig, &policy);
        if (!load_res.is_ok()) {
            return Result<size_t>::failure(load_res.status(), "Failed to load '" + name + "': " + load_res.error_message());
        }
        count++;
    }

    return Result<size_t>::success(count);
}

Result<size_t> ModuleCatalog::load_domain(
    const std::string& domain,
    ModuleLoader& loader,
    const std::string& modules_dir,
    const std::string& signing_key
) {
#if defined(__APPLE__)
    std::string ext = ".dylib";
#else
    std::string ext = ".so";
#endif

    size_t count = 0;
    for (const auto& [name, desc] : m_descriptors) {
        if (desc.domain != domain) continue;
        if (loader.is_loaded(name)) continue;

        std::string filename = desc.filename;
        if (filename.find(ext) == std::string::npos) {
            filename += ext;
        }
        std::string full_path = modules_dir + "/" + filename;

        std::string sig = "";
        if (!signing_key.empty()) {
            auto sig_res = Crypto::sign_file(signing_key, full_path);
            if (sig_res.is_ok()) {
                sig = sig_res.value();
            }
        }

        SecurityPolicy policy(desc.permissions, desc.secured_memory_size * 2);
        auto load_res = loader.load_from_file(full_path, sig, &policy);
        if (!load_res.is_ok()) {
            return Result<size_t>::failure(load_res.status(), "Failed to load '" + name + "': " + load_res.error_message());
        }
        count++;
    }

    return Result<size_t>::success(count);
}

Result<size_t> ModuleCatalog::unload_domain(const std::string& domain, ModuleLoader& loader) {
    size_t count = 0;
    for (const auto& [name, desc] : m_descriptors) {
        if (desc.domain == domain && loader.is_loaded(name)) {
            auto res = loader.unload_module(name);
            if (res.is_ok()) count++;
        }
    }
    return Result<size_t>::success(count);
}

Result<size_t> ModuleCatalog::unload_all(ModuleLoader& loader) {
    size_t count = 0;
    for (const auto& [name, _] : m_descriptors) {
        if (loader.is_loaded(name)) {
            auto res = loader.unload_module(name);
            if (res.is_ok()) count++;
        }
    }
    return Result<size_t>::success(count);
}

void ModuleCatalog::dump_report() const {
    std::cout << "\n┌────────────────────────────────────────────────────────────────────────┐\n";
    std::cout << "│                    DVARGOSH MODULE CATALOG MANIFEST                    │\n";
    std::cout << "├──────────────┬──────────────┬─────────┬──────────────┬─────────────────┤\n";
    std::cout << "│ Module Name  │ Domain       │ Version │ Binary File  │ Secured Quota   │\n";
    std::cout << "├──────────────┼──────────────┼─────────┼──────────────┼─────────────────┤\n";
    for (const auto& [name, desc] : m_descriptors) {
        std::string v = "v" + desc.version.to_string();
        std::string quota = std::to_string(desc.secured_memory_size / 1024) + " KB";
        std::cout << "│ " << name;
        for (size_t i = name.length(); i < 12; ++i) std::cout << " ";
        std::cout << " │ " << desc.domain;
        for (size_t i = desc.domain.length(); i < 12; ++i) std::cout << " ";
        std::cout << " │ " << v;
        for (size_t i = v.length(); i < 7; ++i) std::cout << " ";
        std::cout << " │ " << desc.filename;
        for (size_t i = desc.filename.length(); i < 12; ++i) std::cout << " ";
        std::cout << " │ " << quota;
        for (size_t i = quota.length(); i < 15; ++i) std::cout << " ";
        std::cout << " │\n";
    }
    std::cout << "└──────────────┴──────────────┴─────────┴──────────────┴─────────────────┘\n\n";
}

// Standalone registration function to register all standard modules
void register_standard_modules(ModuleCatalog& catalog) {
    // 1. Logger Module (Core Domain)
    ModuleDescriptor logger_mod;
    logger_mod.name = "logger";
    logger_mod.filename = "libmod_logger";
    logger_mod.domain = "core";
    logger_mod.version = Version{1, 0, 0};
    logger_mod.description = "Plug-and-play Console Logging Service";
    logger_mod.permissions = PermissionSet({
        Permission::ServiceRegister,
        Permission::DynamicInvoke,
        Permission::EventPublish
    });
    logger_mod.secured_memory_size = 1 * 1024 * 1024;
    catalog.register_module(logger_mod);

    // 2. Math Module (Compute Domain)
    ModuleDescriptor math_mod;
    math_mod.name = "math";
    math_mod.filename = "libmod_math";
    math_mod.domain = "compute";
    math_mod.version = Version{1, 2, 0};
    math_mod.description = "Mathematical Computations with Arena Memory and Event Emission";
    math_mod.permissions = PermissionSet({
        Permission::ServiceRegister,
        Permission::DynamicInvoke,
        Permission::EventPublish
    });
    math_mod.secured_memory_size = 2 * 1024 * 1024;
    catalog.register_module(math_mod);

    // 3. Worker Module (Worker Domain)
    ModuleDescriptor worker_mod;
    worker_mod.name = "worker";
    worker_mod.filename = "libmod_worker";
    worker_mod.domain = "worker";
    worker_mod.version = Version{1, 0, 0};
    worker_mod.description = "Isolated Secure Worker Module with Containerized Memory and Event Hooks";
    worker_mod.permissions = PermissionSet({
        Permission::SecuredMemory,
        Permission::ServiceRegister,
        Permission::DynamicInvoke,
        Permission::EventSubscribe,
        Permission::EventPublish
    });
    worker_mod.secured_memory_size = 4 * 1024 * 1024;
    catalog.register_module(worker_mod);

    // 4. Monitoring Module (Telemetry Domain)
    ModuleDescriptor monitor_mod;
    monitor_mod.name = "monitor";
    monitor_mod.filename = "libmod_monitor";
    monitor_mod.domain = "telemetry";
    monitor_mod.version = Version{1, 0, 0};
    monitor_mod.description = "Live Telemetry, System Metrics, and Health Monitoring Module";
    monitor_mod.permissions = PermissionSet({
        Permission::SecuredMemory,
        Permission::ServiceRegister,
        Permission::DynamicInvoke,
        Permission::EventSubscribe,
        Permission::EventPublish,
        Permission::SystemInfo
    });
    monitor_mod.secured_memory_size = 2 * 1024 * 1024;
    catalog.register_module(monitor_mod);

    // 5. Demo Package (Subsystems: main, vault, worker, *)
    ModuleDescriptor demo_mod;
    demo_mod.name = "demo_pkg";
    demo_mod.filename = "libmod_demo_pkg";
    demo_mod.domain = "*";
    demo_mod.version = Version{1, 0, 0};
    demo_mod.description = "Full Demo Package with Subsystems (Domains) and Inter-Subsystem Access Control";
    demo_mod.permissions = PermissionSet::all();
    demo_mod.secured_memory_size = 4 * 1024 * 1024;
    catalog.register_module(demo_mod);
}

} // namespace dvargosh
