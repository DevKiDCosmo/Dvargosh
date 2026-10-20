#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include "di_container.hpp"
#include <string>

namespace dvargosh {

#define DVARGOSH_ABI_VERSION_STR "dvargosh-abi-v1"

struct ModuleManifest {
    std::string name;
    Version version;
    std::string description;
    std::string author;
    std::string domain = "default"; // Domain grouping
    PermissionSet requested_permissions = PermissionSet::standard_module();
    std::string signature; // HMAC-SHA256 signature for verification
};

class IModule {
public:
    virtual ~IModule() = default;

    virtual const ModuleManifest& manifest() const = 0;

    // Lifecycle hooks
    virtual Result<void> on_load(ModuleContext& ctx) = 0;
    virtual Result<void> on_start(ModuleContext& ctx) = 0;
    virtual Result<void> on_stop(ModuleContext& ctx) = 0;
    virtual Result<void> on_unload(ModuleContext& ctx) = 0;
};

// Function pointer signatures for dynamic library symbol export
using ModuleCreateFn = IModule* (*)();
using ModuleDestroyFn = void (*)(IModule*);
using ModuleAbiFn = const char* (*)();

} // namespace dvargosh

// Helper macro to export module in dynamic library (.dylib / .so)
#define DVARGOSH_EXPORT_MODULE(ModuleClass) \
    extern "C" { \
        dvargosh::IModule* dvargosh_module_create() { \
            return new ModuleClass(); \
        } \
        void dvargosh_module_destroy(dvargosh::IModule* mod) { \
            delete mod; \
        } \
        const char* dvargosh_abi_version() { \
            return DVARGOSH_ABI_VERSION_STR; \
        } \
    }
