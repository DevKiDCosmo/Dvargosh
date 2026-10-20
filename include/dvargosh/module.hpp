#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include "di_container.hpp"
#include <string>
#include <vector>
#include <functional>

namespace dvargosh {

#define DVARGOSH_ABI_VERSION_STR "dvargosh-abi-v1"
#define DVARGOSH_MODULE_MAGIC    "DVARGOSH_MODULE_V1"

#ifndef DVARGOSH_BUILD_ID_STR
#define DVARGOSH_BUILD_ID_STR "build-" __DATE__ "-" __TIME__
#endif

struct ModuleManifest {
    std::string name;
    Version version;
    std::string description;
    std::string author;
    std::string domain = "*"; // Scoped wildcard/root domain per module
    PermissionSet requested_permissions = PermissionSet::standard_module();
    std::string signature; // HMAC-SHA256 signature for verification
    std::string build_id = DVARGOSH_BUILD_ID_STR;
};

// Automatic Function Registration for Non-Monolithic Modular Design
struct AutoFunctionEntry {
    std::string name;
    std::string domain;
    std::string description;
    DynamicMethodFn fn;
};

class AutoFunctionRegistry {
public:
    static AutoFunctionRegistry& instance() {
        static AutoFunctionRegistry s_inst;
        return s_inst;
    }

    void add(AutoFunctionEntry entry) {
        m_entries.push_back(std::move(entry));
    }

    const std::vector<AutoFunctionEntry>& entries() const noexcept {
        return m_entries;
    }

    void clear() {
        m_entries.clear();
    }

private:
    AutoFunctionRegistry() = default;
    std::vector<AutoFunctionEntry> m_entries;
};

struct AutoFunctionRegistrar {
    AutoFunctionRegistrar(
        const std::string& name,
        const std::string& domain,
        const std::string& desc,
        DynamicMethodFn fn
    ) {
        AutoFunctionRegistry::instance().add({name, domain, desc, std::move(fn)});
    }
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

    // Helper to register all functions declared across non-monolithic files via DVARGOSH_EXPORT_FN
    void register_auto_functions(ModuleContext& ctx) {
        const auto& entries = AutoFunctionRegistry::instance().entries();
        for (const auto& entry : entries) {
            std::string dom = entry.domain.empty() ? manifest().domain : entry.domain;
            // Scoped wildcard domain resolution
            if (dom == "*") {
                dom = manifest().name + ".*";
            }
            ctx.registry()->register_method(
                entry.name,
                entry.description,
                manifest().name,
                dom,
                entry.fn,
                &ctx.policy()
            );
        }
    }
};

// Function pointer signatures for dynamic library symbol export
using ModuleCreateFn  = IModule* (*)();
using ModuleDestroyFn = void (*)(IModule*);
using ModuleAbiFn     = const char* (*)();
using ModuleMagicFn   = const char* (*)();
using ModuleNameFn    = const char* (*)();
using ModuleBuildIdFn = const char* (*)();

} // namespace dvargosh

// ============================================================================
// ATTRIBUTION MARKERS FOR PIPELINE CODE GENERATION & RUNTIME DECOUPLING
// ============================================================================
// These markers allow developers to decorate clean native C++ functions.
// During runtime C++ compilation, the preprocessor expands these to standard compiler
// annotations or no-ops, effectively commenting out the marker for the compiler.
// The pipeline scanner (pipeline_dvargosh) parses these markers to automatically
// extract domains, generate DVARGOSH_EXPORT_FN registration wrappers, and create
// strongly-typed C++ interface proxies for direct zero-overhead calling.
#ifndef DVARGOSH_SERVICE
#  define DVARGOSH_SERVICE(...) /* Dvargosh pipeline marker: commented out at runtime */
#  define DVARGOSH_FN(...)      /* Dvargosh pipeline marker: commented out at runtime */
#endif

// Attribute-like automatic function export macro for non-monolithic source files
// Usage in any .cpp file:
// DVARGOSH_EXPORT_FN("math.square", "compute", "Squares a number") {
//     double x = args.empty() ? 0 : args[0].as_double();
//     return Result<Value>::success(Value(x * x));
// }
#define DVARGOSH_EXPORT_FN(fn_name, domain_name, desc_str) \
    static dvargosh::Result<dvargosh::Value> _dv_fn_impl_##fn_name(const std::vector<dvargosh::Value>& args); \
    [[maybe_unused]] static const dvargosh::AutoFunctionRegistrar _dv_reg_##fn_name( \
        #fn_name, domain_name, desc_str, &_dv_fn_impl_##fn_name \
    ); \
    static dvargosh::Result<dvargosh::Value> _dv_fn_impl_##fn_name(const std::vector<dvargosh::Value>& args)

// Helper macro to export module in dynamic library (.dylib / .so)
#define DVARGOSH_EXPORT_MODULE(ModuleClass) \
    extern "C" { \
        const char* dvargosh_module_magic() { \
            return DVARGOSH_MODULE_MAGIC; \
        } \
        const char* dvargosh_module_name() { \
            static ModuleClass tmp; \
            return tmp.manifest().name.c_str(); \
        } \
        const char* dvargosh_build_id() { \
            return DVARGOSH_BUILD_ID_STR; \
        } \
        const char* dvargosh_abi_version() { \
            return DVARGOSH_ABI_VERSION_STR; \
        } \
        dvargosh::IModule* dvargosh_module_create() { \
            return new ModuleClass(); \
        } \
        void dvargosh_module_destroy(dvargosh::IModule* mod) { \
            delete mod; \
        } \
    }
