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

struct AutoAliasEntry {
    std::string target_name;
    std::string alias_override;
};

class AutoFunctionRegistry {
public:
    static AutoFunctionRegistry& instance();

    void add(AutoFunctionEntry entry) {
        m_entries.push_back(std::move(entry));
    }

    void add_alias(AutoAliasEntry alias) {
        m_aliases.push_back(std::move(alias));
    }

    const std::vector<AutoFunctionEntry>& entries() const noexcept {
        return m_entries;
    }

    const std::vector<AutoAliasEntry>& aliases() const noexcept {
        return m_aliases;
    }

    void clear() {
        m_entries.clear();
        m_aliases.clear();
    }

private:
    AutoFunctionRegistry() = default;
    std::vector<AutoFunctionEntry> m_entries;
    std::vector<AutoAliasEntry> m_aliases;
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

struct AutoFunctionAliasRegistrar {
    AutoFunctionAliasRegistrar(
        const std::string& target_name,
        const std::string& alias_override
    ) {
        AutoFunctionRegistry::instance().add_alias({target_name, alias_override});
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
    // The alias (module.function) is the thing that the service is registered as. The old un-prefixed name is ditched.
    void register_auto_functions(ModuleContext& ctx) {
        auto& registry = AutoFunctionRegistry::instance();
        const auto& entries = registry.entries();
        const auto& aliases = registry.aliases();

        std::unordered_map<std::string, std::string> alias_map;
        for (const auto& al : aliases) {
            alias_map[al.target_name] = al.alias_override;
        }

        for (const auto& entry : entries) {
            std::string dom = entry.domain.empty() ? manifest().domain : entry.domain;
            if (dom == "*") {
                dom = manifest().name + ".*";
            }

            // The alias (module.function) is the registered name. Old name is ditched.
            std::string registered_name;
            auto it = alias_map.find(entry.name);
            if (it != alias_map.end()) {
                registered_name = it->second;
            } else {
                registered_name = manifest().name + "." + entry.name;
            }

            ctx.registry()->register_method(
                registered_name,
                entry.description,
                manifest().name,
                dom,
                entry.fn,
                &ctx.policy()
            );
        }

        // Clean registry state after registration for modular isolation
        registry.clear();
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

// Automatic Alias Override macro to distinguish methods across modules and domains
// When defined, allows invocations via either the canonical function name or its full alias override.
#define DVARGOSH_EXPORT_ALIAS_OVERRIDE(fn_name, alias_override) \
    [[maybe_unused]] static const dvargosh::AutoFunctionAliasRegistrar _dv_alias_##fn_name( \
        #fn_name, alias_override \
    );

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
