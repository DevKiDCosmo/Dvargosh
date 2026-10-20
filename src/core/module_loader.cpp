#include "dvargosh/module_loader.hpp"
#include <dlfcn.h>
#include <iostream>

namespace dvargosh {

ModuleLoader::ModuleLoader(std::shared_ptr<DIContainer> di, ModuleLoaderConfig config)
    : m_di(std::move(di)), m_config(std::move(config)) {}

ModuleLoader::~ModuleLoader() {
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& [name, _] : m_loaded_modules) {
            names.push_back(name);
        }
    }
    for (const auto& name : names) {
        unload_module(name);
    }
}

Result<void> ModuleLoader::load_from_file(
    const std::string& filepath,
    const std::string& signature_override,
    const SecurityPolicy* custom_policy
) {
    // 1. Signature Verification if enforced
    if (m_config.enforce_signatures) {
        if (m_config.secret_signing_key.empty()) {
            return Result<void>::failure(StatusCode::SignatureInvalid, "Signature verification enforced but no signing key configured");
        }
        if (signature_override.empty()) {
            return Result<void>::failure(StatusCode::SignatureInvalid, "Signature verification failed: no signature provided for module " + filepath);
        }
        bool valid = Crypto::verify_file_signature(m_config.secret_signing_key, filepath, signature_override);
        if (!valid) {
            return Result<void>::failure(StatusCode::SignatureInvalid, "Cryptographic signature verification failed for module " + filepath);
        }
    }

    // 2. Dynamic Library Load
    dlerror(); // Clear existing errors
    void* handle = dlopen(filepath.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char* err = dlerror();
        return Result<void>::failure(StatusCode::LoadFailed, std::string("dlopen failed: ") + (err ? err : "unknown error"));
    }

    // 3. ABI Compatibility Check
    auto abi_fn = reinterpret_cast<ModuleAbiFn>(dlsym(handle, "dvargosh_abi_version"));
    if (!abi_fn) {
        dlclose(handle);
        return Result<void>::failure(StatusCode::SymbolNotFound, "Export 'dvargosh_abi_version' not found");
    }
    const char* abi = abi_fn();
    if (!abi || std::string(abi) != DVARGOSH_ABI_VERSION_STR) {
        dlclose(handle);
        return Result<void>::failure(StatusCode::TypeMismatch, std::string("ABI mismatch: expected ") + DVARGOSH_ABI_VERSION_STR + ", got " + (abi ? abi : "null"));
    }

    // 4. Resolve Factory Functions
    auto create_fn = reinterpret_cast<ModuleCreateFn>(dlsym(handle, "dvargosh_module_create"));
    auto destroy_fn = reinterpret_cast<ModuleDestroyFn>(dlsym(handle, "dvargosh_module_destroy"));

    if (!create_fn || !destroy_fn) {
        dlclose(handle);
        return Result<void>::failure(StatusCode::SymbolNotFound, "Module export symbols 'dvargosh_module_create' or 'destroy' not found");
    }

    // 5. Instantiate Module
    IModule* instance = create_fn();
    if (!instance) {
        dlclose(handle);
        return Result<void>::failure(StatusCode::InternalError, "Module factory returned null instance");
    }

    const auto& manifest = instance->manifest();
    std::string mod_name = manifest.name;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_loaded_modules.find(mod_name) != m_loaded_modules.end()) {
            destroy_fn(instance);
            dlclose(handle);
            return Result<void>::failure(StatusCode::AlreadyExists, "Module '" + mod_name + "' is already loaded");
        }
    }

    // 6. Security Policy & Container Context
    SecurityPolicy policy = custom_policy ? *custom_policy : m_config.default_policy;
    // Intersect or ensure policy accommodates requested permissions if granted
    for (const auto& p_str : manifest.requested_permissions.to_strings()) {
        Permission p = string_to_permission(p_str);
        if (p != Permission::None && m_config.default_policy.permissions().has(p)) {
            policy.permissions().grant(p);
        }
    }

    auto ctx_res = m_di->create_module_context(mod_name, policy, m_config.secured_memory_size);
    if (!ctx_res.is_ok()) {
        destroy_fn(instance);
        dlclose(handle);
        return Result<void>::failure(ctx_res.status(), ctx_res.error_message());
    }
    auto context = std::move(ctx_res.value());

    // 7. Lifecycle on_load & on_start
    auto load_res = instance->on_load(*context);
    if (!load_res.is_ok()) {
        destroy_fn(instance);
        dlclose(handle);
        return Result<void>::failure(load_res.status(), "Module on_load failed: " + load_res.error_message());
    }

    auto start_res = instance->on_start(*context);
    if (!start_res.is_ok()) {
        instance->on_unload(*context);
        destroy_fn(instance);
        dlclose(handle);
        return Result<void>::failure(start_res.status(), "Module on_start failed: " + start_res.error_message());
    }

    // 8. Register in loaded modules
    LoadedModule loaded;
    loaded.name = mod_name;
    loaded.filepath = filepath;
    loaded.version = manifest.version;
    loaded.lib_handle = handle;
    loaded.instance = instance;
    loaded.destroy_fn = destroy_fn;
    loaded.context = std::move(context);
    loaded.is_dynamic = true;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_loaded_modules[mod_name] = std::move(loaded);
    }

    return Result<void>::success();
}

Result<void> ModuleLoader::load_static_module(
    std::unique_ptr<IModule> mod,
    const SecurityPolicy* custom_policy
) {
    if (!mod) return Result<void>::failure(StatusCode::NullPointer, "Static module pointer is null");

    const auto& manifest = mod->manifest();
    std::string mod_name = manifest.name;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_loaded_modules.find(mod_name) != m_loaded_modules.end()) {
            return Result<void>::failure(StatusCode::AlreadyExists, "Module '" + mod_name + "' is already loaded");
        }
    }

    SecurityPolicy policy = custom_policy ? *custom_policy : m_config.default_policy;
    auto ctx_res = m_di->create_module_context(mod_name, policy, m_config.secured_memory_size);
    if (!ctx_res.is_ok()) {
        return Result<void>::failure(ctx_res.status(), ctx_res.error_message());
    }
    auto context = std::move(ctx_res.value());

    auto load_res = mod->on_load(*context);
    if (!load_res.is_ok()) {
        return Result<void>::failure(load_res.status(), "Static module on_load failed: " + load_res.error_message());
    }

    auto start_res = mod->on_start(*context);
    if (!start_res.is_ok()) {
        mod->on_unload(*context);
        return Result<void>::failure(start_res.status(), "Static module on_start failed: " + start_res.error_message());
    }

    LoadedModule loaded;
    loaded.name = mod_name;
    loaded.filepath = "<in-memory>";
    loaded.version = manifest.version;
    loaded.lib_handle = nullptr;
    loaded.instance = mod.release();
    loaded.destroy_fn = [](IModule* m) { delete m; };
    loaded.context = std::move(context);
    loaded.is_dynamic = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_loaded_modules[mod_name] = std::move(loaded);
    }

    return Result<void>::success();
}

Result<void> ModuleLoader::unload_module(const std::string& module_name) {
    LoadedModule loaded;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_loaded_modules.find(module_name);
        if (it == m_loaded_modules.end()) {
            return Result<void>::failure(StatusCode::NotFound, "Module '" + module_name + "' not found");
        }
        loaded = std::move(it->second);
        m_loaded_modules.erase(it);
    }

    if (loaded.instance && loaded.context) {
        loaded.instance->on_stop(*loaded.context);
        loaded.instance->on_unload(*loaded.context);
    }

    // Destroy context (cleans registry, event bus, resource manager, secured memory)
    loaded.context.reset();

    // Destroy module instance
    if (loaded.destroy_fn && loaded.instance) {
        loaded.destroy_fn(loaded.instance);
        loaded.instance = nullptr;
    }

    // Close dynamic library handle
    if (loaded.lib_handle) {
        dlclose(loaded.lib_handle);
        loaded.lib_handle = nullptr;
    }

    return Result<void>::success();
}

Result<void> ModuleLoader::reload_module(const std::string& module_name, const std::string& signature) {
    std::string path;
    bool is_dyn = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_loaded_modules.find(module_name);
        if (it == m_loaded_modules.end()) {
            return Result<void>::failure(StatusCode::NotFound, "Module '" + module_name + "' not loaded");
        }
        path = it->second.filepath;
        is_dyn = it->second.is_dynamic;
    }

    if (!is_dyn) {
        return Result<void>::failure(StatusCode::InvalidArg, "Cannot reload static/in-memory module");
    }

    auto unload_res = unload_module(module_name);
    if (!unload_res.is_ok()) return unload_res;

    return load_from_file(path, signature);
}

bool ModuleLoader::is_loaded(const std::string& module_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_loaded_modules.find(module_name) != m_loaded_modules.end();
}

std::vector<std::string> ModuleLoader::loaded_modules() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> names;
    names.reserve(m_loaded_modules.size());
    for (const auto& [name, _] : m_loaded_modules) {
        names.push_back(name);
    }
    return names;
}

const LoadedModule* ModuleLoader::get_module_info(const std::string& module_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_loaded_modules.find(module_name);
    if (it != m_loaded_modules.end()) {
        return &it->second;
    }
    return nullptr;
}

void ModuleLoader::dump_report() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << "=== [Dvargosh Loaded Modules: " << m_loaded_modules.size() << "] ===\n";
    for (const auto& [name, mod] : m_loaded_modules) {
        std::cout << "  * Module '" << name << "' v" << mod.version.to_string()
                  << " [" << (mod.is_dynamic ? "Dynamic: " + mod.filepath : "Static") << "]\n";
        if (mod.context && mod.context->secured_memory()) {
            std::cout << "    Secured Memory: "
                      << mod.context->secured_memory()->used_bytes() << "/"
                      << mod.context->secured_memory()->capacity() << " bytes used\n";
        }
    }
    std::cout << "=================================================\n";
}

} // namespace dvargosh
