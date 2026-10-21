#include "dvargosh/module_loader.hpp"
#include "dvargosh/runtime.hpp"
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <unordered_set>

namespace dvargosh {

static size_t read_module_def_quota_bytes(const std::string& mod_name, const std::string& filepath) {
    std::string dir_part = "";
    auto last_slash = filepath.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        dir_part = filepath.substr(0, last_slash + 1);
    }

    std::vector<std::string> candidate_defs = {
        filepath + ".def",
        dir_part + mod_name + ".def",
        dir_part + "module.def",
        "modules/" + mod_name + "/module.def",
        "development_modules/" + mod_name + "/module.def",
        "build/development_modules/" + mod_name + "/module.def",
        "build/modules/" + mod_name + ".def"
    };

    for (const auto& def_path : candidate_defs) {
        std::ifstream f(def_path);
        if (!f.is_open()) continue;
        std::string line;
        while (std::getline(f, line)) {
            auto pos = line.find("secured_memory_kb");
            if (pos != std::string::npos) {
                auto eq = line.find('=', pos);
                if (eq != std::string::npos) {
                    try {
                        std::string val_str = line.substr(eq + 1);
                        size_t kb = std::stoull(val_str);
                        if (kb > 0) return kb * 1024;
                    } catch (...) {}
                }
            }
        }
    }
    return 0;
}

ModuleLoader::ModuleLoader(std::shared_ptr<DIContainer> di, ModuleLoaderConfig config)
    : m_di(std::move(di)), m_config(std::move(config)) {
    // Default search directories
    m_search_paths.push_back("./build/modules");
    m_search_paths.push_back("./modules");
}

void ModuleLoader::add_search_path(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& existing : m_search_paths) {
        if (existing == path) return;
    }
    m_search_paths.push_back(path);
}

std::vector<DiscoveredModuleInfo> ModuleLoader::discover_all_modules() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<DiscoveredModuleInfo> result;
    std::unordered_set<std::string> seen_names;

#if defined(__APPLE__)
    const std::string ext = ".dylib";
#else
    const std::string ext = ".so";
#endif

    for (const auto& dir_path : m_search_paths) {
        DIR* dir = opendir(dir_path.c_str());
        if (!dir) continue;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string filename = entry->d_name;
            if (filename.size() <= ext.size()) continue;
            if (filename.compare(filename.size() - ext.size(), ext.size(), ext) != 0) continue;

            std::string full_path = dir_path + "/" + filename;

            // Inspect dynamic library header symbols without executing module code
            void* handle = dlopen(full_path.c_str(), RTLD_LAZY | RTLD_LOCAL);
            if (!handle) continue;

            auto magic_fn = reinterpret_cast<ModuleMagicFn>(dlsym(handle, "dvargosh_module_magic"));
            if (!magic_fn || std::string(magic_fn()) != DVARGOSH_MODULE_MAGIC) {
                dlclose(handle);
                continue;
            }

            auto name_fn = reinterpret_cast<ModuleNameFn>(dlsym(handle, "dvargosh_module_name"));
            auto build_fn = reinterpret_cast<ModuleBuildIdFn>(dlsym(handle, "dvargosh_build_id"));
            auto abi_fn = reinterpret_cast<ModuleAbiFn>(dlsym(handle, "dvargosh_abi_version"));

            DiscoveredModuleInfo info;
            info.filename = filename;
            info.full_path = full_path;
            info.name = name_fn ? name_fn() : filename;
            info.build_id = build_fn ? build_fn() : "unknown";
            info.abi_version = abi_fn ? abi_fn() : "unknown";
            info.is_valid = true;

            dlclose(handle);

            m_discovered_by_name[info.name] = info;
            m_discovered_by_filename[info.filename] = info;

            if (seen_names.find(info.name) == seen_names.end()) {
                seen_names.insert(info.name);
                result.push_back(info);
            }
        }
        closedir(dir);
    }

    return result;
}

const DiscoveredModuleInfo* ModuleLoader::get_discovered_info(const std::string& name_or_filename) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it_name = m_discovered_by_name.find(name_or_filename);
    if (it_name != m_discovered_by_name.end()) return &it_name->second;

    auto it_file = m_discovered_by_filename.find(name_or_filename);
    if (it_file != m_discovered_by_filename.end()) return &it_file->second;

    return nullptr;
}

Result<std::string> ModuleLoader::find_module_file(const std::string& name_or_filename) const {
    // 1. Direct path check
    if (access(name_or_filename.c_str(), F_OK) == 0) {
        return Result<std::string>::success(name_or_filename);
    }

    // 2. Check cached discovered modules
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_discovered_by_name.find(name_or_filename);
        if (it != m_discovered_by_name.end()) {
            return Result<std::string>::success(it->second.full_path);
        }
        auto it_f = m_discovered_by_filename.find(name_or_filename);
        if (it_f != m_discovered_by_filename.end()) {
            return Result<std::string>::success(it_f->second.full_path);
        }
    }

#if defined(__APPLE__)
    const char* ext = ".dylib";
#else
    const char* ext = ".so";
#endif

    std::vector<std::string> patterns = {
        name_or_filename,
        "libmod_" + name_or_filename + ext,
        "lib" + name_or_filename + ext,
        name_or_filename + ext
    };

    for (const auto& dir : m_search_paths) {
        for (const auto& pat : patterns) {
            std::string candidate = dir + "/" + pat;
            if (access(candidate.c_str(), F_OK) == 0) {
                return Result<std::string>::success(candidate);
            }
        }
    }

    return Result<std::string>::failure(
        StatusCode::NotFound,
        "Module '" + name_or_filename + "' not found in search paths"
    );
}

Result<void> ModuleLoader::load(
    const std::string& name_or_filename,
    const std::string& signature,
    const SecurityPolicy* custom_policy
) {
    auto file_res = find_module_file(name_or_filename);
    if (!file_res.is_ok()) {
        // Run auto-discovery if first search missed
        discover_all_modules();
        file_res = find_module_file(name_or_filename);
        if (!file_res.is_ok()) {
            return Result<void>::failure(file_res.status(), file_res.error_message());
        }
    }

    return load_from_file(file_res.value(), signature, custom_policy);
}

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

    size_t def_quota = read_module_def_quota_bytes(mod_name, filepath);
    size_t secured_mem_size = (def_quota > 0) ? def_quota : m_config.secured_memory_size;

    auto ctx_res = m_di->create_module_context(mod_name, manifest.domain, policy, secured_mem_size);
    if (!ctx_res.is_ok()) {
        destroy_fn(instance);
        dlclose(handle);
        return Result<void>::failure(ctx_res.status(), ctx_res.error_message());
    }
    auto context = std::move(ctx_res.value());

    // Enforce quota limit on the module's tracked allocator if defined in module.def
    if (def_quota > 0 && context->allocator()) {
        context->allocator()->set_max_capacity(def_quota);
    }

    // Register active context in runtime service locator
    Runtime::set_active_registry(m_di->registry().get());
    Runtime::set_active_container(m_di.get());
    Runtime::register_module_context(mod_name, context.get());

    // 7. Lifecycle on_load & on_start
    auto load_res = instance->on_load(*context);
    if (!load_res.is_ok()) {
        Runtime::unregister_module_context(mod_name);
        destroy_fn(instance);
        dlclose(handle);
        return Result<void>::failure(load_res.status(), "Module on_load failed: " + load_res.error_message());
    }

    auto start_res = instance->on_start(*context);
    if (!start_res.is_ok()) {
        instance->on_unload(*context);
        Runtime::unregister_module_context(mod_name);
        destroy_fn(instance);
        dlclose(handle);
        return Result<void>::failure(start_res.status(), "Module on_start failed: " + start_res.error_message());
    }

    // 8. Register in loaded modules
    LoadedModule loaded;
    loaded.name = mod_name;
    loaded.domain = manifest.domain;
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
    auto ctx_res = m_di->create_module_context(mod_name, manifest.domain, policy, m_config.secured_memory_size);
    if (!ctx_res.is_ok()) {
        return Result<void>::failure(ctx_res.status(), ctx_res.error_message());
    }
    auto context = std::move(ctx_res.value());

    Runtime::set_active_registry(m_di->registry().get());
    Runtime::set_active_container(m_di.get());
    Runtime::register_module_context(mod_name, context.get());

    auto load_res = mod->on_load(*context);
    if (!load_res.is_ok()) {
        Runtime::unregister_module_context(mod_name);
        return Result<void>::failure(load_res.status(), "Static module on_load failed: " + load_res.error_message());
    }

    auto start_res = mod->on_start(*context);
    if (!start_res.is_ok()) {
        mod->on_unload(*context);
        Runtime::unregister_module_context(mod_name);
        return Result<void>::failure(start_res.status(), "Static module on_start failed: " + start_res.error_message());
    }

    LoadedModule loaded;
    loaded.name = mod_name;
    loaded.domain = manifest.domain;
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

    Runtime::unregister_module_context(module_name);

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

Result<size_t> ModuleLoader::auto_load_all(const std::string& secret_key) {
    auto discovered = discover_all_modules();
    std::string key = secret_key.empty() ? m_config.secret_signing_key : secret_key;
    size_t loaded_count = 0;

    for (const auto& info : discovered) {
        if (is_loaded(info.name)) continue;

        std::string sig;
        if (!key.empty()) {
            auto sig_res = Crypto::sign_file(key, info.full_path);
            if (sig_res.is_ok()) sig = sig_res.value();
        }

        auto load_res = load(info.name, sig);
        if (load_res.is_ok()) {
            loaded_count++;
        }
    }
    return Result<size_t>::success(loaded_count);
}

Result<size_t> ModuleLoader::auto_load_matching(const std::string& pattern, const std::string& secret_key) {
    auto discovered = discover_all_modules();
    std::string key = secret_key.empty() ? m_config.secret_signing_key : secret_key;
    size_t loaded_count = 0;

    auto matches = [](const std::string& str, const std::string& pat) {
        if (pat == "*" || pat.empty()) return true;
        if (pat.front() == '*' && pat.back() == '*') {
            std::string sub = pat.substr(1, pat.size() - 2);
            return str.find(sub) != std::string::npos;
        }
        if (pat.back() == '*') {
            std::string prefix = pat.substr(0, pat.size() - 1);
            return str.rfind(prefix, 0) == 0;
        }
        if (pat.front() == '*') {
            std::string suffix = pat.substr(1);
            if (str.size() >= suffix.size()) {
                return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
            }
            return false;
        }
        return str == pat;
    };

    for (const auto& info : discovered) {
        if (!matches(info.name, pattern) && !matches(info.filename, pattern)) {
            continue;
        }
        if (is_loaded(info.name)) continue;

        std::string sig;
        if (!key.empty()) {
            auto sig_res = Crypto::sign_file(key, info.full_path);
            if (sig_res.is_ok()) sig = sig_res.value();
        }

        auto load_res = load(info.name, sig);
        if (load_res.is_ok()) {
            loaded_count++;
        }
    }
    return Result<size_t>::success(loaded_count);
}

Result<void> ModuleLoader::auto_load_domain(const std::string& domain_name, const std::string& secret_key) {
    auto discovered = discover_all_modules();
    std::string key = secret_key.empty() ? m_config.secret_signing_key : secret_key;

    std::string candidate_mod = domain_name;
    auto colon_pos = domain_name.find(':');
    if (colon_pos != std::string::npos) {
        candidate_mod = domain_name.substr(0, colon_pos);
    }

    for (const auto& info : discovered) {
        if (info.name == candidate_mod || info.name.find(candidate_mod) != std::string::npos) {
            if (is_loaded(info.name)) return Result<void>::success();

            std::string sig;
            if (!key.empty()) {
                auto sig_res = Crypto::sign_file(key, info.full_path);
                if (sig_res.is_ok()) sig = sig_res.value();
            }
            return load(info.name, sig);
        }
    }
    return Result<void>::failure(StatusCode::NotFound, "No discovered module provides domain '" + domain_name + "'");
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
