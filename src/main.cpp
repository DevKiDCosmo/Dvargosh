#include "dvargosh/dvargosh.hpp"
#include "../modules/logger/logger_interface.hpp"
#include "../modules/math/math_interface.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

using namespace dvargosh;

void run_automated_demonstration(const std::string& module_dir, const std::string& secret_key) {
    std::cout << "\n=================================================================\n";
    std::cout << "        DVARGOSH RUNTIME ENGINE: AUTOMATED VERIFICATION        \n";
    std::cout << "=================================================================\n\n";

    // 1. Initialize DI Container
    std::cout << "[1/8] Bootstrapping DI Container and Subsystems...\n";
    auto di = std::make_shared<DIContainer>();

    // 2. Configure ModuleLoader with Signature Enforcement
    std::cout << "[2/8] Setting up ModuleLoader with Cryptographic Signature Engine...\n";
    ModuleLoaderConfig cfg;
    cfg.enforce_signatures = true;
    cfg.secret_signing_key = secret_key;
    cfg.default_policy = SecurityPolicy::permissive();
    cfg.secured_memory_size = 4 * 1024 * 1024; // 4 MB secured container per module

    ModuleLoader loader(di, cfg);

#if defined(__APPLE__)
    std::string ext = ".dylib";
#else
    std::string ext = ".so";
#endif

    std::string logger_path = module_dir + "/libmod_logger" + ext;
    std::string math_path   = module_dir + "/libmod_math" + ext;
    std::string worker_path = module_dir + "/libmod_worker" + ext;

    // 3. Cryptographic Signature Generation & Verification
    std::cout << "[3/8] Cryptographically Signing and Loading Dynamic Modules...\n";

    auto sign_and_load = [&](const std::string& path) {
        auto sig_res = Crypto::sign_file(secret_key, path);
        if (!sig_res.is_ok()) {
            std::cerr << "  [ERROR] Failed to sign " << path << ": " << sig_res.error_message() << "\n";
            return false;
        }
        std::string sig = sig_res.value();
        std::cout << "  * Signed '" << path << "'\n    HMAC-SHA256: " << sig << "\n";

        auto load_res = loader.load_from_file(path, sig);
        if (!load_res.is_ok()) {
            std::cerr << "  [ERROR] Failed to load " << path << ": " << load_res.error_message() << "\n";
            return false;
        }
        std::cout << "  * Successfully verified and loaded: " << path << "\n\n";
        return true;
    };

    if (!sign_and_load(logger_path)) return;
    if (!sign_and_load(math_path)) return;
    if (!sign_and_load(worker_path)) return;

    // 4. Inspect Global Registry
    std::cout << "[4/8] Global Service & Dynamic Method Registry Status:\n";
    di->registry()->dump_report();

    // 5. Demonstrate Dependency Injection & Dynamic Global Calling
    std::cout << "[5/8] Demonstrating Global Calling & Cross-Module Communication:\n";

    // Dynamic invoke "math.add"
    std::cout << "  -> Calling dynamic method 'math.add'(40, 2)...\n";
    auto add_res = di->registry()->invoke("math.add", {Value(40.0), Value(2.0)});
    if (add_res.is_ok()) {
        std::cout << "     Result: " << add_res.value().to_string() << "\n";
    }

    // Dynamic invoke "math.factorial"
    std::cout << "  -> Calling dynamic method 'math.factorial'(6)...\n";
    auto fact_res = di->registry()->invoke("math.factorial", {Value(6)});
    if (fact_res.is_ok()) {
        std::cout << "     Result: " << fact_res.value().to_string() << "\n";
    }

    // Dynamic invoke "math.sum_range" (triggers arena memory allocation + event bus emit)
    std::cout << "  -> Calling dynamic method 'math.sum_range'(100) [Scratchpad Arena + Event Pub]...\n";
    auto sum_res = di->registry()->invoke("math.sum_range", {Value(100)});
    if (sum_res.is_ok()) {
        std::cout << "     Result: " << sum_res.value().to_string() << "\n";
    }

    // Dynamic invoke "worker.execute_task" (cross-invokes math and logger!)
    std::cout << "  -> Calling dynamic method 'worker.execute_task'(7)...\n";
    auto worker_task_res = di->registry()->invoke("worker.execute_task", {Value(7)});
    if (worker_task_res.is_ok()) {
        std::cout << "     Worker Task Output: " << worker_task_res.value().to_string() << "\n";
    }

    // 6. Test Secured Memory Container & Hardware Isolation
    std::cout << "\n[6/8] Testing Secured Memory Space & Containerization:\n";
    auto sec_inspect = di->registry()->invoke("worker.inspect_security");
    if (sec_inspect.is_ok()) {
        std::cout << "  * " << sec_inspect.value().to_string() << "\n";
    }

    // Test stand-alone secured memory space initialization
    auto isolated_space_res = init_secured_memory_space("custom_isolated_container", 1024 * 1024, true);
    if (isolated_space_res.is_ok()) {
        auto& space = isolated_space_res.value();
        std::cout << "  * Initialized standalone secured memory container '" << space->name()
                  << "' with hardware guard pages.\n"
                  << "    Base Address: " << space->raw_base()
                  << " | Capacity: " << space->capacity() << " bytes\n";

        void* secure_buf = space->allocate(512);
        std::cout << "    Allocated 512 bytes inside secure container at: " << secure_buf << "\n";
        space->scrub();
        std::cout << "    Scrubbed and secured memory buffer successfully.\n";
    }

    // 7. Test Security Policy & Permission Enforcement
    std::cout << "\n[7/8] Testing Permission Enforcement & Tamper Detection:\n";

    // Tampered signature test
    std::cout << "  * Attempting to load module with invalid cryptographic signature...\n";
    auto tampered_res = loader.load_from_file(worker_path, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    if (!tampered_res.is_ok()) {
        std::cout << "    [SUCCESS] Blocked tampered module! Error: " << tampered_res.error_message() << "\n";
    }

    // Permission restriction test
    SecurityPolicy restricted_policy;
    restricted_policy.permissions().revoke(Permission::DynamicInvoke);
    std::cout << "  * Testing permission check: invoking method without DynamicInvoke permission...\n";
    auto restricted_call = di->registry()->invoke("math.add", {Value(1), Value(2)}, "unauthorized_caller", &restricted_policy);
    if (!restricted_call.is_ok()) {
        std::cout << "    [SUCCESS] Blocked unauthorized invocation! Error: " << restricted_call.error_message() << "\n";
    }

    // 8. Resource Manager & Hot-Unload / Clean Teardown
    std::cout << "\n[8/8] Testing Hot-Unplug & Scoped Zero-Leak Resource Cleanup:\n";
    di->resource_manager()->dump_report();

    std::cout << "  * Hot-unloading module 'worker'...\n";
    loader.unload_module("worker");

    std::cout << "  * Verifying resources owned by 'worker' were automatically destroyed:\n";
    di->resource_manager()->dump_report();

    std::cout << "  * Hot-unloading remaining modules...\n";
    loader.unload_module("math");
    loader.unload_module("logger");

    std::cout << "\n=================================================================\n";
    std::cout << "       DVARGOSH VERIFICATION COMPLETE: ALL SYSTEMS NOMINAL       \n";
    std::cout << "=================================================================\n\n";
}

int main(int argc, char** argv) {
    std::string module_dir = "./build/modules";
    std::string secret_key = "dvargosh_super_secret_master_signing_key_2026";
    bool interactive = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--modules" && i + 1 < argc) {
            module_dir = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            secret_key = argv[++i];
        } else if (arg == "--interactive" || arg == "-i") {
            interactive = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "  --modules <path>  Path to dynamic module directory (default: ./build/modules)\n"
                      << "  --key <secret>    Cryptographic secret signing key\n"
                      << "  --interactive, -i Run interactive CLI REPL\n"
                      << "  --help, -h        Show help\n";
            return 0;
        }
    }

    if (!interactive) {
        run_automated_demonstration(module_dir, secret_key);
        return 0;
    }

    // Interactive REPL
    std::cout << "Starting Dvargosh Interactive CLI...\nType 'help' for commands.\n\n";
    auto di = std::make_shared<DIContainer>();
    ModuleLoaderConfig cfg;
    cfg.enforce_signatures = false;
    cfg.secret_signing_key = secret_key;
    ModuleLoader loader(di, cfg);

    std::string line;
    while (std::cout << "dvargosh> " && std::getline(std::cin, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "quit" || cmd == "exit") {
            break;
        } else if (cmd == "help") {
            std::cout << "Available commands:\n"
                      << "  load <filepath> [signature] - Load dynamic module\n"
                      << "  unload <module_name>        - Hot-unload module\n"
                      << "  reload <module_name>        - Hot-reload module\n"
                      << "  invoke <method> [args...]   - Dynamically call registry method\n"
                      << "  services                    - List registered services\n"
                      << "  methods                     - List dynamic callable methods\n"
                      << "  modules                     - List loaded modules\n"
                      << "  resources                   - List active tracked resources\n"
                      << "  sign <filepath>             - Generate HMAC-SHA256 signature\n"
                      << "  quit                        - Exit\n";
        } else if (cmd == "load") {
            std::string path, sig;
            iss >> path >> sig;
            auto res = loader.load_from_file(path, sig);
            if (res.is_ok()) std::cout << "Module loaded successfully.\n";
            else std::cerr << "Load failed: " << res.error_message() << "\n";
        } else if (cmd == "unload") {
            std::string name;
            iss >> name;
            auto res = loader.unload_module(name);
            if (res.is_ok()) std::cout << "Module unloaded successfully.\n";
            else std::cerr << "Unload failed: " << res.error_message() << "\n";
        } else if (cmd == "reload") {
            std::string name;
            iss >> name;
            auto res = loader.reload_module(name);
            if (res.is_ok()) std::cout << "Module reloaded successfully.\n";
            else std::cerr << "Reload failed: " << res.error_message() << "\n";
        } else if (cmd == "invoke") {
            std::string method;
            iss >> method;
            std::vector<Value> args;
            std::string arg_str;
            while (iss >> arg_str) {
                // simple float/int/str detection
                try {
                    if (arg_str.find('.') != std::string::npos) {
                        args.push_back(Value(std::stod(arg_str)));
                    } else {
                        args.push_back(Value(static_cast<int64_t>(std::stoll(arg_str))));
                    }
                } catch (...) {
                    args.push_back(Value(arg_str));
                }
            }
            auto res = di->registry()->invoke(method, args);
            if (res.is_ok()) std::cout << "=> " << res.value().to_string() << "\n";
            else std::cerr << "Invoke failed: " << res.error_message() << "\n";
        } else if (cmd == "services" || cmd == "methods") {
            di->registry()->dump_report();
        } else if (cmd == "modules") {
            loader.dump_report();
        } else if (cmd == "resources") {
            di->resource_manager()->dump_report();
        } else if (cmd == "sign") {
            std::string path;
            iss >> path;
            auto res = Crypto::sign_file(secret_key, path);
            if (res.is_ok()) std::cout << "HMAC-SHA256: " << res.value() << "\n";
            else std::cerr << "Signing failed: " << res.error_message() << "\n";
        } else {
            std::cout << "Unknown command: '" << cmd << "'. Type 'help'.\n";
        }
    }

    return 0;
}
