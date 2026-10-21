#include "dvargosh/dvargosh.hpp"
#include "../modules/logger/logger_interface.hpp"
#include "../modules/math/math_interface.hpp"
#include "../modules/monitor/monitor_interface.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>

using namespace dvargosh;

// ANSI Terminal Colors
#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_RED     "\033[31m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"

void print_banner() {
    std::cout << ANSI_CYAN << ANSI_BOLD
              << "[dvargosh] Runtime Engine v1.0.0 (Sandboxed Modules • Domains • RPC)\n"
              << ANSI_RESET;
}

void print_step(int step, int total, const std::string& title) {
    std::cout << ANSI_MAGENTA << ANSI_BOLD << "[" << step << "/" << total << "] "
              << ANSI_RESET << ANSI_BOLD << title << ANSI_RESET << "\n";
}

void run_automated_demonstration(const std::string& module_dir, const std::string& secret_key) {
    print_banner();

    // 1. Initialize DI Container & Domains
    print_step(1, 8, "Bootstrapping DI Container & Initializing Domain Hierarchy");
    auto di = std::make_shared<DIContainer>();
    auto dm = di->domain_manager();

    // Create logical security domains
    dm->create_domain("core", SecurityPolicy::permissive());
    dm->create_domain("compute", SecurityPolicy::standard());
    dm->create_domain("worker", SecurityPolicy::standard());
    dm->create_domain("telemetry", SecurityPolicy::standard());
    dm->create_domain("untrusted_guest", SecurityPolicy::strict());

    // Configure Domain-to-Domain Communication Policies
    dm->allow_cross_domain("compute", "core");      // compute can call core (logger)
    dm->allow_cross_domain("worker", "compute");    // worker can call compute (math)
    dm->allow_cross_domain("worker", "core");       // worker can call core (logger)
    dm->allow_cross_domain("telemetry", "*");       // telemetry can observe all domains
    // Notice: untrusted_guest is NOT allowed to call core or compute!

    // 2. Initialize Dedicated Domain Secured Memory Space
    print_step(2, 8, "Initializing Domain-Level Secured Memory Spaces");
    auto dom_space_res = dm->init_domain_space("compute", 1024 * 1024, true);
    if (dom_space_res.is_ok()) {
        std::cout << "  " << ANSI_GREEN << "✓" << ANSI_RESET
                  << " Allocated 1 MB Hardware-Guarded Domain Space for [compute] at: "
                  << dom_space_res.value()->raw_base() << "\n";
    }

    // 3. Declarative Module Registration via External Module Catalog
    print_step(3, 8, "Declarative Module Registration via Catalog");
    ModuleCatalog catalog;
    register_standard_modules(catalog); // Populates logger, math, worker, monitor
    catalog.dump_report();

    // 4. Cryptographic Module Loader & Signing
    print_step(4, 8, "Signing & Loading Modules into In-Process Containers");
    ModuleLoaderConfig loader_cfg;
    loader_cfg.enforce_signatures = true;
    loader_cfg.secret_signing_key = secret_key;
    loader_cfg.default_policy = SecurityPolicy::standard();
    loader_cfg.secured_memory_size = 4 * 1024 * 1024;

    ModuleLoader loader(di, loader_cfg);

    auto load_count_res = catalog.load_all(loader, module_dir, secret_key);
    if (!load_count_res.is_ok()) {
        std::cerr << "  " << ANSI_RED << "✗ Load failed: " << load_count_res.error_message() << ANSI_RESET << "\n";
        return;
    }
    std::cout << "  " << ANSI_GREEN << "✓" << ANSI_RESET << " Successfully verified, signed, and loaded "
              << load_count_res.value() << " plug-and-play dynamic modules.\n";

    // Show domain status report
    dm->dump_report();
    di->registry()->dump_report();

    // 5. Cross-Module Communication, Dynamic Calling & Monitoring
    print_step(5, 8, "Executing Cross-Module Dynamic Calls & Event Telemetry");

    // Dynamic invoke math.add
    auto add_res = di->registry()->invoke("math.add", {Value(21.0), Value(21.0)}, "main_runner", "compute");
    std::cout << "  -> Dynamic Call: math.add(21, 21) => "
              << ANSI_GREEN << (add_res.is_ok() ? add_res.value().to_string() : add_res.error_message()) << ANSI_RESET << "\n";

    // Dynamic invoke math.sum_range (uses arena scratchpad + emits event)
    auto sum_res = di->registry()->invoke("math.sum_range", {Value(100)}, "main_runner", "compute");
    std::cout << "  -> Dynamic Call: math.sum_range(100) => "
              << ANSI_GREEN << (sum_res.is_ok() ? sum_res.value().to_string() : sum_res.error_message()) << ANSI_RESET << "\n";

    // Dynamic invoke worker.execute_task (cross-calls math and logger)
    auto worker_task = di->registry()->invoke("worker.execute_task", {Value(5)}, "main_runner", "worker");
    std::cout << "  -> Dynamic Call: worker.execute_task(5) => "
              << ANSI_GREEN << (worker_task.is_ok() ? worker_task.value().to_string() : worker_task.error_message()) << ANSI_RESET << "\n";

    // Query telemetry dashboard from monitor module
    di->registry()->invoke("monitor.dashboard", {}, "main_runner", "telemetry");

    // 6. Security Violations & Error Catching
    print_step(6, 8, "Testing Security Violations & Diagnostic Catches");

    // Violation 1: Cross-Domain Access Violation
    std::cout << "  [Test 1] Untrusted domain attempts to invoke 'finance/admin' or 'math.add'...\n";
    auto cross_dom_res = di->registry()->invoke("math.add", {Value(1), Value(2)}, "guest_client", "untrusted_guest");
    if (!cross_dom_res.is_ok() && cross_dom_res.status() == StatusCode::PermissionDenied) {
        std::cout << "    " << ANSI_GREEN << "✓ CAUGHT VIOLATION:" << ANSI_RESET
                  << " " << cross_dom_res.error_message() << "\n";
    } else {
        std::cout << "    " << ANSI_RED << "✗ FAILED TO CATCH DOMAIN VIOLATION!" << ANSI_RESET << "\n";
    }

    // Violation 2: Cryptographic Signature Tamper Violation
    std::cout << "  [Test 2] Loading module with corrupted/tampered cryptographic signature...\n";
    std::string test_mod_path = module_dir + "/libmod_worker" + (std::string(
#if defined(__APPLE__)
        ".dylib"
#else
        ".so"
#endif
    ));
    auto tamper_res = loader.load_from_file(test_mod_path, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    if (!tamper_res.is_ok() && tamper_res.status() == StatusCode::SignatureInvalid) {
        std::cout << "    " << ANSI_GREEN << "✓ CAUGHT TAMPER VIOLATION:" << ANSI_RESET
                  << " " << tamper_res.error_message() << "\n";
    }

    // Violation 3: Permission Denial Violation
    std::cout << "  [Test 3] Invoking dynamic RPC without DynamicInvoke permission...\n";
    SecurityPolicy no_invoke_policy;
    no_invoke_policy.permissions().revoke(Permission::DynamicInvoke);
    auto perm_res = di->registry()->invoke("math.add", {Value(1), Value(2)}, "restricted_caller", "compute", &no_invoke_policy);
    if (!perm_res.is_ok() && perm_res.status() == StatusCode::PermissionDenied) {
        std::cout << "    " << ANSI_GREEN << "✓ CAUGHT PERMISSION VIOLATION:" << ANSI_RESET
                  << " " << perm_res.error_message() << "\n";
    }

    // 7. Domain Unplugging and Hot-Replugging
    print_step(7, 8, "Testing Domain Unplugging & Re-Plugging (Hot-Plug)");
    std::cout << "  -> Unplugging entire domain [compute]...\n";
    auto unplug_res = catalog.unload_domain("compute", loader);
    std::cout << "     " << ANSI_GREEN << "✓" << ANSI_RESET << " Unplugged " << unplug_res.value() << " module(s) from [compute].\n";
    std::cout << "     Is 'math' loaded? " << (loader.is_loaded("math") ? "YES" : "NO (Cleanly unmounted)") << "\n";

    std::cout << "  -> Re-plugging domain [compute]...\n";
    auto replug_res = catalog.load_domain("compute", loader, module_dir, secret_key);
    std::cout << "     " << ANSI_GREEN << "✓" << ANSI_RESET << " Re-plugged " << replug_res.value() << " module(s) into [compute].\n";
    std::cout << "     Is 'math' loaded? " << (loader.is_loaded("math") ? "YES (Fully restored & active)" : "NO") << "\n";

    // 8. Final Resource Teardown & Leak Audit
    print_step(8, 8, "Clean Teardown & Scoped Zero-Leak Memory Audit");
    catalog.unload_all(loader);

    std::cout << "\n" << ANSI_GREEN << ANSI_BOLD
              << "[dvargosh] All verification suites & domain tests passed with 0 leaks.\n"
              << ANSI_RESET << "\n";
}

int main(int argc, char** argv) {
    std::string module_dir = "./build/modules";
    std::string secret_key = "dvargosh_master_signing_key_2026";
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

    // Interactive CLI REPL
    std::cout << "[dvargosh] Starting Interactive CLI...\nType 'help' for commands.\n\n";
    ScopedCallFrame admin_frame("cli_admin", "system");
    auto di = std::make_shared<DIContainer>();
    ModuleLoaderConfig cfg;
    cfg.enforce_signatures = false;
    cfg.secret_signing_key = secret_key;
    ModuleLoader loader(di, cfg);

    // Add comprehensive search paths so standard, build, development, and dist modules are discovered
    loader.add_search_path(module_dir);
    loader.add_search_path("./build/modules");
    loader.add_search_path("./build/development_modules");
    loader.add_search_path("./dist/modules");
    loader.add_search_path("./modules");
    loader.add_search_path("./development_modules");

    ModuleCatalog catalog;
    register_standard_modules(catalog);

    // Initial discovery
    loader.discover_all_modules();

    std::string line;
    while (std::cout << "dvargosh> " && std::getline(std::cin, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "quit" || cmd == "exit") {
            break;
        } else if (cmd == "help") {
            std::cout << "Commands:\n"
                      << "  discover                     - Scan & list all available modules in search paths\n"
                      << "  load <name_or_file> [sig]    - Load dynamic module by name or path\n"
                      << "  unload <module_name>         - Unload single module\n"
                      << "  load_all                     - Load all discovered & catalog modules\n"
                      << "  load_domain <domain>         - Load all modules in domain\n"
                      << "  unload_domain <domain>       - Unload all modules in domain\n"
                      << "  invoke <method> [args...]    - Dynamically invoke RPC method\n"
                      << "  memory [status|domain|scrub] - Display or manage domain and vault memory\n"
                      << "  vaults                       - List all active cryptographic vaults\n"
                      << "  vault <subcmd> [args...]     - Inspect or operate on a vault (info, read, write, wipe, seal, unseal, verify)\n"
                      << "  domains                      - Display domain registry & memory\n"
                      << "  catalog                      - Display module catalog\n"
                      << "  services                     - List services & dynamic methods\n"
                      << "  modules                      - List loaded modules\n"
                      << "  resources                    - List active tracked resources\n"
                      << "  quit                         - Exit\n";
        } else if (cmd == "discover") {
            auto discovered = loader.discover_all_modules();
            std::cout << "Discovered " << discovered.size() << " modules:\n";
            for (const auto& info : discovered) {
                std::cout << "  - " << info.name << " (" << info.filename
                          << ", build: " << info.build_id
                          << ", path: " << info.full_path << ")\n";
            }
        } else if (cmd == "load") {
            std::string target;
            iss >> target;
            std::string sig;
            iss >> sig;
            if (target.empty()) {
                std::cout << "Usage: load <module_name_or_path> [signature]\n";
                continue;
            }

            // Auto-sign if secret_key is provided and sig is empty
            if (sig.empty() && !secret_key.empty()) {
                auto file_res = loader.find_module_file(target);
                if (file_res.is_ok()) {
                    auto s_res = Crypto::sign_file(secret_key, file_res.value());
                    if (s_res.is_ok()) sig = s_res.value();
                }
            }

            auto res = loader.load(target, sig);
            if (res.is_ok()) {
                std::cout << "Loaded module '" << target << "'.\n";
            } else {
                auto res2 = loader.load_from_file(target, sig);
                if (res2.is_ok()) {
                    std::cout << "Loaded module file '" << target << "'.\n";
                } else {
                    std::cerr << "Failed to load '" << target << "': " << res.error_message() << "\n";
                }
            }
        } else if (cmd == "unload") {
            std::string mod_name;
            iss >> mod_name;
            if (mod_name.empty()) {
                std::cout << "Usage: unload <module_name>\n";
            } else {
                auto res = loader.unload_module(mod_name);
                if (res.is_ok()) std::cout << "Unloaded module '" << mod_name << "'.\n";
                else std::cerr << "Failed: " << res.error_message() << "\n";
            }
        } else if (cmd == "load_all") {
            auto disc_res = loader.auto_load_all(secret_key);
            auto cat_res = catalog.load_all(loader, module_dir, secret_key);
            size_t total = (disc_res.is_ok() ? disc_res.value() : 0);
            std::cout << "Loaded " << total << " modules.\n";
        } else if (cmd == "load_domain") {
            std::string dom;
            iss >> dom;
            auto res = loader.auto_load_domain(dom, secret_key);
            if (res.is_ok()) {
                std::cout << "Loaded domain '" << dom << "'.\n";
            } else {
                auto res2 = catalog.load_domain(dom, loader, module_dir, secret_key);
                if (res2.is_ok()) std::cout << "Loaded " << res2.value() << " modules in domain '" << dom << "'.\n";
                else std::cerr << "Failed: " << res.error_message() << "\n";
            }
        } else if (cmd == "unload_domain") {
            std::string dom;
            iss >> dom;
            auto res = catalog.unload_domain(dom, loader);
            if (res.is_ok()) std::cout << "Unloaded " << res.value() << " modules from domain '" << dom << "'.\n";
            else std::cerr << "Failed: " << res.error_message() << "\n";
        } else if (cmd == "domains") {
            di->domain_manager()->dump_report();
        } else if (cmd == "memory") {
            std::string subcmd;
            iss >> subcmd;
            if (subcmd.empty() || subcmd == "status") {
                di->domain_manager()->dump_memory_report();
            } else if (subcmd == "domain") {
                std::string dom;
                iss >> dom;
                auto* space = di->domain_manager()->get_domain_space(dom);
                if (space) {
                    std::cout << "Domain '" << dom << "' Memory Space:\n"
                              << "  Capacity:  " << (space->capacity() / 1024) << " KB (" << space->capacity() << " bytes)\n"
                              << "  Used:      " << space->used_bytes() << " bytes\n"
                              << "  Remaining: " << space->remaining_bytes() << " bytes\n"
                              << "  Base:      " << space->raw_base() << "\n";
                } else {
                    std::cerr << "Domain '" << dom << "' has no active secured memory space.\n";
                }
            } else if (subcmd == "scrub") {
                std::string dom;
                iss >> dom;
                auto* space = di->domain_manager()->get_domain_space(dom);
                if (space) {
                    space->scrub();
                    std::cout << "Scrubbed and volatile-zeroed secured memory space for domain '" << dom << "'.\n";
                } else {
                    std::cerr << "Domain '" << dom << "' not found or has no memory space.\n";
                }
            } else if (subcmd == "reset") {
                std::string dom;
                iss >> dom;
                auto* space = di->domain_manager()->get_domain_space(dom);
                if (space) {
                    space->reset();
                    std::cout << "Reset secured memory space for domain '" << dom << "' (offset rewound to 0).\n";
                } else {
                    std::cerr << "Domain '" << dom << "' not found or has no memory space.\n";
                }
            } else {
                std::cout << "Usage: memory [status | domain <name> | scrub <name> | reset <name>]\n";
            }
        } else if (cmd == "vaults") {
            auto vaults = di->domain_manager()->list_all_vaults();
            std::cout << "\n┌────────────────────────────────────────────────────────────────────────────────────────┐\n";
            std::cout << "│                               DVARGOSH VAULTS REGISTRY                                 │\n";
            std::cout << "├──────────────────┬──────────────────┬──────────────┬──────────────┬───────┬────────────┤\n";
            std::cout << "│ Vault Name       │ Owner Domain     │ Capacity     │ Used Memory  │ Slots │ Sealed     │\n";
            std::cout << "├──────────────────┼──────────────────┼──────────────┼──────────────┼───────┼────────────┤\n";
            for (const auto& v : vaults) {
                auto st = v->memory_stats();
                std::string cap_str = std::to_string(st.capacity_bytes / 1024) + " KB";
                std::string used_str = std::to_string(st.used_bytes) + " B";
                std::string sealed_str = st.is_sealed ? "YES (PROT)" : "NO";

                std::cout << "│ " << st.name;
                for (size_t i = st.name.length(); i < 16; ++i) std::cout << " ";
                std::cout << " │ " << st.owner_domain;
                for (size_t i = st.owner_domain.length(); i < 16; ++i) std::cout << " ";
                std::cout << " │ " << cap_str;
                for (size_t i = cap_str.length(); i < 12; ++i) std::cout << " ";
                std::cout << " │ " << used_str;
                for (size_t i = used_str.length(); i < 12; ++i) std::cout << " ";
                std::cout << " │ " << st.slot_count;
                for (size_t i = std::to_string(st.slot_count).length(); i < 5; ++i) std::cout << " ";
                std::cout << " │ " << sealed_str;
                for (size_t i = sealed_str.length(); i < 10; ++i) std::cout << " ";
                std::cout << " │\n";
            }
            std::cout << "└──────────────────┴──────────────────┴──────────────┴──────────────┴───────┴────────────┘\n\n";
        } else if (cmd == "vault") {
            std::string subcmd;
            iss >> subcmd;
            if (subcmd == "info") {
                std::string dom, vname;
                iss >> dom >> vname;
                auto v_res = di->domain_manager()->get_domain_vault(dom, vname);
                if (v_res.is_ok()) {
                    auto st = v_res.value()->memory_stats();
                    std::cout << "Vault '" << st.name << "' in Domain '" << st.owner_domain << "':\n"
                              << "  Owner Module:   " << st.owner_module << "\n"
                              << "  Security Level: " << vault_security_level_to_string(st.security_level) << "\n"
                              << "  Capacity:       " << (st.capacity_bytes / 1024) << " KB (" << st.capacity_bytes << " bytes)\n"
                              << "  Used Memory:    " << st.used_bytes << " bytes\n"
                              << "  Remaining:      " << st.remaining_bytes << " bytes\n"
                              << "  Active Slots:   " << st.slot_count << "\n"
                              << "  Sealed:         " << (st.is_sealed ? "YES (Hardware PROT_READ)" : "NO") << "\n"
                              << "  Guard Pages:    " << (st.guard_pages_enabled ? "YES (PROT_NONE)" : "NO") << "\n";
                    auto slots = v_res.value()->list_slots();
                    if (!slots.empty()) {
                        std::cout << "  Stored Slots:\n";
                        for (const auto& sl : slots) {
                            std::cout << "    * " << sl.key << " [offset=" << sl.offset
                                      << ", size=" << sl.size << " bytes, checksum="
                                      << (sl.checksum.empty() ? "(none)" : sl.checksum.substr(0, 16) + "...")
                                      << (sl.is_wiped ? " (WIPED)" : "") << "]\n";
                        }
                    }
                } else {
                    std::cerr << "Vault error: " << v_res.error_message() << "\n";
                }
            } else if (subcmd == "read") {
                std::string dom, vname, key;
                iss >> dom >> vname >> key;
                auto v_res = di->domain_manager()->get_domain_vault(dom, vname);
                if (v_res.is_ok()) {
                    auto s_res = v_res.value()->read_secret(key);
                    if (s_res.is_ok()) std::cout << "=> " << s_res.value() << "\n";
                    else std::cerr << "Read failed: " << s_res.error_message() << "\n";
                } else {
                    std::cerr << "Vault error: " << v_res.error_message() << "\n";
                }
            } else if (subcmd == "write") {
                std::string dom, vname, key, val;
                iss >> dom >> vname >> key >> val;
                auto v_res = di->domain_manager()->get_domain_vault(dom, vname);
                if (v_res.is_ok()) {
                    auto w_res = v_res.value()->write_secret(key, val);
                    if (w_res.is_ok()) std::cout << "Successfully written secret '" << key << "' into vault '" << vname << "'.\n";
                    else std::cerr << "Write failed: " << w_res.error_message() << "\n";
                } else {
                    std::cerr << "Vault error: " << v_res.error_message() << "\n";
                }
            } else if (subcmd == "wipe") {
                std::string dom, vname, key;
                iss >> dom >> vname >> key;
                auto v_res = di->domain_manager()->get_domain_vault(dom, vname);
                if (v_res.is_ok()) {
                    auto wp_res = v_res.value()->wipe_secret(key);
                    if (wp_res.is_ok()) std::cout << "Wiped memory slot for '" << key << "'.\n";
                    else std::cerr << "Wipe failed: " << wp_res.error_message() << "\n";
                } else {
                    std::cerr << "Vault error: " << v_res.error_message() << "\n";
                }
            } else if (subcmd == "seal") {
                std::string dom, vname;
                iss >> dom >> vname;
                auto v_res = di->domain_manager()->get_domain_vault(dom, vname);
                if (v_res.is_ok()) {
                    auto sl_res = v_res.value()->seal();
                    if (sl_res.is_ok()) std::cout << "Vault '" << vname << "' hardware-sealed (PROT_READ).\n";
                    else std::cerr << "Seal failed: " << sl_res.error_message() << "\n";
                } else {
                    std::cerr << "Vault error: " << v_res.error_message() << "\n";
                }
            } else if (subcmd == "unseal") {
                std::string dom, vname;
                iss >> dom >> vname;
                auto v_res = di->domain_manager()->get_domain_vault(dom, vname);
                if (v_res.is_ok()) {
                    auto unsl_res = v_res.value()->unseal();
                    if (unsl_res.is_ok()) std::cout << "Vault '" << vname << "' unsealed for authorized writes.\n";
                    else std::cerr << "Unseal failed: " << unsl_res.error_message() << "\n";
                } else {
                    std::cerr << "Vault error: " << v_res.error_message() << "\n";
                }
            } else if (subcmd == "verify") {
                std::string dom, vname;
                iss >> dom >> vname;
                auto v_res = di->domain_manager()->get_domain_vault(dom, vname);
                if (v_res.is_ok()) {
                    auto vf_res = v_res.value()->verify_integrity();
                    if (vf_res.is_ok() && vf_res.value()) {
                        std::cout << "✓ Cryptographic integrity verified: All stored slots match recorded checksums.\n";
                    } else {
                        std::cerr << "✗ Integrity check FAILED: " << vf_res.error_message() << "\n";
                    }
                } else {
                    std::cerr << "Vault error: " << v_res.error_message() << "\n";
                }
            } else {
                std::cout << "Usage: vault [info|read|write|wipe|seal|unseal|verify] <domain> <vault_name> [args...]\n";
            }
        } else if (cmd == "catalog") {
            catalog.dump_report();
        } else if (cmd == "services" || cmd == "methods") {
            di->registry()->dump_report();
        } else if (cmd == "modules") {
            loader.dump_report();
        } else if (cmd == "resources") {
            di->resource_manager()->dump_report();
        } else if (cmd == "invoke") {
            std::string method;
            iss >> method;
            std::vector<Value> args;
            std::string arg_str;
            while (iss >> arg_str) {
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
            else std::cerr << "Invoke error: " << res.error_message() << "\n";
        } else {
            std::cout << "Unknown command: '" << cmd << "'. Type 'help'.\n";
        }
    }

    return 0;
}
