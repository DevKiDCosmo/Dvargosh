#include "dvargosh/dvargosh.hpp"
#include <iostream>
#include <cassert>

using namespace dvargosh;

int main() {
    std::cout << "[dvargosh] Standalone App Test: Loader & Auto-Registration\n";

    auto di = std::make_shared<DIContainer>();
    const std::string secret_key = "dvargosh_master_signing_key_2026";

    ModuleLoaderConfig cfg;
    cfg.enforce_signatures = true;
    cfg.secret_signing_key = secret_key;
    ModuleLoader loader(di, cfg);

    loader.add_search_path("./build/modules");
    loader.add_search_path("./build/development_modules");
    loader.add_search_path("./modules");
    loader.add_search_path("./development_modules");
    loader.add_search_path("../build/modules");
    loader.add_search_path("../build/development_modules");

    // 1. Run Universal Recognition & Auto-Discovery
    std::cout << "[Step 1] Running Auto-Discovery & Header Symbol Recognition...\n";
    auto discovered = loader.discover_all_modules();
    std::cout << "  Discovered " << discovered.size() << " Dvargosh modules in search paths:\n";
    for (const auto& info : discovered) {
        std::cout << "  * Name: " << info.name
                  << " | File: " << info.filename
                  << " | Build-ID: " << info.build_id
                  << " | ABI: " << info.abi_version << "\n";
    }

    // 2. Load modules using load('name', 'signature')
    std::cout << "\n[Step 2] Loading modules via load('name', 'signature')...\n";

    auto sign_and_load = [&](const std::string& name) {
        auto file_res = loader.find_module_file(name);
        if (!file_res.is_ok()) {
            std::cerr << "  [ERROR] Cannot find file for " << name << ": " << file_res.error_message() << "\n";
            return false;
        }
        auto sig_res = Crypto::sign_file(secret_key, file_res.value());
        std::string sig = sig_res.is_ok() ? sig_res.value() : "";

        // Calling load('name', 'signature') as requested
        auto load_res = loader.load(name, sig);
        if (!load_res.is_ok()) {
            std::cerr << "  [ERROR] load('" << name << "', sig) failed: " << load_res.error_message() << "\n";
            return false;
        }
        std::cout << "  ✓ Successfully loaded '" << name << "' via signature verification.\n";
        return true;
    };

    if (!sign_and_load("demo_pkg")) return 1;
    if (!sign_and_load("monitor")) return 1;
    if (!sign_and_load("crypto_accelerator")) return 1;
    if (!sign_and_load("hello_world")) return 1;
    if (!sign_and_load("worker")) return 1;

    // 3. Test Signature Rejection on Tampered Signature
    std::cout << "\n[Step 3] Testing Signature Rejection on Invalid Signature...\n";
    auto bad_load = loader.load("math", "invalid_tampered_signature_hex_00112233");
    if (!bad_load.is_ok() && bad_load.status() == StatusCode::SignatureInvalid) {
        std::cout << "  ✓ Correctly rejected invalid signature: " << bad_load.error_message() << "\n";
    } else {
        std::cerr << "  ✗ FAILED: Expected signature error!\n";
        return 1;
    }

    // 4. Invoke Multi-File Auto-Registered Functions (from [[]] / DVARGOSH_EXPORT_FN)
    std::cout << "\n[Step 4] Invoking Auto-Registered Functions from Non-Monolithic Files...\n";

    // Call demo_pkg_vault_hash (from ops_crypto.cpp)
    auto hash_res = di->registry()->invoke("demo_pkg_vault_hash", {Value("DvargoshData")});
    std::cout << "  * demo_pkg_vault_hash('DvargoshData') => "
              << (hash_res.is_ok() ? hash_res.value().to_string() : hash_res.error_message()) << "\n";
    assert(hash_res.is_ok());

    // Call demo_pkg_worker_power (from ops_calc.cpp)
    auto pow_res = di->registry()->invoke("demo_pkg_worker_power", {Value(2.0), Value(8.0)});
    std::cout << "  * demo_pkg_worker_power(2, 8) => "
              << (pow_res.is_ok() ? pow_res.value().to_string() : pow_res.error_message()) << "\n";
    assert(pow_res.is_ok());
    assert(pow_res.value().as_double() == 256.0);

    // Call accelerator_sha256 (from development_modules/crypto_accelerator/hasher.cpp)
    auto accel_hash = di->registry()->invoke("accelerator_sha256", {Value("QuantumPayload")});
    std::cout << "  * accelerator_sha256('QuantumPayload') => "
              << (accel_hash.is_ok() ? accel_hash.value().to_string() : accel_hash.error_message()) << "\n";
    assert(accel_hash.is_ok());

    // Call accelerator_rot13 (from development_modules/crypto_accelerator/cipher.cpp)
    auto rot13_res = di->registry()->invoke("accelerator_rot13", {Value("HelloDvargosh")});
    std::cout << "  * accelerator_rot13('HelloDvargosh') => "
              << (rot13_res.is_ok() ? rot13_res.value().to_string() : rot13_res.error_message()) << "\n";
    assert(rot13_res.is_ok());

    // Call get_safe_vault_key (from development_modules/helloWorld)
    auto vault_key_res = di->registry()->invoke("get_safe_vault_key");
    std::cout << "  * get_safe_vault_key() => "
              << (vault_key_res.is_ok() ? vault_key_res.value().to_string() : vault_key_res.error_message()) << "\n";
    assert(vault_key_res.is_ok());
    assert(vault_key_res.value().to_string() == "SECURE_KEY_NAM_CAPTIVES_9988_XYZ");

    // Call via alias override (helloworld.captives:vault.get_safe_vault_key)
    auto alias_res = di->registry()->invoke("helloworld.captives:vault.get_safe_vault_key");
    std::cout << "  * helloworld.captives:vault.get_safe_vault_key() (alias) => "
              << (alias_res.is_ok() ? alias_res.value().to_string() : alias_res.error_message()) << "\n";
    assert(alias_res.is_ok());
    assert(alias_res.value().to_string() == "SECURE_KEY_NAM_CAPTIVES_9988_XYZ");

    // Call intruder_access_safe_space -> correctly rejected
    auto breach_res = di->registry()->invoke("intruder_access_safe_space");
    std::cout << "  * intruder_access_safe_space() => "
              << (breach_res.is_ok() ? breach_res.value().to_string() : breach_res.error_message()) << "\n";
    assert(breach_res.is_ok());
    assert(breach_res.value().to_string().rfind("REJECTED", 0) == 0);

    // Call worker.box_invoke with normal execution
    auto box_ok = di->registry()->invoke("worker.box_invoke", {Value("accelerator_rot13"), Value("SecretTest"), Value("KILL_TRIGGER")});
    std::cout << "  * worker.box_invoke(accelerator_rot13, SecretTest) => "
              << (box_ok.is_ok() ? box_ok.value().to_string() : box_ok.error_message()) << "\n";
    assert(box_ok.is_ok());

    // Call worker.box_invoke with kill trigger -> terminates process
    auto box_kill = di->registry()->invoke("worker.box_invoke", {Value("accelerator_rot13"), Value("KILL_TRIGGER"), Value("KILL_TRIGGER")});
    std::cout << "  * worker.box_invoke with kill trigger => "
              << (box_kill.is_ok() ? box_kill.value().to_string() : box_kill.error_message()) << "\n";
    assert(!box_kill.is_ok());
    assert(box_kill.status() == StatusCode::SecurityTampering);

    // 5. Test Handling of Unresolved Functions & Fuzzy Suggestions
    std::cout << "\n[Step 5] Testing Unresolved Function Handling & Suggestions...\n";
    auto unres_res = di->registry()->invoke("demo_pkg_worker_pow"); // intentional typo for demo_pkg_worker_power
    if (!unres_res.is_ok() && unres_res.status() == StatusCode::SymbolNotFound) {
        std::cout << "  ✓ Caught unresolved function: " << unres_res.error_message() << "\n";
    }

    // 6. Test Memory & Secured Space Occupation from Monitor Module
    std::cout << "\n[Step 6] Querying Live Memory Occupation from Monitor Module...\n";
    auto mem_res = di->registry()->invoke("monitor.memory_status");
    if (mem_res.is_ok()) {
        std::cout << mem_res.value().to_string() << "\n";
    }

    std::cout << "[dvargosh] Standalone App Loader Test passed with 100% success.\n";
    return 0;
}
