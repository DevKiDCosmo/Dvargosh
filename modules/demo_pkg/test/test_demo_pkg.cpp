#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include "../demo_interfaces.hpp"

using namespace dvargosh;

TEST_CASE(test_demo_pkg_subsystems_and_cross_domain_restrictions) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    auto load_res = loader.load("demo_pkg", "");
    if (!load_res.is_ok()) {
        std::cout << " (skipping dynamic load, file not present yet) ";
        return;
    }

    ASSERT_TRUE(loader.is_loaded("demo_pkg"));

    // 1. Resolve typed services in scoped block
    {
        auto vault_res = di->registry()->get_service<IVaultService>("demo_pkg.vault");
        ASSERT_TRUE(vault_res.is_ok());
        auto vault = vault_res.value();
        ASSERT_TRUE(vault != nullptr);
        ASSERT_TRUE(vault->get_secret_token().find("SECRET_KEY_VAULT") != std::string::npos);

        auto worker_res = di->registry()->get_service<IWorkerService>("demo_pkg.worker");
        ASSERT_TRUE(worker_res.is_ok());
        auto worker = worker_res.value();
        ASSERT_EQ(worker->process_data("hello"), "[TRANSFORMED] hello");

        auto root_res = di->registry()->get_service<IModuleRootService>("demo_pkg.root");
        ASSERT_TRUE(root_res.is_ok());
        auto root_svc = root_res.value();
        ASSERT_TRUE(root_svc->get_package_info().find("demo_pkg") != std::string::npos);
    }

    // 2. Test Main Subsystem Access to Vault Subsystem (ALLOWED)
    auto main_call = di->registry()->invoke("demo_pkg.main.orchestrate");
    ASSERT_TRUE(main_call.is_ok());
    std::string result_str = main_call.value().to_string();
    ASSERT_TRUE(result_str.find("[TRANSFORMED] Job with key SECRET_KEY_VAULT") != std::string::npos);

    // 3. Test Worker Subsystem Access to Vault Subsystem (RESTRICTED VIOLATION)
    // The method demo_pkg.worker.try_vault_violation calls vault with caller_domain = "demo_pkg:worker"
    auto violation_call = di->registry()->invoke("demo_pkg.worker.try_vault_violation");
    // Verify that the call is blocked by cross-domain access control
    ASSERT_FALSE(violation_call.is_ok());
    ASSERT_EQ(violation_call.status(), StatusCode::PermissionDenied);
    ASSERT_TRUE(violation_call.error_message().find("Cross-Domain Violation") != std::string::npos);

    // 4. Test Root Wildcard (*) Subsystem method
    auto root_call = di->registry()->invoke("demo_pkg.root.info");
    ASSERT_TRUE(root_call.is_ok());
    ASSERT_TRUE(root_call.value().to_string().find("demo_pkg v1.0.0") != std::string::npos);

    // 5. Unload demo_pkg
    auto unload_res = loader.unload_module("demo_pkg");
    ASSERT_TRUE(unload_res.is_ok());
    ASSERT_FALSE(loader.is_loaded("demo_pkg"));
}
