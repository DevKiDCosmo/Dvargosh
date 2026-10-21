#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

TEST_CASE(test_cross_domain_violation_catch) {
    auto dm = std::make_shared<DomainManager>();
    Registry reg;
    reg.set_domain_manager(dm.get());

    // Create two domains: "finance" and "guest"
    dm->create_domain("finance", SecurityPolicy::standard());
    dm->create_domain("guest", SecurityPolicy::strict());

    // Register a sensitive method in "finance" domain
    auto reg_res = reg.register_method(
        "finance.transfer",
        "Transfers funds",
        "mod_bank",
        "finance",
        [](const std::vector<Value>&) -> Result<Value> {
            return Result<Value>::success(Value("Transfer successful"));
        }
    );
    ASSERT_TRUE(reg_res.is_ok());

    // 1. Violation Test: "guest" domain attempts to invoke method in "finance" domain
    auto unauthorized_call = reg.invoke(
        "finance.transfer",
        {},
        "guest_module",
        "guest" // Caller domain
    );

    // Verify it was caught and denied!
    ASSERT_FALSE(unauthorized_call.is_ok());
    ASSERT_EQ(unauthorized_call.status(), StatusCode::PermissionDenied);
    ASSERT_TRUE(unauthorized_call.error_message().find("Cross-Domain Violation") != std::string::npos);

    // 2. Grant cross-domain access and verify it now succeeds
    dm->allow_cross_domain("guest", "finance");
    auto authorized_call = reg.invoke(
        "finance.transfer",
        {},
        "guest_module",
        "guest"
    );
    ASSERT_TRUE(authorized_call.is_ok());
    ASSERT_EQ(authorized_call.value().to_string(), "Transfer successful");
}

TEST_CASE(test_memory_quota_violation_catch) {
    SecuredMemoryConfig cfg;
    cfg.container_name = "test_quota_violation";
    cfg.capacity_bytes = 4096;
    cfg.use_guard_pages = false;

    SecurityPolicy policy;
    policy.permissions().grant(Permission::SecuredMemory);
    policy.set_max_memory_bytes(4096);

    auto space_res = SecuredMemorySpace::create(cfg, policy);
    ASSERT_TRUE(space_res.is_ok());
    auto& space = space_res.value();

    // Allocate within capacity
    void* p1 = space->allocate(1024);
    ASSERT_TRUE(p1 != nullptr);

    // Exceed capacity -> catch violation
    void* p_exceed = space->allocate(space->capacity() + 1024);
    ASSERT_TRUE(p_exceed == nullptr);
}

TEST_CASE(test_permission_denial_catch) {
    Registry reg;
    SecurityPolicy restricted_policy;
    restricted_policy.permissions().revoke(Permission::ServiceRegister);

    // Try to register service without permission
    auto res = reg.register_service<int>(
        "bad_svc",
        std::make_shared<int>(42),
        Version{1, 0, 0},
        "bad_module",
        "default",
        &restricted_policy
    );

    ASSERT_FALSE(res.is_ok());
    ASSERT_EQ(res.status(), StatusCode::PermissionDenied);
}

TEST_CASE(test_crypto_signature_tamper_catch) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoaderConfig cfg;
    cfg.enforce_signatures = true;
    cfg.secret_signing_key = "correct_master_key";
    ModuleLoader loader(di, cfg);

    // Attempt to load with tampered signature
    auto res = loader.load_from_file("/invalid/path/tampered.dylib", "deadbeef00112233");
    ASSERT_FALSE(res.is_ok());
    ASSERT_EQ(res.status(), StatusCode::SignatureInvalid);
}

TEST_CASE(test_native_zero_conversion_logger) {
    Logger& logger = Logger::instance();
    logger.set_level(LogSeverity::Debug);
    logger.set_colored(false);

    int count = 42;
    double ratio = 3.14159;
    bool active = true;
    void* ptr = &count;

    logger.info("Native types: count=", count, ", ratio=", ratio, ", active=", active, ", ptr=", ptr);
    logger.warn("Warning check: code=", 500);
    logger.error("Error check: status=", false);

    logger.info_stream() << "Streaming native types: " << count << " and " << ratio;
    ASSERT_TRUE(logger.level() == LogSeverity::Debug);
}

TEST_CASE(test_runtime_context_and_cross_domain_violation) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    // Create domains
    di->domain_manager()->create_domain("vault_dom", SecurityPolicy::strict(), 64 * 1024, false);
    di->domain_manager()->create_domain("intruder_dom", SecurityPolicy::strict());

    // Register a mock secret in vault_dom
    di->registry()->register_method("vault.secret", "Protected secret", "test_mod", "vault_dom", [](const std::vector<Value>&) -> Result<Value> {
        return Result<Value>::success(Value("TOP_SECRET_DATA"));
    });

    // 1. Intruder invokes vault.secret -> rejected
    auto reject_res = di->registry()->invoke("vault.secret", {}, "intruder_mod", "intruder_dom");
    ASSERT_FALSE(reject_res.is_ok());
    ASSERT_EQ(reject_res.status(), StatusCode::PermissionDenied);

    // 2. Intruder attempts memory space access -> rejected
    auto space_reject = di->domain_manager()->get_domain_space("vault_dom", "intruder_dom");
    ASSERT_FALSE(space_reject.is_ok());
    ASSERT_EQ(space_reject.status(), StatusCode::PermissionDenied);

    // 3. Authorized domain after grant
    di->domain_manager()->allow_cross_domain("intruder_dom", "vault_dom");
    auto ok_res = di->registry()->invoke("vault.secret", {}, "intruder_mod", "intruder_dom");
    ASSERT_TRUE(ok_res.is_ok());
    ASSERT_EQ(ok_res.value().to_string(), "TOP_SECRET_DATA");
}
