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
