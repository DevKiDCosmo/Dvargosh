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

TEST_CASE(test_domain_spoofing_tamper_kill_violation) {
    auto dm = std::make_shared<DomainManager>();
    dm->create_domain("vault_dom", SecurityPolicy::strict(), 64 * 1024, false);
    dm->create_domain("intruder_dom", SecurityPolicy::strict());

    // Enter execution context as intruder_dom
    ScopedCallFrame intruder_frame("intruder_mod", "intruder_dom");

    // Attempt to spoof caller_domain by explicitly passing "vault_dom" to acquire safe space
    auto tamper_res = dm->get_domain_space("vault_dom", "vault_dom");

    // MUST be detected as tampering and rejected with SecurityTampering
    ASSERT_FALSE(tamper_res.is_ok());
    ASSERT_EQ(tamper_res.status(), StatusCode::SecurityTampering);
    ASSERT_TRUE(tamper_res.error_message().find("Tampered domain") != std::string::npos);
}

TEST_CASE(test_vault_hardware_sealing_and_domain_protection) {
    auto dm = std::make_shared<DomainManager>();
    dm->create_domain("secure_subsystem", SecurityPolicy::strict(), 64 * 1024, false);
    dm->create_domain("rogue_subsystem", SecurityPolicy::strict());

    VaultConfig vcfg;
    vcfg.name = "crypto_keys";
    vcfg.owner_domain = "secure_subsystem";
    vcfg.owner_module = "crypto_mod";
    vcfg.capacity_bytes = 32 * 1024;
    vcfg.security_level = VaultSecurityLevel::TamperProof;
    vcfg.auto_seal_on_write = true;
    vcfg.description = "Encrypted key storage with hardware page sealing";

    auto vault_res = dm->create_vault(vcfg);
    ASSERT_TRUE(vault_res.is_ok());
    auto vault = vault_res.value();

    // 1. Write secret as system/owner
    {
        ScopedCallFrame owner_frame("crypto_mod", "secure_subsystem");
        auto write_res = vault->write_secret("AES_ROOT_KEY", "7F8B9C0D1E2F3A4B5C6D");
        ASSERT_TRUE(write_res.is_ok());
        ASSERT_TRUE(vault->is_sealed());

        // Read secret as owner -> succeeds
        auto read_res = vault->read_secret("AES_ROOT_KEY");
        ASSERT_TRUE(read_res.is_ok());
        ASSERT_EQ(read_res.value(), "7F8B9C0D1E2F3A4B5C6D");

        // Verify cryptographic integrity
        auto integ_res = vault->verify_integrity();
        ASSERT_TRUE(integ_res.is_ok());
        ASSERT_TRUE(integ_res.value());
    }

    // 2. Unauthorized read from rogue_subsystem -> rejected
    {
        ScopedCallFrame rogue_frame("rogue_mod", "rogue_subsystem");
        auto bad_read = vault->read_secret("AES_ROOT_KEY");
        ASSERT_FALSE(bad_read.is_ok());
        ASSERT_EQ(bad_read.status(), StatusCode::PermissionDenied);

        // Unauthorized write from rogue_subsystem -> rejected
        auto bad_write = vault->write_secret("MALICIOUS_KEY", "OVERWRITE_ATTEMPT");
        ASSERT_FALSE(bad_write.is_ok());
        ASSERT_EQ(bad_write.status(), StatusCode::PermissionDenied);
    }
}

TEST_CASE(test_alias_override_method_resolution) {
    Registry reg;
    auto reg_res = reg.register_method(
        "compute_hash",
        "Computes payload hash",
        "demo_pkg",
        "crypto",
        [](const std::vector<Value>& args) -> Result<Value> {
            std::string input = args.empty() ? "" : args[0].to_string();
            return Result<Value>::success(Value("HASHED_" + input));
        }
    );
    ASSERT_TRUE(reg_res.is_ok());

    // Register alias override
    auto alias_res = reg.register_alias("demo_pkg.crypto.compute_hash", "compute_hash");
    ASSERT_TRUE(alias_res.is_ok());
    ASSERT_TRUE(reg.has_alias("demo_pkg.crypto.compute_hash"));
    ASSERT_TRUE(reg.has_method("demo_pkg.crypto.compute_hash"));

    // Invoke via canonical name
    auto call_canonical = reg.invoke("compute_hash", {Value("TestInput")});
    ASSERT_TRUE(call_canonical.is_ok());
    ASSERT_EQ(call_canonical.value().to_string(), "HASHED_TestInput");

    // Invoke via alias override
    auto call_alias = reg.invoke("demo_pkg.crypto.compute_hash", {Value("TestInput")});
    ASSERT_TRUE(call_alias.is_ok());
    ASSERT_EQ(call_alias.value().to_string(), "HASHED_TestInput");
}
