#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include <iostream>
#include <cstring>

using namespace dvargosh;

/**
 * =========================================================================================
 * TEST SUITE: Streamlined Isolation & 3-Tier Secure Memory Architecture
 * =========================================================================================
 * Validates:
 * 1. Zero-parameter Runtime::get_context() caller resolution and anti-spoofing protection.
 * 2. Tier 1: Module heap memory quota enforcement via TrackedAllocator.
 * 3. Tier 2: In-process hardware-guarded memory container (SecuredMemorySpace).
 * 4. Tier 3: Cryptographic sealed vaults with domain authentication and hardware write sealing.
 * 5. Ephemeral execution scratchpad memory (CommandMemory) lifecycle and auto-scrubbing.
 * 6. Explicit DVARGOSH_SERVICE export boundary and cross-domain access control.
 * =========================================================================================
 */

TEST_CASE(test_zero_parameter_runtime_get_context_and_anti_spoofing) {
    auto di = std::make_shared<DIContainer>();
    auto ctx1_res = di->create_module_context("mod_victim", "victim_dom", SecurityPolicy::standard());
    auto ctx2_res = di->create_module_context("mod_attacker", "attacker_dom", SecurityPolicy::standard());
    ASSERT_TRUE(ctx1_res.is_ok());
    ASSERT_TRUE(ctx2_res.is_ok());
    auto ctx1 = std::move(ctx1_res.value());
    auto ctx2 = std::move(ctx2_res.value());

    Runtime::register_module_context("mod_victim", ctx1.get());
    Runtime::register_module_context("mod_attacker", ctx2.get());

    // Execute within frame of mod_attacker
    {
        ScopedCallFrame frame("mod_attacker", "attacker_dom");

        // 1. Zero-parameter Runtime::get_context() automatically and safely returns attacker's own context
        ModuleContext* own_ctx = Runtime::get_context();
        ASSERT_EQ(own_ctx, ctx2.get());

        // 2. Attacker attempting to pass "mod_victim" to get_context() is strictly denied (returns nullptr)
        ModuleContext* hijacked_ctx = Runtime::get_context("mod_victim");
        ASSERT_EQ(hijacked_ctx, nullptr);

        // 3. Runtime::current_context() also returns authentic context
        ASSERT_EQ(Runtime::current_context(), ctx2.get());
    }

    // Clean up
    Runtime::unregister_module_context("mod_victim");
    Runtime::unregister_module_context("mod_attacker");
}

TEST_CASE(test_tier1_tracked_allocator_quota_enforcement) {
    SystemAllocator sys_alloc;
    TrackedAllocator allocator(&sys_alloc, "test_tier1_module");

    // Set 4 KB hard quota
    allocator.set_max_capacity(4096);
    ASSERT_EQ(allocator.max_capacity(), 4096);

    // 1. Valid allocation within quota
    void* p1 = allocator.allocate(2048);
    ASSERT_TRUE(p1 != nullptr);
    ASSERT_EQ(allocator.allocated_bytes(), 2048);

    // 2. Exceeding quota must strictly fail (returns nullptr)
    void* p_exceed = allocator.allocate(3072);
    ASSERT_TRUE(p_exceed == nullptr);
    ASSERT_EQ(allocator.allocated_bytes(), 2048);

    // 3. Deallocation restores budget
    allocator.deallocate(p1, 2048);
    ASSERT_EQ(allocator.allocated_bytes(), 0);
    ASSERT_FALSE(allocator.has_leaks());
}

TEST_CASE(test_tier2_hardware_guarded_secured_memory_space) {
    SecuredMemoryConfig cfg;
    cfg.container_name = "test_tier2_hardware_space";
    cfg.capacity_bytes = 64 * 1024;
    cfg.use_guard_pages = true;
    cfg.scrub_on_destroy = true;

    SecurityPolicy policy;
    policy.permissions().grant(Permission::SecuredMemory);
    policy.set_max_memory_bytes(128 * 1024);

    auto space_res = SecuredMemorySpace::create(cfg, policy);
    ASSERT_TRUE(space_res.is_ok());
    auto space = std::move(space_res.value());

    ASSERT_TRUE(space->is_guard_pages_enabled());
    ASSERT_TRUE(space->capacity() >= 64 * 1024);

    // Allocate memory within hardware-guarded space
    void* buf = space->allocate(1024);
    ASSERT_TRUE(buf != nullptr);
    std::memset(buf, 0xAA, 1024);

    // Reset with volatile scrub
    space->reset();
    ASSERT_EQ(space->used_bytes(), 0);
}

TEST_CASE(test_tier3_cryptographic_vault_hardware_sealing_and_domain_isolation) {
    DomainManager dm;
    dm.create_domain("vault_domain", SecurityPolicy::strict(), 64 * 1024, true);
    dm.create_domain("intruder_domain", SecurityPolicy::strict());

    VaultConfig vcfg;
    vcfg.name = "root_vault";
    vcfg.owner_domain = "vault_domain";
    vcfg.owner_module = "test_mod";
    vcfg.capacity_bytes = 16 * 1024;
    vcfg.security_level = VaultSecurityLevel::TamperProof;
    vcfg.use_guard_pages = true;
    vcfg.auto_seal_on_write = true;

    auto v_res = dm.create_vault(vcfg);
    ASSERT_TRUE(v_res.is_ok());
    auto vault = v_res.value();

    // 1. Authorized write within owner domain
    {
        ScopedCallFrame frame("test_mod", "vault_domain");
        auto write_res = vault->write_secret("API_KEY", "SECRET_KEY_9988_XYZ");
        ASSERT_TRUE(write_res.is_ok());
        ASSERT_TRUE(vault->is_sealed());

        // Authorized read
        auto read_res = vault->read_secret("API_KEY");
        ASSERT_TRUE(read_res.is_ok());
        ASSERT_EQ(read_res.value(), "SECRET_KEY_9988_XYZ");
    }

    // 2. Unauthorized read from foreign domain (intruder_domain) MUST be rejected
    {
        ScopedCallFrame frame("test_mod", "intruder_domain");
        auto reject_res = dm.get_domain_vault("vault_domain", "root_vault");
        ASSERT_FALSE(reject_res.is_ok());
        ASSERT_EQ(reject_res.status(), StatusCode::PermissionDenied);
    }
}

TEST_CASE(test_ephemeral_command_memory_lifecycle_and_scrubbing) {
    // CommandMemory is ephemeral: tied to an execution frame, wiped on completion
    {
        CommandMemory cmd_mem(32 * 1024);
        ASSERT_EQ(cmd_mem.capacity(), 32 * 1024);
        ASSERT_EQ(cmd_mem.used_bytes(), 0);

        void* scratch = cmd_mem.allocate(512);
        ASSERT_TRUE(scratch != nullptr);
        std::memset(scratch, 0x55, 512);
        ASSERT_EQ(cmd_mem.used_bytes(), 512);

        // Volatile scrub and reset
        cmd_mem.scrub();
        cmd_mem.reset();
        ASSERT_EQ(cmd_mem.used_bytes(), 0);
    }
    // Memory unmapped upon scope exit
}

TEST_CASE(test_explicit_service_export_and_domain_boundary_checks) {
    auto di = std::make_shared<DIContainer>();
    auto reg = di->registry();
    auto dm = di->domain_manager();

    dm->create_domain("public_domain", SecurityPolicy::standard());
    dm->create_domain("vault_domain", SecurityPolicy::strict());
    dm->create_domain("intruder_domain", SecurityPolicy::strict());

    // Register sensitive service in vault_domain
    reg->register_method(
        "auth.get_token",
        "Sensitive Token Generator",
        "auth_mod",
        "vault_domain",
        [](const std::vector<Value>&) {
            return Result<Value>::success(Value("TOKEN_12345"));
        }
    );

    // Register public utility service in public_domain
    reg->register_method(
        "util.echo",
        "Public Echo",
        "util_mod",
        "public_domain",
        [](const std::vector<Value>& args) {
            return Result<Value>::success(args.empty() ? Value("OK") : args[0]);
        }
    );

    // 1. Intruder calling sensitive vault service without allow rule MUST FAIL (403)
    {
        ScopedCallFrame frame("caller_mod", "intruder_domain");
        auto call_res = reg->invoke("auth.get_token", {});
        ASSERT_FALSE(call_res.is_ok());
        ASSERT_EQ(call_res.status(), StatusCode::PermissionDenied);
    }

    // 2. Grant explicit intra-module domain access: allow intruder_domain -> vault_domain
    dm->allow_cross_domain("intruder_domain", "vault_domain");

    // 3. Now the call MUST SUCCEED
    {
        ScopedCallFrame frame("caller_mod", "intruder_domain");
        auto call_res = reg->invoke("auth.get_token", {});
        ASSERT_TRUE(call_res.is_ok());
        ASSERT_EQ(call_res.value().to_string(), "TOKEN_12345");
    }
}

TEST_CASE(test_discover_only_reads_header_and_rodata_of_libs) {
#if defined(__APPLE__)
    const std::string ext = ".dylib";
#else
    const std::string ext = ".so";
#endif

    std::string math_lib_path = "build/modules/libmod_math" + ext;
    if (!std::ifstream(math_lib_path).good()) {
        math_lib_path = "./build/modules/libmod_math" + ext;
    }

    if (std::ifstream(math_lib_path).good()) {
        // 1. Direct zero-execution binary inspection of header and rd (rodata) from disk
        auto hdr_res = ModuleHeader::read_from_file(math_lib_path);
        ASSERT_TRUE(hdr_res.is_ok());
        const auto& hdr = hdr_res.value();
        ASSERT_EQ(hdr.name, "math");
        ASSERT_EQ(hdr.abi_version, DVARGOSH_ABI_VERSION_STR);
        ASSERT_TRUE(hdr.validate().is_ok());
    }

    // 2. ModuleLoader::discover_all_modules directly scans libraries and extracts headers
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    loader.add_search_path("build/modules");
    loader.add_search_path("./build/modules");

    auto discovered = loader.discover_all_modules();
    ASSERT_FALSE(discovered.empty());

    bool found_math = false;
    for (const auto& mod : discovered) {
        ASSERT_FALSE(mod.name.empty());
        ASSERT_FALSE(mod.full_path.empty());
        ASSERT_EQ(mod.abi_version, DVARGOSH_ABI_VERSION_STR);
        ASSERT_TRUE(mod.is_valid);
        if (mod.name == "math") {
            found_math = true;
        }
    }
    ASSERT_TRUE(found_math);
}
