#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

TEST_CASE(test_domain_creation_and_memory_space) {
    DomainManager dm;

    // 1. Create a custom domain with its own secured space
    auto create_res = dm.create_domain("analytics", SecurityPolicy::standard(), 128 * 1024, true);
    ASSERT_TRUE(create_res.is_ok());
    Domain* domain = create_res.value();
    ASSERT_TRUE(domain != nullptr);
    ASSERT_EQ(domain->name(), "analytics");

    // 2. Verify domain-level secured memory space was initialized
    SecuredMemorySpace* space = dm.get_domain_space("analytics");
    ASSERT_TRUE(space != nullptr);
    ASSERT_TRUE(space->capacity() >= 128 * 1024);

    // Sub-allocate within domain space
    void* p = space->allocate(512);
    ASSERT_TRUE(p != nullptr);
}

TEST_CASE(test_init_domain_space_function) {
    DomainManager dm;
    dm.create_domain("ml_inference", SecurityPolicy::standard());

    // Call explicit function to init secured space for domain
    auto res = dm.init_domain_space("ml_inference", 256 * 1024, true);
    ASSERT_TRUE(res.is_ok());

    SecuredMemorySpace* space = res.value();
    ASSERT_TRUE(space != nullptr);
    ASSERT_TRUE(space->capacity() >= 256 * 1024);
}

// Mock domain module to test plug and unplug
class DomainTestModule : public IModule {
public:
    DomainTestModule(std::string name, std::string domain)
        : m_name(std::move(name)), m_domain(std::move(domain)) {}

    const ModuleManifest& manifest() const override {
        static ModuleManifest m;
        m.name = m_name;
        m.domain = m_domain;
        m.version = Version{1, 0, 0};
        m.requested_permissions = PermissionSet::all();
        return m;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        m_loaded = true;
        // Verify domain space is accessible from within module context
        SecuredMemorySpace* d_space = ctx.domain_space();
        m_had_domain_space = (d_space != nullptr);
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override {
        m_loaded = false;
        return Result<void>::success();
    }

    bool m_loaded = false;
    bool m_had_domain_space = false;
private:
    std::string m_name;
    std::string m_domain;
};

TEST_CASE(test_domain_unplug_and_plug) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    // Initialize domain with domain-level secured memory space
    di->domain_manager()->create_domain("cloud_compute", SecurityPolicy::permissive(), 64 * 1024, false);

    // 1. Plug static module into domain "cloud_compute"
    auto mod1 = std::make_unique<DomainTestModule>("compute_node_1", "cloud_compute");
    DomainTestModule* ptr1 = mod1.get();

    auto load_res = loader.load_static_module(std::move(mod1));
    ASSERT_TRUE(load_res.is_ok());
    ASSERT_TRUE(loader.is_loaded("compute_node_1"));
    ASSERT_TRUE(ptr1->m_loaded);
    ASSERT_TRUE(ptr1->m_had_domain_space);

    // Verify module is in domain
    Domain* dom = di->domain_manager()->get_domain("cloud_compute");
    ASSERT_TRUE(dom != nullptr);
    ASSERT_TRUE(dom->has_module("compute_node_1"));

    // 2. Unplug entire domain
    auto unplug_res = di->domain_manager()->unplug_domain("cloud_compute", loader);
    ASSERT_TRUE(unplug_res.is_ok());
    ASSERT_EQ(unplug_res.value(), 1); // 1 module unplugged
    ASSERT_FALSE(loader.is_loaded("compute_node_1"));
    ASSERT_FALSE(dom->has_module("compute_node_1"));

    // 3. Re-plug module back into domain
    auto mod2 = std::make_unique<DomainTestModule>("compute_node_1", "cloud_compute");
    DomainTestModule* ptr2 = mod2.get();
    auto replug_res = loader.load_static_module(std::move(mod2));
    ASSERT_TRUE(replug_res.is_ok());
    ASSERT_TRUE(loader.is_loaded("compute_node_1"));
    ASSERT_TRUE(ptr2->m_loaded);
    ASSERT_TRUE(dom->has_module("compute_node_1"));

    loader.unload_module("compute_node_1");
}

TEST_CASE(test_domain_space_cross_domain_access_and_rejection) {
    DomainManager dm;
    dm.create_domain("vault", SecurityPolicy::strict(), 64 * 1024, false);
    dm.create_domain("intruder", SecurityPolicy::strict());
    dm.create_domain("authorized_partner", SecurityPolicy::standard());

    dm.allow_cross_domain("authorized_partner", "vault");

    // 1. Authorized partner can access vault safe space
    auto auth_res = dm.get_domain_space("vault", "authorized_partner");
    ASSERT_TRUE(auth_res.is_ok());
    ASSERT_TRUE(auth_res.value() != nullptr);

    // 2. Intruder is rejected
    auto reject_res = dm.get_domain_space("vault", "intruder");
    ASSERT_FALSE(reject_res.is_ok());
    ASSERT_EQ(reject_res.status(), StatusCode::PermissionDenied);
}

TEST_CASE(test_domain_blacklist_takes_precedence) {
    DomainManager dm;
    dm.create_domain("vault_zone", SecurityPolicy::strict());
    dm.create_domain("client_zone", SecurityPolicy::standard());

    // 1. Grant access via whitelist
    auto allow_res = dm.allow_cross_domain("client_zone", "vault_zone");
    ASSERT_TRUE(allow_res.is_ok());
    ASSERT_TRUE(dm.check_cross_domain_access("client_zone", "vault_zone"));

    // 2. Explicitly blacklist vault_zone for client_zone
    auto bl_res = dm.blacklist_domain("client_zone", "vault_zone");
    ASSERT_TRUE(bl_res.is_ok());
    ASSERT_TRUE(dm.is_cross_domain_blacklisted("client_zone", "vault_zone"));

    // Blacklist MUST override whitelist
    ASSERT_FALSE(dm.check_cross_domain_access("client_zone", "vault_zone"));

    // 3. Even with universal wildcard access granted, blacklist strictly takes precedence
    dm.allow_cross_domain("client_zone", "*");
    ASSERT_FALSE(dm.check_cross_domain_access("client_zone", "vault_zone"));

    // 4. Removing from blacklist restores access via whitelist/wildcard
    dm.unblacklist_domain("client_zone", "vault_zone");
    ASSERT_FALSE(dm.is_cross_domain_blacklisted("client_zone", "vault_zone"));
    ASSERT_TRUE(dm.check_cross_domain_access("client_zone", "vault_zone"));
}

TEST_CASE(test_domain_secured_space_and_vaults_unloader) {
    DomainManager dm;
    auto cr_res = dm.create_domain("secure_tier", SecurityPolicy::strict(), 64 * 1024, true);
    ASSERT_TRUE(cr_res.is_ok());
    ASSERT_TRUE(dm.get_domain_space("secure_tier") != nullptr);

    // Create vault in secure_tier
    VaultConfig vcfg;
    vcfg.name = "tier_vault";
    vcfg.owner_domain = "secure_tier";
    vcfg.owner_module = "tier_mod";
    vcfg.capacity_bytes = 16 * 1024;
    auto v_res = dm.create_vault(vcfg);
    ASSERT_TRUE(v_res.is_ok());

    // Unload secured space
    auto unl_space = dm.unload_domain_space("secure_tier");
    ASSERT_TRUE(unl_space.is_ok());
    ASSERT_TRUE(dm.get_domain_space("secure_tier") == nullptr);

    // Unload vaults
    auto unl_vaults = dm.unload_domain_vaults("secure_tier");
    ASSERT_TRUE(unl_vaults.is_ok());
    ASSERT_TRUE(dm.get_vault("tier_vault") == nullptr);
}

TEST_CASE(test_call_stack_hmac_tamper_detection) {
    // Fail-closed default: unauthenticated stack without frame defaults to untrusted, not system
    ASSERT_FALSE(ExecutionContext::is_system());
    ASSERT_EQ(ExecutionContext::current_domain(), "untrusted");

    {
        ScopedCallFrame frame("mod_alpha", "dom_alpha");
        ASSERT_FALSE(ExecutionContext::is_system());
        ASSERT_EQ(ExecutionContext::current_domain(), "dom_alpha");
        ASSERT_EQ(ExecutionContext::current_module(), "mod_alpha");

        // Integrity verification passes for authentic frames
        auto valid_res = ExecutionContext::validate_stack_integrity();
        ASSERT_TRUE(valid_res.is_ok());
    }

    // Explicit system frame grants system authority
    {
        ScopedCallFrame sys_frame("system_runner", "system");
        ASSERT_TRUE(ExecutionContext::is_system());
        ASSERT_EQ(ExecutionContext::current_domain(), "system");
    }

    // Frame cleanly popped -> returns to untrusted
    ASSERT_FALSE(ExecutionContext::is_system());
    ASSERT_EQ(ExecutionContext::current_domain(), "untrusted");
}
