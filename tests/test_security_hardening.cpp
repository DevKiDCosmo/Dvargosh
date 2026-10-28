// Regression tests for the Sprint S1 security remediations (docs/continuation_architecture.md §2.1):
//   C1 — reserved-domain deny-list (module "system" impersonation)
//   C4 — wildcard-target semantics (targets ending ".*" no longer auto-grant access)
//   C5 — alias hijacking (aliases cannot shadow methods nor cross providers)
#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

// ---------------------------------------------------------------------------
// C1: a module declaring domain "system" must be denied a module context.
// ---------------------------------------------------------------------------
namespace {
class SystemDomainModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest m = []() {
            ModuleManifest man;
            man.name = "impersonator";
            man.version = Version{1, 0, 0};
            man.description = "Attempts to claim the reserved system domain";
            man.domain = "system";
            man.requested_permissions = PermissionSet::all();
            return man;
        }();
        return m;
    }
    Result<void> on_load(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }
};
} // namespace

TEST_CASE(test_security_c1_reserved_domain_rejected) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    auto load_res = loader.load_static_module(std::make_unique<SystemDomainModule>());
    ASSERT_FALSE(load_res.is_ok());
    ASSERT_EQ(load_res.status(), StatusCode::SecurityTampering);
    ASSERT_FALSE(loader.is_loaded("impersonator"));
}

TEST_CASE(test_security_c1_reserved_domain_via_context_factory) {
    auto di = std::make_shared<DIContainer>();
    auto ctx_res = di->create_module_context("sneaky", "system", SecurityPolicy::permissive());
    ASSERT_FALSE(ctx_res.is_ok());
    ASSERT_EQ(ctx_res.status(), StatusCode::SecurityTampering);
    // And the sneaky module was never attached to the system domain:
    auto* sys_domain = di->domain_manager()->get_domain("system");
    ASSERT_TRUE(sys_domain != nullptr);
    ASSERT_FALSE(sys_domain->has_module("sneaky"));
}

// ---------------------------------------------------------------------------
// C4: wildcard targets require explicit allow entries.
// ---------------------------------------------------------------------------
TEST_CASE(test_security_c4_wildcard_target_requires_explicit_allow) {
    auto di = std::make_shared<DIContainer>();
    auto dm = di->domain_manager();
    dm->create_domain("alice", SecurityPolicy::standard());
    dm->create_domain("bob", SecurityPolicy::standard());

    // "other.*" is the default scope shape of every auto-registered method.
    // It must NOT be callable by a domain with no explicit allow entry.
    ASSERT_FALSE(dm->check_cross_domain_access("alice", "other.*"));
    ASSERT_FALSE(dm->check_cross_domain_access("alice", "*"));
    ASSERT_FALSE(dm->check_cross_domain_access("alice", "unheard-of-domain"));

    // An explicit allow entry grants exactly that edge (and nothing more).
    ASSERT_TRUE(dm->allow_cross_domain("alice", "other.*").is_ok());
    ASSERT_TRUE(dm->check_cross_domain_access("alice", "other.*"));
    ASSERT_FALSE(dm->check_cross_domain_access("bob", "other.*"));
    ASSERT_FALSE(dm->check_cross_domain_access("alice", "different.*"));

    // Allow-to-all is an explicit host decision, still honored...
    ASSERT_TRUE(dm->allow_cross_domain("bob", "*").is_ok());
    ASSERT_TRUE(dm->check_cross_domain_access("bob", "anything.else"));
    // ...and "system" remains the host's universal caller.
    ASSERT_TRUE(dm->check_cross_domain_access("system", "other.*"));
}

TEST_CASE(test_security_c4_registry_invoke_respects_explicit_edges) {
    auto di = std::make_shared<DIContainer>();
    auto dm = di->domain_manager();
    dm->create_domain("caller_dom", SecurityPolicy::standard());

    auto& reg = *di->registry();
    (void)reg.register_method(
        "scoped.fn", "scoped", "provider", "scoped_provider.*",
        [](const std::vector<Value>&) -> Result<Value> {
            return Result<Value>::success(Value(true));
        },
        nullptr);

    // No edge declared -> denied, even though the target ends in ".*".
    auto denied = reg.invoke("scoped.fn", {}, "c1", "caller_dom", nullptr);
    ASSERT_FALSE(denied.is_ok());
    ASSERT_EQ(denied.status(), StatusCode::PermissionDenied);

    // Host declares the edge -> allowed.
    ASSERT_TRUE(dm->allow_cross_domain("caller_dom", "scoped_provider.*").is_ok());
    auto allowed = reg.invoke("scoped.fn", {}, "c1", "caller_dom", nullptr);
    ASSERT_TRUE(allowed.is_ok());
}

// ---------------------------------------------------------------------------
// C5: aliases cannot shadow methods nor cross providers.
// ---------------------------------------------------------------------------
TEST_CASE(test_security_c5_alias_cannot_shadow_real_method) {
    Registry reg;
    (void)reg.register_method(
        "victim.fn", "victim", "victim_mod", "victim:*",
        [](const std::vector<Value>&) -> Result<Value> {
            return Result<Value>::success(Value("VICTIM"));
        },
        nullptr);
    (void)reg.register_method(
        "attacker.fn", "attack", "attacker_mod", "attacker:*",
        [](const std::vector<Value>&) -> Result<Value> {
            return Result<Value>::success(Value("HIJACKED"));
        },
        nullptr);

    // Register an alias pointing the victim's name at the attacker's method.
    (void)reg.register_alias("victim.fn", "attacker.fn");

    // Method-first resolution: the real method wins, hijack fails.
    auto res = reg.invoke("victim.fn", {}, "c1", "system", nullptr);
    ASSERT_TRUE(res.is_ok());
    ASSERT_EQ(res.value().to_string(), "VICTIM");
}

TEST_CASE(test_security_c5_cross_provider_alias_rejected) {
    Registry reg;
    (void)reg.register_method(
        "victim.fn", "victim", "victim_mod", "victim:*",
        [](const std::vector<Value>&) -> Result<Value> {
            return Result<Value>::success(Value("VICTIM"));
        },
        nullptr);

    auto rejected = reg.register_alias("victim.fn", "victim.fn", "attacker_mod");
    ASSERT_FALSE(rejected.is_ok());
    ASSERT_EQ(rejected.status(), StatusCode::PermissionDenied);

    // Same-provider aliasing (the module.hpp auto-registration pattern) still works.
    auto ok = reg.register_alias("victim.fn", "victim.fn", "victim_mod");
    ASSERT_TRUE(ok.is_ok());
}
