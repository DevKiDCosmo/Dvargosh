#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include <iostream>

using namespace dvargosh;

/**
 * =========================================================================================
 * TEST SUITE: SubContext Isolation & Multi-Tier Access Control Matrix
 * =========================================================================================
 * Validates:
 * 1. SubContext creation (fixed memory size vs dynamic).
 * 2. Multi-domain attachment to a single SubContext room space.
 * 3. Unique cryptographic HMAC-SHA256 tracking token generation and collision avoidance.
 * 4. Strictly unidirectional intra-module cross-domain access (A -> B != B -> A).
 * 5. Inter-module coarse grants (allow_cross_module).
 * 6. Inter-module fine-grained grants (allow_cross_module_specific).
 * 7. Ingress control (allow_access_to, allow_access_to_specific, allow_all_income).
 * 8. Open Wildcards (services in '*' are open to all callers).
 * 9. Anti-hijacking (Runtime::get_context rejects foreign callers, current_subcontext succeeds).
 * =========================================================================================
 */

TEST_CASE(test_subcontext_creation_and_domain_attachment) {
    auto di = std::make_shared<DIContainer>();
    auto ctx_res = di->create_module_context("mod_alpha", "alpha_root", SecurityPolicy::permissive(), 128 * 1024);
    ASSERT_TRUE(ctx_res.is_ok());
    auto ctx = std::move(ctx_res.value());

    // 1. Explicit creation of a SubContext room space with fixed secured memory
    auto sub1_res = ctx->create_subcontext("vault_room", 32 * 1024, true);
    ASSERT_TRUE(sub1_res.is_ok());
    SubContext* sub1 = sub1_res.value();
    ASSERT_EQ(sub1->name(), "vault_room");
    ASSERT_EQ(sub1->module_name(), "mod_alpha");
    ASSERT_FALSE(sub1->is_dynamic());
    ASSERT_TRUE(sub1->secured_memory() != nullptr);

    // 2. Explicit creation of a dynamic SubContext room space (capacity = 0)
    auto sub2_res = ctx->create_subcontext("worker_room", 0);
    ASSERT_TRUE(sub2_res.is_ok());
    SubContext* sub2 = sub2_res.value();
    ASSERT_EQ(sub2->name(), "worker_room");
    ASSERT_TRUE(sub2->is_dynamic());
    ASSERT_TRUE(sub2->secured_memory() == nullptr);

    // 3. Attach multiple domains to subcontext 1
    ASSERT_TRUE(sub1->attach_domain("captives:vault").is_ok());
    ASSERT_TRUE(sub1->attach_domain("captives:keys").is_ok());
    ASSERT_TRUE(sub1->has_domain("captives:vault"));
    ASSERT_TRUE(sub1->has_domain("captives:keys"));
    ASSERT_FALSE(sub1->has_domain("captives:worker"));

    // 4. Attach domain to subcontext 2
    ASSERT_TRUE(sub2->attach_domain("captives:worker").is_ok());
    ASSERT_TRUE(sub2->has_domain("captives:worker"));

    // 5. Query subcontext for domain from ModuleContext
    ASSERT_EQ(ctx->get_subcontext_for_domain("captives:vault"), sub1);
    ASSERT_EQ(ctx->get_subcontext_for_domain("captives:keys"), sub1);
    ASSERT_EQ(ctx->get_subcontext_for_domain("captives:worker"), sub2);
}

TEST_CASE(test_subcontext_cryptographic_tracking_hash_anti_collision) {
    auto di = std::make_shared<DIContainer>();
    auto ctx1_res = di->create_module_context("module_one", "root", SecurityPolicy::standard());
    auto ctx2_res = di->create_module_context("module_two", "root", SecurityPolicy::standard());
    auto ctx1 = std::move(ctx1_res.value());
    auto ctx2 = std::move(ctx2_res.value());

    // Both modules create a subcontext with the same local name "storage"
    auto s1_res = ctx1->create_subcontext("storage", 0);
    auto s2_res = ctx2->create_subcontext("storage", 0);
    ASSERT_TRUE(s1_res.is_ok());
    ASSERT_TRUE(s2_res.is_ok());

    SubContext* s1 = s1_res.value();
    SubContext* s2 = s2_res.value();

    // Verify both have valid 64-character hex HMAC-SHA256 hashes
    ASSERT_EQ(s1->hash().length(), 64);
    ASSERT_EQ(s2->hash().length(), 64);

    // Anti-collision: identical local names in different modules MUST yield distinct hashes
    ASSERT_NE(s1->hash(), s2->hash());

    // Global lookup by hash via Runtime
    ASSERT_EQ(Runtime::get_subcontext_by_hash(s1->hash()), s1);
    ASSERT_EQ(Runtime::get_subcontext_by_hash(s2->hash()), s2);
}

TEST_CASE(test_unidirectional_intra_module_isolation) {
    DomainManager dm;
    dm.create_domain("value", SecurityPolicy::standard());
    dm.create_domain("core", SecurityPolicy::standard());

    // Before any grant, intra-module access between different domains is DENIED
    ASSERT_FALSE(dm.check_execution_access("mod_test", "value", "mod_test", "core"));
    ASSERT_FALSE(dm.check_execution_access("mod_test", "core", "mod_test", "value"));

    // Grant unidirectional intra-module access from "value" to "core"
    auto grant_res = dm.allow_cross_domain("value", "core");
    ASSERT_TRUE(grant_res.is_ok());

    // "value" calling "core" MUST be ALLOWED
    ASSERT_TRUE(dm.check_execution_access("mod_test", "value", "mod_test", "core"));

    // UNIDIRECTIONAL: "core" calling "value" MUST STILL BE DENIED!
    ASSERT_FALSE(dm.check_execution_access("mod_test", "core", "mod_test", "value"));

    // Same domain calling itself is always allowed
    ASSERT_TRUE(dm.check_execution_access("mod_test", "value", "mod_test", "value"));
    ASSERT_TRUE(dm.check_execution_access("mod_test", "core", "mod_test", "core"));
}

TEST_CASE(test_inter_module_coarse_and_specific_grants) {
    DomainManager dm;
    dm.create_domain("client_dom", SecurityPolicy::standard());
    dm.create_domain("server_api", SecurityPolicy::standard());
    dm.create_domain("server_admin", SecurityPolicy::strict());

    // Without grants, cross-module calls between mod_client and mod_server are DENIED
    ASSERT_FALSE(dm.check_execution_access("mod_client", "client_dom", "mod_server", "server_api"));
    ASSERT_FALSE(dm.check_execution_access("mod_client", "client_dom", "mod_server", "server_admin"));

    // 1. Fine-grained grant: allow mod_client:client_dom to access ONLY server_api in mod_server
    auto spec_res = dm.allow_cross_module_specific("client_dom", "server_api", "mod_server");
    ASSERT_TRUE(spec_res.is_ok());

    // server_api is now accessible
    ASSERT_TRUE(dm.check_execution_access("mod_client", "client_dom", "mod_server", "server_api"));

    // server_admin MUST STILL BE DENIED!
    ASSERT_FALSE(dm.check_execution_access("mod_client", "client_dom", "mod_server", "server_admin"));

    // 2. Coarse-grained grant: allow_cross_module
    DomainManager dm2;
    dm2.allow_cross_module("client_dom", "mod_server");
    ASSERT_TRUE(dm2.check_execution_access("mod_client", "client_dom", "mod_server", "server_api"));
    ASSERT_TRUE(dm2.check_execution_access("mod_client", "client_dom", "mod_server", "server_admin"));
}

TEST_CASE(test_ingress_control_and_wildcard_openness) {
    DomainManager dm;

    // 1. Wildcards are open by default: no allow needed
    ASSERT_TRUE(dm.check_execution_access("mod_any", "dom_any", "mod_target", "*"));
    ASSERT_TRUE(dm.check_execution_access("mod_any", "dom_any", "mod_target", "mod_target.*"));

    // 2. Non-wildcard is blocked without ingress or egress grants
    ASSERT_FALSE(dm.check_execution_access("mod_caller", "dom_caller", "mod_target", "dom_target"));

    // 3. Test allow_all_income: opens target to all incoming callers
    dm.allow_all_income();
    ASSERT_TRUE(dm.check_execution_access("mod_caller", "dom_caller", "mod_target", "dom_target"));

    // 4. Test targeted ingress: allow_access_to
    DomainManager dm2;
    dm2.allow_access_to("trusted_module");
    ASSERT_TRUE(dm2.check_execution_access("trusted_module", "any_domain", "mod_target", "dom_target"));
    ASSERT_FALSE(dm2.check_execution_access("untrusted_module", "any_domain", "mod_target", "dom_target"));

    // 5. Test specific ingress: allow_access_to_specific
    DomainManager dm3;
    dm3.allow_access_to_specific("trusted_domain", "trusted_module");
    ASSERT_TRUE(dm3.check_execution_access("trusted_module", "trusted_domain", "mod_target", "dom_target"));
    ASSERT_FALSE(dm3.check_execution_access("trusted_module", "other_domain", "mod_target", "dom_target"));
}

TEST_CASE(test_runtime_anti_hijacking_and_current_subcontext) {
    auto di = std::make_shared<DIContainer>();
    auto ctx1_res = di->create_module_context("victim_module", "victim_dom", SecurityPolicy::standard());
    auto ctx2_res = di->create_module_context("attacker_module", "attacker_dom", SecurityPolicy::standard());
    auto ctx1 = std::move(ctx1_res.value());
    auto ctx2 = std::move(ctx2_res.value());

    Runtime::register_module_context("victim_module", ctx1.get());
    Runtime::register_module_context("attacker_module", ctx2.get());

    // Create subcontext for victim
    auto sub_res = ctx1->create_subcontext("victim_safe_room", 16 * 1024);
    ASSERT_TRUE(sub_res.is_ok());
    sub_res.value()->attach_domain("victim_dom");

    // Execute within frame of attacker_module
    {
        ScopedCallFrame frame("attacker_module", "attacker_dom");

        // 1. Attacker attempts to fetch victim's ModuleContext via Runtime::get_context
        ModuleContext* hijacked_ctx = Runtime::get_context("victim_module");
        // MUST BE REJECTED (nullptr) to prevent context hijacking!
        ASSERT_EQ(hijacked_ctx, nullptr);

        // 2. Zero-parameter Runtime::get_context() automatically and safely returns attacker's own context
        ModuleContext* zero_param_ctx = Runtime::get_context();
        ASSERT_EQ(zero_param_ctx, ctx2.get());

        // 3. Attacker calling its own context explicitly also succeeds
        ModuleContext* own_ctx = Runtime::get_context("attacker_module");
        ASSERT_EQ(own_ctx, ctx2.get());

        // 4. Runtime::current_context automatically returns attacker's context
        ASSERT_EQ(Runtime::current_context(), ctx2.get());

        // 5. Runtime::current_subcontext automatically returns attacker's subcontext
        SubContext* own_sub = Runtime::current_subcontext();
        ASSERT_TRUE(own_sub != nullptr);
        ASSERT_EQ(own_sub->module_name(), "attacker_module");
    }

    // Clean up
    Runtime::unregister_module_context("victim_module");
    Runtime::unregister_module_context("attacker_module");
}
