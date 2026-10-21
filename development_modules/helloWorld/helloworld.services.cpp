#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

DVARGOSH_SERVICE(captives:hello_world)
std::string hello_world(const std::string& input) {
    return "HELLO_WORLD_" + input;
}

// 2. Safe Space Authorized Accessor
// Function residing inside the protected "captives:vault" domain
DVARGOSH_SERVICE(captives:vault)
std::string get_safe_vault_key() {
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx || !ctx->domain_manager()) return "ERROR_NO_CONTEXT";

    // 1. Explicit domain security check: verify caller is neither blacklisted nor unauthorized
    std::string caller = ExecutionContext::current_domain();
    if (ctx->domain_manager()->is_cross_domain_blacklisted(caller, "captives:vault")) {
        return "ACCESS_DENIED: Calling domain '" + caller + "' is explicitly blacklisted";
    }

    // 2. Authorized access: caller domain is automatically resolved as ExecutionContext::current_domain()
    // and verified by get_domain_vault() using the permission matrix (blacklist + whitelist)
    auto vault_res = ctx->domain_manager()->get_domain_vault("captives:vault", "captives_vault");
    if (!vault_res.is_ok()) {
        return "ACCESS_DENIED: " + vault_res.error_message();
    }

    auto secret_res = vault_res.value()->read_secret("ROOT_KEY");
    if (!secret_res.is_ok()) {
        return "READ_FAILED: " + secret_res.error_message();
    }

    return secret_res.value();
}

// 3. Unauthorized Cross-Domain Memory / Vault Access Attempt
// Function residing in "captives:intruder" domain trying to breach "captives:vault"
DVARGOSH_SERVICE(captives:intruder)
std::string intruder_access_safe_space() {
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx || !ctx->domain_manager()) return "ERROR_NO_CONTEXT";

    // Executing domain is automatically resolved as "captives:intruder"
    // Attempting cross-domain vault access without permissions is rejected
    auto vault_res = ctx->domain_manager()->get_domain_vault("captives:vault", "captives_vault");
    if (!vault_res.is_ok()) {
        return "REJECTED: " + vault_res.error_message();
    }

    auto secret_res = vault_res.value()->read_secret("ROOT_KEY");
    if (!secret_res.is_ok()) {
        return "REJECTED: " + secret_res.error_message();
    }

    return "UNEXPECTED_BREACH_SUCCESS";
}

// 4. Domain Spoofing / Tampering Attempt
// Intruder attempts to falsify caller domain identity to bypass security
DVARGOSH_SERVICE(captives:intruder)
std::string intruder_tamper_attempt() {
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx || !ctx->domain_manager()) return "ERROR_NO_CONTEXT";

    // Executing frame is "captives:intruder", but intruder attempts to pass "captives:vault"
    auto spoof_res = ctx->domain_manager()->get_domain_space("captives:vault", "captives:vault");
    if (!spoof_res.is_ok()) {
        return "TAMPER_DETECTED: " + spoof_res.error_message();
    }

    return "TAMPER_UNNOTICED_FAILURE";
}

// 5. Unauthorized Cross-Domain RPC Invocation Attempt
// Function in "captives:intruder" domain trying to invoke a service in "captives:vault"
DVARGOSH_SERVICE(captives:intruder)
std::string intruder_invoke_vault() {
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx || !ctx->registry()) return "ERROR_NO_CONTEXT";

    // Attempt RPC call from executing domain "captives:intruder" to target "captives:vault"
    auto res = ctx->call("hello_world.get_safe_vault_key", {});
    if (!res.is_ok()) {
        return "REJECTED: " + res.error_message();
    }

    return res.value().to_string();
}

// 6. Correct cross-module invocation via host context
DVARGOSH_SERVICE(captives:hello_world)
std::string invokeothers() {
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx) return "Error: No active module context";

    auto hash_res = ctx->call("demo_pkg.demo_pkg_vault_hash", {Value("DvargoshData")});
    return hash_res.is_ok() ? hash_res.value().to_string() : "Error: " + hash_res.error_message();
}

extern void* just_true();
DVARGOSH_EXPORT_FN(just_true, "value", "JUST TRUE") {
    return Result<Value>::success(Value(true));
}

} // namespace dvargosh
