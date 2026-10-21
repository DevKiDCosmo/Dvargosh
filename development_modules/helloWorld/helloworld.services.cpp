#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

// 1. Normal Service Method
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

    // Authorized access: caller domain "captives:vault" accesses its own safe space
    auto space_res = ctx->domain_manager()->get_domain_space("captives:vault", "captives:vault");
    if (!space_res.is_ok()) {
        return "ACCESS_DENIED: " + space_res.error_message();
    }

    char* key_ptr = static_cast<char*>(space_res.value()->raw_base());
    return key_ptr ? std::string(key_ptr) : "EMPTY_KEY";
}

// 3. Unauthorized Cross-Domain Memory Access Attempt
// Function residing in "captives:intruder" domain trying to breach "captives:vault" safe space
DVARGOSH_SERVICE(captives:intruder)
std::string intruder_access_safe_space() {
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx || !ctx->domain_manager()) return "ERROR_NO_CONTEXT";

    // Attempt direct memory access across domain isolation boundary:
    // Domain "captives:intruder" requests the hardware-guarded space of "captives:vault"
    auto space_res = ctx->domain_manager()->get_domain_space("captives:vault", "captives:intruder");
    if (!space_res.is_ok()) {
        // Correctly REJECTED by DomainManager
        return "REJECTED: " + space_res.error_message();
    }

    return "UNEXPECTED_BREACH_SUCCESS";
}

// 4. Unauthorized Cross-Domain RPC Invocation Attempt
// Function in "captives:intruder" domain trying to invoke a service in "captives:vault"
DVARGOSH_SERVICE(captives:intruder)
std::string intruder_invoke_vault() {
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx || !ctx->registry()) return "ERROR_NO_CONTEXT";

    // Attempt RPC call from caller domain "captives:intruder" to target "captives:vault"
    auto res = ctx->registry()->invoke("get_safe_vault_key", {}, "hello_world", "captives:intruder");
    if (!res.is_ok()) {
        // Correctly REJECTED by Registry cross-domain security policy
        return "REJECTED: " + res.error_message();
    }

    return res.value().to_string();
}

// 5. Correct cross-module invocation (explained in docs)
// Replaces the flawed `auto di = std::make_shared<DIContainer>()` with active host context
DVARGOSH_SERVICE(captives:hello_world)
std::string invokeothers() {
    auto* ctx = Runtime::get_context("hello_world");
    if (!ctx) return "Error: No active module context";

    // Correct invocation via host ModuleContext or active Registry
    auto hash_res = ctx->call("demo_pkg_vault_hash", {Value("DvargoshData")});
    return hash_res.is_ok() ? hash_res.value().to_string() : "Error: " + hash_res.error_message();
}

} // namespace dvargosh
