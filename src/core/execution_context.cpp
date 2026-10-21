#include "dvargosh/execution_context.hpp"
#include "dvargosh/crypto.hpp"
#include "dvargosh/logger.hpp"

namespace dvargosh {

static thread_local std::vector<CallFrame> t_call_stack;
static const std::string s_stack_salt = "dvargosh_stack_internal_salt_918273";

static std::string compute_frame_token(const CallFrame& f, size_t depth) {
    std::string payload = f.module_name + "|" + f.domain_name + "|" + f.caller_module + "|" +
                          f.caller_domain + "|" + std::to_string(depth) + "|" + (f.is_system ? "SYS" : "USR");
    return Crypto::hmac_sha256_hex(s_stack_salt, payload);
}

void ExecutionContext::push_frame(CallFrame frame) {
    size_t depth = t_call_stack.size();
    frame.token = compute_frame_token(frame, depth);
    t_call_stack.push_back(std::move(frame));
}

void ExecutionContext::pop_frame() {
    if (!t_call_stack.empty()) {
        auto check = validate_stack_integrity();
        if (!check.is_ok()) {
            log_error("ExecutionContext::pop_frame detected stack corruption! Purging compromised stack.");
            t_call_stack.clear();
            return;
        }
        t_call_stack.pop_back();
    }
}

Result<void> ExecutionContext::validate_stack_integrity() {
    for (size_t i = 0; i < t_call_stack.size(); ++i) {
        std::string expected = compute_frame_token(t_call_stack[i], i);
        if (t_call_stack[i].token != expected) {
            log_error("CRITICAL TAMPER ALERT: Call stack internal mutation detected at depth ", i,
                      "! Memory tampering detected for module '", t_call_stack[i].module_name,
                      "', domain '", t_call_stack[i].domain_name, "'.");
            return Result<void>::failure(
                StatusCode::SecurityTampering,
                "Security Tampering Violation: Execution stack internal memory mutation detected at depth " +
                std::to_string(i) + "! Aborting execution."
            );
        }
    }
    return Result<void>::success();
}

std::string ExecutionContext::current_domain() {
    if (t_call_stack.empty()) return "untrusted";
    auto val = validate_stack_integrity();
    if (!val.is_ok()) return "__COMPROMISED__";
    return t_call_stack.back().domain_name;
}

std::string ExecutionContext::current_module() {
    if (t_call_stack.empty()) return "untrusted";
    auto val = validate_stack_integrity();
    if (!val.is_ok()) return "__COMPROMISED__";
    return t_call_stack.back().module_name;
}

std::string ExecutionContext::caller_domain() {
    if (t_call_stack.empty()) return "untrusted";
    auto val = validate_stack_integrity();
    if (!val.is_ok()) return "__COMPROMISED__";
    return t_call_stack.back().caller_domain;
}

std::string ExecutionContext::caller_module() {
    if (t_call_stack.empty()) return "untrusted";
    auto val = validate_stack_integrity();
    if (!val.is_ok()) return "__COMPROMISED__";
    return t_call_stack.back().caller_module;
}

bool ExecutionContext::is_system() {
    if (t_call_stack.empty()) return false;
    auto val = validate_stack_integrity();
    if (!val.is_ok()) return false;
    return t_call_stack.back().is_system;
}

void* ExecutionContext::allocate_command_memory(size_t size, size_t alignment) {
    if (t_call_stack.empty()) return nullptr;
    auto val = validate_stack_integrity();
    if (!val.is_ok()) return nullptr;

    auto& mem = t_call_stack.back().command_memory;
    if (!mem) {
        mem = std::make_shared<CommandMemory>(64 * 1024);
    }
    return mem->allocate(size, alignment);
}

CommandMemory* ExecutionContext::current_command_memory() {
    if (t_call_stack.empty()) return nullptr;
    auto val = validate_stack_integrity();
    if (!val.is_ok()) return nullptr;
    return t_call_stack.back().command_memory.get();
}

size_t ExecutionContext::command_memory_used() {
    auto* mem = current_command_memory();
    return mem ? mem->used_bytes() : 0;
}

size_t ExecutionContext::command_memory_capacity() {
    auto* mem = current_command_memory();
    return mem ? mem->capacity() : 0;
}

Result<void> ExecutionContext::verify_not_tampered(const std::string& claimed_domain) {
    auto val = validate_stack_integrity();
    if (!val.is_ok()) {
        return val;
    }
    if (t_call_stack.empty() || claimed_domain.empty()) {
        return Result<void>::success();
    }
    std::string actual = current_domain();
    if (actual == "system") {
        // System caller holds universal privilege
        return Result<void>::success();
    }
    if (claimed_domain == "*") {
        log_error("CRITICAL SECURITY VIOLATION: Non-system domain '", actual,
                  "' attempted to claim wildcard domain '*'.");
        return Result<void>::failure(
            StatusCode::SecurityTampering,
            "Security Violation: Non-system domain '" + actual + "' attempted to claim wildcard '*'"
        );
    }
    if (actual != claimed_domain) {
        log_error("CRITICAL SECURITY VIOLATION: Execution domain tampering detected! Current domain '",
                  actual, "' attempted to impersonate '", claimed_domain, "'.");
        return Result<void>::failure(
            StatusCode::SecurityTampering,
            "Security Violation: Tampered domain execution detected! Claimed '" + claimed_domain +
            "' but executing frame belongs to domain '" + actual + "'."
        );
    }
    return Result<void>::success();
}

size_t ExecutionContext::frame_depth() {
    return t_call_stack.size();
}

} // namespace dvargosh
