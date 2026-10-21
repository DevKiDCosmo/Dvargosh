#include "dvargosh/execution_context.hpp"
#include "dvargosh/logger.hpp"

namespace dvargosh {

static thread_local std::vector<CallFrame> t_call_stack;

void ExecutionContext::push_frame(CallFrame frame) {
    t_call_stack.push_back(std::move(frame));
}

void ExecutionContext::pop_frame() {
    if (!t_call_stack.empty()) {
        t_call_stack.pop_back();
    }
}

std::string ExecutionContext::current_domain() {
    if (t_call_stack.empty()) return "system";
    return t_call_stack.back().domain_name;
}

std::string ExecutionContext::current_module() {
    if (t_call_stack.empty()) return "system";
    return t_call_stack.back().module_name;
}

std::string ExecutionContext::caller_domain() {
    if (t_call_stack.empty()) return "system";
    return t_call_stack.back().caller_domain;
}

std::string ExecutionContext::caller_module() {
    if (t_call_stack.empty()) return "system";
    return t_call_stack.back().caller_module;
}

bool ExecutionContext::is_system() {
    if (t_call_stack.empty()) return true;
    return t_call_stack.back().is_system;
}

Result<void> ExecutionContext::verify_not_tampered(const std::string& claimed_domain) {
    if (claimed_domain.empty() || claimed_domain == "*") {
        return Result<void>::success();
    }
    std::string actual = current_domain();
    if (actual == "system") {
        // System caller holds universal privilege
        return Result<void>::success();
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
