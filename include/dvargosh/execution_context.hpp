#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <mutex>

namespace dvargosh {

struct CallFrame {
    std::string module_name;
    std::string domain_name;
    std::string caller_module;
    std::string caller_domain;
    bool is_system = false;
};

/**
 * @brief Thread-local execution context that tracks the currently executing module and domain.
 * Automatically resolves caller/callee domains and detects identity spoofing or domain tampering.
 */
class ExecutionContext {
public:
    static void push_frame(CallFrame frame);
    static void pop_frame();

    static std::string current_domain();
    static std::string current_module();
    static std::string caller_domain();
    static std::string caller_module();
    static bool is_system();

    /**
     * @brief Verifies that claimed_domain matches the real currently executing domain.
     * If tampering is detected, execution is marked compromised.
     * @return Result<void>::success() if authentic, StatusCode::SecurityTampering otherwise.
     */
    static Result<void> verify_not_tampered(const std::string& claimed_domain);

    static size_t frame_depth();
};

/**
 * @brief RAII Guard for managing execution call frames.
 */
class ScopedCallFrame {
public:
    ScopedCallFrame(
        std::string module_name,
        std::string domain_name,
        std::string caller_module = "",
        std::string caller_domain = ""
    ) {
        CallFrame frame;
        frame.module_name = std::move(module_name);
        frame.domain_name = std::move(domain_name);
        frame.caller_module = std::move(caller_module);
        frame.caller_domain = std::move(caller_domain);
        frame.is_system = (frame.domain_name == "system");
        ExecutionContext::push_frame(std::move(frame));
    }

    ~ScopedCallFrame() {
        ExecutionContext::pop_frame();
    }

    ScopedCallFrame(const ScopedCallFrame&) = delete;
    ScopedCallFrame& operator=(const ScopedCallFrame&) = delete;
};

} // namespace dvargosh
