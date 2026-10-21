#pragma once

#include "types.hpp"
#include "command_memory.hpp"
#include <string>
#include <vector>
#include <mutex>
#include <memory>

namespace dvargosh {

struct CallFrame {
    std::string module_name;
    std::string domain_name;
    std::string caller_module;
    std::string caller_domain;
    bool is_system = false;
    std::string token;
    std::shared_ptr<CommandMemory> command_memory;
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
     * @brief Allocates scratchpad memory within the active command's execution frame.
     * Automatically volatile-scrubbed and unmapped upon command completion.
     */
    static void* allocate_command_memory(size_t size, size_t alignment = 8);

    /**
     * @brief Retrieves pointer to the active command's scratchpad memory container.
     */
    static CommandMemory* current_command_memory();

    static size_t command_memory_used();
    static size_t command_memory_capacity();

    /**
     * @brief Cryptographically validates that thread-local frames have not been tampered with or modified in memory.
     * @return Result<void>::success() if authentic, StatusCode::SecurityTampering if corrupted.
     */
    static Result<void> validate_stack_integrity();

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
        std::string caller_domain = "",
        size_t command_memory_bytes = 64 * 1024
    ) {
        CallFrame frame;
        frame.module_name = std::move(module_name);
        frame.domain_name = std::move(domain_name);
        frame.caller_module = std::move(caller_module);
        frame.caller_domain = std::move(caller_domain);
        frame.is_system = (frame.domain_name == "system");
        if (command_memory_bytes > 0) {
            frame.command_memory = std::make_shared<CommandMemory>(command_memory_bytes);
        }
        ExecutionContext::push_frame(std::move(frame));
    }

    ~ScopedCallFrame() {
        ExecutionContext::pop_frame();
    }

    ScopedCallFrame(const ScopedCallFrame&) = delete;
    ScopedCallFrame& operator=(const ScopedCallFrame&) = delete;
};

} // namespace dvargosh
