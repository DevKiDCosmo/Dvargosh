#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <memory>
#include <mutex>

namespace dvargosh {

struct SecuredMemoryConfig {
    size_t capacity_bytes = 4 * 1024 * 1024; // 4 MB default
    bool use_guard_pages = true;             // PROT_NONE guard pages at borders
    bool lock_in_ram = false;                // Call mlock() to prevent swapping
    bool scrub_on_destroy = true;            // Overwrite with zeros on deallocation
    std::string container_name = "default";
};

class SecuredMemorySpace {
public:
    static Result<std::unique_ptr<SecuredMemorySpace>> create(
        const SecuredMemoryConfig& config,
        const SecurityPolicy& policy
    );

    ~SecuredMemorySpace();

    // Non-copyable, movable
    SecuredMemorySpace(const SecuredMemorySpace&) = delete;
    SecuredMemorySpace& operator=(const SecuredMemorySpace&) = delete;
    SecuredMemorySpace(SecuredMemorySpace&&) noexcept;
    SecuredMemorySpace& operator=(SecuredMemorySpace&&) noexcept;

    // Sub-allocations within the secured container
    void* allocate(size_t size, size_t alignment = sizeof(void*));
    void  reset(); // Reset internal allocation offset (arena style)

    // Memory info
    size_t capacity() const noexcept { return m_usable_size; }
    size_t used_bytes() const noexcept { return m_used_offset; }
    size_t remaining_bytes() const noexcept { return m_usable_size > m_used_offset ? m_usable_size - m_used_offset : 0; }
    const std::string& name() const noexcept { return m_config.container_name; }

    void* raw_base() noexcept { return m_usable_memory; }
    const void* raw_base() const noexcept { return m_usable_memory; }

    // Manually scrub/zero the memory
    void scrub();

private:
    explicit SecuredMemorySpace(const SecuredMemoryConfig& config);
    Result<void> initialize();

    SecuredMemoryConfig m_config;
    void* m_total_mapped = nullptr;
    size_t m_total_mapped_size = 0;
    void* m_usable_memory = nullptr;
    size_t m_usable_size = 0;
    size_t m_page_size = 4096;
    size_t m_used_offset = 0;
    mutable std::mutex m_mutex;
};

// Top-level factory functions as requested by the user:
// "The functions to init own memory space is needed still."
Result<std::unique_ptr<SecuredMemorySpace>> init_secured_memory_space(
    const std::string& module_name,
    size_t capacity_bytes = 4 * 1024 * 1024,
    bool enable_guard_pages = true
);

Result<std::unique_ptr<SecuredMemorySpace>> init_own_memory_space(
    const std::string& name,
    size_t capacity_bytes = 4 * 1024 * 1024,
    bool enable_guard_pages = true,
    bool lock_in_ram = false,
    bool scrub_on_destroy = true
);

} // namespace dvargosh
