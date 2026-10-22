#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <memory>
#include <mutex>

namespace dvargosh {

/**
 * @brief Configuration parameters for initializing an isolated, hardware-guarded memory container.
 */
struct SecuredMemoryConfig {
    /** @brief Usable allocation capacity in bytes (page-aligned up to the host page size). Default: 4 MB. */
    size_t capacity_bytes = 4 * 1024 * 1024;

    /** @brief If true, places leading and trailing PROT_NONE guard pages around usable memory. */
    bool use_guard_pages = true;

    /** @brief If true, invokes mlock() to pin pages in physical RAM and prevent paging to swap. */
    bool lock_in_ram = false;

    /** @brief If true, performs volatile zero-scrubbing upon deallocation or container destruction. */
    bool scrub_on_destroy = true;

    /** @brief Human-readable identifier for memory tracking, telemetry, and quota auditing. */
    std::string container_name = "default";
};

/**
 * @brief In-Process Memory Container with Hardware Guard Pages and Volatile Sanitization.
 *
 * Provides page-aligned memory isolation using OS-level virtual memory primitives (`mmap`, `mprotect`, `mlock`).
 *
 * ### Architectural Guarantees:
 * 1. **Hardware Guard Pages:** The allocated space is bounded by leading and trailing `PROT_NONE` guard
 *    pages. Any read, write, or out-of-bounds pointer arithmetic into these pages immediately triggers
 *    a CPU hardware fault (`SIGSEGV`), preventing buffer overrun/underrun into adjacent memory.
 * 2. **Physical Page Pinning:** Critical cryptographic workspaces can be pinned in physical RAM via `mlock()`,
 *    preventing the kernel from writing sensitive keys or states to persistent disk swap files.
 * 3. **Volatile Scrubbing:** Upon release or container destruction, all memory is wiped using volatile
 *    zero-fill operations (`explicit_bzero` / volatile memory barrier) to defeat cold-boot attacks and
 *    dangling pointer inspection.
 * 4. **Linear Arena Sub-Allocation:** Internal thread-safe bump allocator with strict quota enforcement.
 */
class SecuredMemorySpace {
public:
    /**
     * @brief Factory method creating an isolated secured memory space with security policy validation.
     * @param config The memory container configuration parameters.
     * @param policy The security policy governing memory allocation privileges.
     * @return Result containing unique_ptr to the initialized SecuredMemorySpace, or StatusCode::PermissionDenied.
     */
    static Result<std::unique_ptr<SecuredMemorySpace>> create(
        const SecuredMemoryConfig& config,
        const SecurityPolicy& policy
    );

    /**
     * @brief Destructor. Automatically scrubs usable memory and unmaps guard pages and allocated regions.
     */
    ~SecuredMemorySpace();

    SecuredMemorySpace(const SecuredMemorySpace&) = delete;
    SecuredMemorySpace& operator=(const SecuredMemorySpace&) = delete;
    SecuredMemorySpace(SecuredMemorySpace&&) noexcept;
    SecuredMemorySpace& operator=(SecuredMemorySpace&&) noexcept;

    /**
     * @brief Allocates a contiguous memory block from within the secured container.
     * @param size Size in bytes to allocate.
     * @param alignment Byte alignment boundary (must be power of two, defaults to sizeof(void*)).
     * @return Raw pointer to allocated memory block, or nullptr if container quota is exceeded.
     */
    void* allocate(size_t size, size_t alignment = sizeof(void*));

    /**
     * @brief Resets the internal arena allocation offset to zero without releasing mapped virtual memory.
     * Scrubbing is automatically performed over previously allocated regions.
     */
    void  reset();

    /** @brief Returns total usable memory capacity in bytes. */
    size_t capacity() const noexcept { return m_usable_size; }

    /** @brief Returns total allocated bytes currently occupied. */
    size_t used_bytes() const noexcept { return m_used_offset; }

    /** @brief Returns remaining bytes available for sub-allocation. */
    size_t remaining_bytes() const noexcept { return m_usable_size > m_used_offset ? m_usable_size - m_used_offset : 0; }

    /** @brief Returns the container's registered name. */
    const std::string& name() const noexcept { return m_config.container_name; }

    /** @brief Returns whether hardware PROT_NONE guard pages are enabled. */
    bool is_guard_pages_enabled() const noexcept { return m_config.use_guard_pages; }

    /** @brief Returns configuration parameters of the container. */
    const SecuredMemoryConfig& config() const noexcept { return m_config; }

    /** @brief Returns the base pointer of the usable memory region. */
    void* raw_base() noexcept { return m_usable_memory; }
    const void* raw_base() const noexcept { return m_usable_memory; }

    /**
     * @brief Performs immediate volatile zero-scrubbing across the entire usable memory space.
     */
    void scrub();

    /**
     * @brief Explicitly unloads, sanitizes, and releases the secured memory space and hardware guard pages.
     */
    void unload();

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

/**
 * @brief Initializes a secured memory container assigned to a specific module.
 * @param module_name Name of the module owning the container.
 * @param capacity_bytes Usable capacity in bytes.
 * @param enable_guard_pages Whether to place hardware PROT_NONE guard pages at borders.
 * @return Result containing the initialized memory space, or error status.
 */
Result<std::unique_ptr<SecuredMemorySpace>> init_secured_memory_space(
    const std::string& module_name,
    size_t capacity_bytes = 4 * 1024 * 1024,
    bool enable_guard_pages = true
);

/**
 * @brief Initializes an autonomous secured memory space with custom isolation parameters.
 * @param name Custom container identifier.
 * @param capacity_bytes Usable capacity in bytes.
 * @param enable_guard_pages Whether to place hardware PROT_NONE guard pages at borders.
 * @param lock_in_ram Whether to pin pages into physical RAM with mlock().
 * @param scrub_on_destroy Whether to sanitize memory on teardown.
 * @return Result containing the initialized memory space, or error status.
 */
Result<std::unique_ptr<SecuredMemorySpace>> init_own_memory_space(
    const std::string& name,
    size_t capacity_bytes = 4 * 1024 * 1024,
    bool enable_guard_pages = true,
    bool lock_in_ram = false,
    bool scrub_on_destroy = true
);

} // namespace dvargosh
