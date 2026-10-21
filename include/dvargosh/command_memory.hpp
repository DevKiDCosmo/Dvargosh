#pragma once

#include "types.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace dvargosh {

/**
 * @brief Scoped scratchpad memory container tied to a command execution frame.
 * 
 * Provides:
 * 1. Fast O(1) bump-pointer sub-allocation within a dedicated command memory page.
 * 2. Guaranteed zero-leak memory lifecycle: memory is automatically volatile-scrubbed
 *    and unmapped upon command completion.
 * 3. Command boundary isolation: intermediate computation artifacts, sensitive keys,
 *    or payloads cannot leak to subsequent commands.
 */
class CommandMemory {
public:
    explicit CommandMemory(size_t capacity_bytes = 64 * 1024);
    ~CommandMemory();

    CommandMemory(const CommandMemory&) = delete;
    CommandMemory& operator=(const CommandMemory&) = delete;

    CommandMemory(CommandMemory&& other) noexcept;
    CommandMemory& operator=(CommandMemory&& other) noexcept;

    /**
     * @brief Allocates a scratchpad memory block of the specified size and alignment.
     * @param size Number of bytes to allocate.
     * @param alignment Byte alignment boundary (default: 8).
     * @return Pointer to allocated memory, or nullptr if command capacity is exceeded.
     */
    void* allocate(size_t size, size_t alignment = 8);

    /**
     * @brief Volatile-zeros used memory and rewinds the allocation offset to 0.
     */
    void reset();

    /**
     * @brief Volatile-zeros the entire memory page.
     */
    void scrub();

    size_t capacity() const noexcept { return m_capacity; }
    size_t used_bytes() const noexcept { return m_used_offset; }
    size_t remaining_bytes() const noexcept { return (m_capacity > m_used_offset) ? (m_capacity - m_used_offset) : 0; }
    size_t allocation_count() const noexcept { return m_alloc_count; }
    void* raw_base() noexcept { return m_buffer; }
    const void* raw_base() const noexcept { return m_buffer; }

private:
    uint8_t* m_buffer = nullptr;
    size_t m_capacity = 0;
    size_t m_used_offset = 0;
    size_t m_alloc_count = 0;
    bool m_mapped = false;
    mutable std::mutex m_mutex;
};

} // namespace dvargosh
