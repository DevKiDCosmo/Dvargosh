#pragma once

#include "types.hpp"
#include "secured_memory.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <string>

namespace dvargosh {

class IAllocator {
public:
    virtual ~IAllocator() = default;
    virtual void* allocate(size_t size, size_t alignment = alignof(std::max_align_t)) = 0;
    virtual void* reallocate(void* ptr, size_t old_size, size_t new_size, size_t alignment = alignof(std::max_align_t)) = 0;
    virtual void  deallocate(void* ptr, size_t size = 0) = 0;
};

// Standard Heap Allocator
class SystemAllocator : public IAllocator {
public:
    static SystemAllocator& instance();
    void* allocate(size_t size, size_t alignment = alignof(std::max_align_t)) override;
    void* reallocate(void* ptr, size_t old_size, size_t new_size, size_t alignment = alignof(std::max_align_t)) override;
    void  deallocate(void* ptr, size_t size = 0) override;
};

// Tracked Allocator - Leak Detector & Memory Accounting
struct MemoryStats {
    size_t current_allocated_bytes = 0;
    size_t peak_allocated_bytes = 0;
    size_t total_allocations = 0;
    size_t total_deallocations = 0;
    size_t active_allocations = 0;
};

class TrackedAllocator : public IAllocator {
public:
    explicit TrackedAllocator(IAllocator* upstream = nullptr, std::string tag = "general");
    ~TrackedAllocator() override = default;

    void* allocate(size_t size, size_t alignment = alignof(std::max_align_t)) override;
    void* reallocate(void* ptr, size_t old_size, size_t new_size, size_t alignment = alignof(std::max_align_t)) override;
    void  deallocate(void* ptr, size_t size = 0) override;

    MemoryStats get_stats() const;
    void dump_report(const std::string& title = "") const;
    bool has_leaks() const;
    const std::string& tag() const { return m_tag; }

    void set_max_capacity(size_t max_bytes) noexcept { m_max_capacity_bytes = max_bytes; }
    size_t max_capacity() const noexcept { return m_max_capacity_bytes; }
    size_t allocated_bytes() const noexcept { return get_stats().current_allocated_bytes; }

private:
    IAllocator* m_upstream;
    std::string m_tag;
    size_t m_max_capacity_bytes = 0; // 0 = unlimited
    mutable std::mutex m_mutex;
    MemoryStats m_stats;
    std::unordered_map<void*, size_t> m_active_records;
};

// Arena / Bump Allocator
class ArenaAllocator : public IAllocator {
public:
    explicit ArenaAllocator(size_t chunk_size = 64 * 1024, IAllocator* upstream = nullptr);
    ~ArenaAllocator() override;

    void* allocate(size_t size, size_t alignment = alignof(std::max_align_t)) override;
    void* reallocate(void* ptr, size_t old_size, size_t new_size, size_t alignment = alignof(std::max_align_t)) override;
    void  deallocate(void* ptr, size_t size = 0) override;

    void reset();
    size_t total_allocated() const noexcept { return m_total_allocated; }

private:
    struct Chunk {
        uint8_t* memory;
        size_t capacity;
        size_t offset;
        Chunk* next;
    };

    IAllocator* m_upstream;
    size_t m_chunk_size;
    Chunk* m_head = nullptr;
    size_t m_total_allocated = 0;
    std::mutex m_mutex;

    Chunk* allocate_chunk(size_t min_capacity);
};

// Secured Container Allocator (adapts SecuredMemorySpace to IAllocator)
class SecuredContainerAllocator : public IAllocator {
public:
    explicit SecuredContainerAllocator(SecuredMemorySpace* space) : m_space(space) {}

    void* allocate(size_t size, size_t alignment = alignof(std::max_align_t)) override {
        if (!m_space) return nullptr;
        return m_space->allocate(size, alignment);
    }

    void* reallocate(void* ptr, size_t old_size, size_t new_size, size_t alignment = alignof(std::max_align_t)) override {
        void* new_ptr = allocate(new_size, alignment);
        if (new_ptr && ptr) {
            size_t copy_len = old_size < new_size ? old_size : new_size;
            std::memcpy(new_ptr, ptr, copy_len);
        }
        return new_ptr;
    }

    void deallocate(void* /*ptr*/, size_t /*size*/) override {
        // Linear arena inside secured memory space resets en masse
    }

    void reset() {
        if (m_space) m_space->reset();
    }

private:
    SecuredMemorySpace* m_space;
};

} // namespace dvargosh
