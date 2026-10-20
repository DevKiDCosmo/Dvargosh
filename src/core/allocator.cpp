#include "dvargosh/allocator.hpp"
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>

namespace dvargosh {

/* ========================================================================= */
/* SystemAllocator                                                           */
/* ========================================================================= */

SystemAllocator& SystemAllocator::instance() {
    static SystemAllocator s_inst;
    return s_inst;
}

void* SystemAllocator::allocate(size_t size, size_t alignment) {
    if (size == 0) return nullptr;
    void* ptr = nullptr;
    if (alignment <= sizeof(void*)) {
        ptr = std::malloc(size);
    } else {
        if (posix_memalign(&ptr, alignment, size) != 0) {
            return nullptr;
        }
    }
    return ptr;
}

void* SystemAllocator::reallocate(void* ptr, size_t /*old_size*/, size_t new_size, size_t alignment) {
    if (!ptr) return allocate(new_size, alignment);
    if (new_size == 0) {
        deallocate(ptr);
        return nullptr;
    }
    return std::realloc(ptr, new_size);
}

void SystemAllocator::deallocate(void* ptr, size_t /*size*/) {
    if (ptr) {
        std::free(ptr);
    }
}

/* ========================================================================= */
/* TrackedAllocator                                                          */
/* ========================================================================= */

TrackedAllocator::TrackedAllocator(IAllocator* upstream, std::string tag)
    : m_upstream(upstream ? upstream : &SystemAllocator::instance()),
      m_tag(std::move(tag)) {}

void* TrackedAllocator::allocate(size_t size, size_t alignment) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_max_capacity_bytes > 0 && (m_stats.current_allocated_bytes + size > m_max_capacity_bytes)) {
            // Memory limit defined in module.def exceeded: hijack and block allocation
            return nullptr;
        }
    }

    void* ptr = m_upstream->allocate(size, alignment);
    if (!ptr) return nullptr;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_active_records[ptr] = size;
    m_stats.total_allocations++;
    m_stats.active_allocations++;
    m_stats.current_allocated_bytes += size;
    if (m_stats.current_allocated_bytes > m_stats.peak_allocated_bytes) {
        m_stats.peak_allocated_bytes = m_stats.current_allocated_bytes;
    }
    return ptr;
}

void* TrackedAllocator::reallocate(void* ptr, size_t old_size, size_t new_size, size_t alignment) {
    if (!ptr) return allocate(new_size, alignment);
    if (new_size == 0) {
        deallocate(ptr, old_size);
        return nullptr;
    }

    size_t recorded_old = old_size;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_active_records.find(ptr);
        if (it != m_active_records.end()) {
            recorded_old = it->second;
        }
        if (m_max_capacity_bytes > 0 && (m_stats.current_allocated_bytes - recorded_old + new_size > m_max_capacity_bytes)) {
            // Memory limit defined in module.def exceeded: hijack and block reallocation
            return nullptr;
        }
        if (it != m_active_records.end()) {
            m_active_records.erase(it);
        }
    }

    void* new_ptr = m_upstream->reallocate(ptr, recorded_old, new_size, alignment);
    if (!new_ptr) return nullptr;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_active_records[new_ptr] = new_size;
    m_stats.current_allocated_bytes = m_stats.current_allocated_bytes - recorded_old + new_size;
    if (m_stats.current_allocated_bytes > m_stats.peak_allocated_bytes) {
        m_stats.peak_allocated_bytes = m_stats.current_allocated_bytes;
    }
    return new_ptr;
}

void TrackedAllocator::deallocate(void* ptr, size_t size) {
    if (!ptr) return;

    size_t freed_bytes = size;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_active_records.find(ptr);
        if (it != m_active_records.end()) {
            freed_bytes = it->second;
            m_active_records.erase(it);
        }
        m_stats.total_deallocations++;
        if (m_stats.active_allocations > 0) m_stats.active_allocations--;
        if (m_stats.current_allocated_bytes >= freed_bytes) {
            m_stats.current_allocated_bytes -= freed_bytes;
        } else {
            m_stats.current_allocated_bytes = 0;
        }
    }

    m_upstream->deallocate(ptr, freed_bytes);
}

MemoryStats TrackedAllocator::get_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

bool TrackedAllocator::has_leaks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats.current_allocated_bytes > 0 || !m_active_records.empty();
}

void TrackedAllocator::dump_report(const std::string& title) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << "--- [Memory Report: " << (title.empty() ? m_tag : title) << "] ---\n"
              << "  Current Bytes: " << m_stats.current_allocated_bytes << "\n"
              << "  Peak Bytes:    " << m_stats.peak_allocated_bytes << "\n"
              << "  Allocations:   " << m_stats.total_allocations << "\n"
              << "  Frees:         " << m_stats.total_deallocations << "\n"
              << "  Active Blocks: " << m_stats.active_allocations << "\n";
    if (!m_active_records.empty()) {
        std::cout << "  [WARNING] " << m_active_records.size() << " unfreed blocks detected!\n";
        size_t count = 0;
        for (const auto& [ptr, sz] : m_active_records) {
            std::cout << "    leak #" << ++count << ": addr=" << ptr << ", " << sz << " bytes\n";
            if (count >= 10) {
                std::cout << "    ... (truncated)\n";
                break;
            }
        }
    } else {
        std::cout << "  [STATUS] No leaks detected. 0 bytes currently allocated.\n";
    }
    std::cout << "------------------------------------------\n";
}

/* ========================================================================= */
/* ArenaAllocator                                                            */
/* ========================================================================= */

ArenaAllocator::ArenaAllocator(size_t chunk_size, IAllocator* upstream)
    : m_upstream(upstream ? upstream : &SystemAllocator::instance()),
      m_chunk_size(chunk_size > 0 ? chunk_size : 64 * 1024) {}

ArenaAllocator::~ArenaAllocator() {
    Chunk* curr = m_head;
    while (curr) {
        Chunk* next = curr->next;
        m_upstream->deallocate(curr->memory, curr->capacity);
        m_upstream->deallocate(curr, sizeof(Chunk));
        curr = next;
    }
}

ArenaAllocator::Chunk* ArenaAllocator::allocate_chunk(size_t min_capacity) {
    size_t cap = m_chunk_size > min_capacity ? m_chunk_size : min_capacity;
    uint8_t* mem = static_cast<uint8_t*>(m_upstream->allocate(cap, alignof(std::max_align_t)));
    if (!mem) return nullptr;

    Chunk* chunk = static_cast<Chunk*>(m_upstream->allocate(sizeof(Chunk), alignof(Chunk)));
    if (!chunk) {
        m_upstream->deallocate(mem, cap);
        return nullptr;
    }
    chunk->memory = mem;
    chunk->capacity = cap;
    chunk->offset = 0;
    chunk->next = m_head;
    m_head = chunk;
    return chunk;
}

void* ArenaAllocator::allocate(size_t size, size_t alignment) {
    if (size == 0) return nullptr;
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_head) {
        if (!allocate_chunk(size + alignment)) return nullptr;
    }

    uintptr_t cur = reinterpret_cast<uintptr_t>(m_head->memory + m_head->offset);
    uintptr_t aligned = (cur + alignment - 1) & ~(alignment - 1);
    size_t needed = (aligned - cur) + size;

    if (m_head->offset + needed > m_head->capacity) {
        // Current chunk full; allocate new chunk
        Chunk* new_c = allocate_chunk(size + alignment);
        if (!new_c) return nullptr;

        cur = reinterpret_cast<uintptr_t>(m_head->memory);
        aligned = (cur + alignment - 1) & ~(alignment - 1);
        needed = (aligned - cur) + size;
    }

    m_head->offset += needed;
    m_total_allocated += size;
    return reinterpret_cast<void*>(aligned);
}

void* ArenaAllocator::reallocate(void* ptr, size_t old_size, size_t new_size, size_t alignment) {
    void* new_ptr = allocate(new_size, alignment);
    if (new_ptr && ptr) {
        size_t copy_sz = old_size < new_size ? old_size : new_size;
        std::memcpy(new_ptr, ptr, copy_sz);
    }
    return new_ptr;
}

void ArenaAllocator::deallocate(void* /*ptr*/, size_t /*size*/) {
    // Arena deallocates all at once via reset()
}

void ArenaAllocator::reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    Chunk* curr = m_head;
    while (curr) {
        curr->offset = 0;
        curr = curr->next;
    }
    m_total_allocated = 0;
}

} // namespace dvargosh
