#include "dvargosh/command_memory.hpp"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

namespace dvargosh {

namespace {

void secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

size_t align_up(size_t val, size_t align) {
    if (align == 0) return val;
    return (val + align - 1) & ~(align - 1);
}

} // anonymous namespace

CommandMemory::CommandMemory(size_t capacity_bytes) {
    long ps = sysconf(_SC_PAGESIZE);
    size_t page_size = (ps > 0) ? static_cast<size_t>(ps) : 4096;
    m_capacity = align_up(capacity_bytes > 0 ? capacity_bytes : 64 * 1024, page_size);

    void* mapped = mmap(
        nullptr,
        m_capacity,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (mapped != MAP_FAILED) {
        m_buffer = static_cast<uint8_t*>(mapped);
        m_mapped = true;
    } else {
        // Fallback to aligned heap allocation
        m_buffer = new uint8_t[m_capacity];
        m_mapped = false;
    }
    m_used_offset = 0;
    m_alloc_count = 0;
}

CommandMemory::~CommandMemory() {
    if (m_buffer) {
        secure_zero(m_buffer, m_capacity);
        if (m_mapped) {
            munmap(m_buffer, m_capacity);
        } else {
            delete[] m_buffer;
        }
        m_buffer = nullptr;
    }
    m_capacity = 0;
    m_used_offset = 0;
    m_alloc_count = 0;
}

CommandMemory::CommandMemory(CommandMemory&& other) noexcept {
    std::lock_guard<std::mutex> lock(other.m_mutex);
    m_buffer = other.m_buffer;
    m_capacity = other.m_capacity;
    m_used_offset = other.m_used_offset;
    m_alloc_count = other.m_alloc_count;
    m_mapped = other.m_mapped;

    other.m_buffer = nullptr;
    other.m_capacity = 0;
    other.m_used_offset = 0;
    other.m_alloc_count = 0;
    other.m_mapped = false;
}

CommandMemory& CommandMemory::operator=(CommandMemory&& other) noexcept {
    if (this != &other) {
        if (m_buffer) {
            secure_zero(m_buffer, m_capacity);
            if (m_mapped) munmap(m_buffer, m_capacity);
            else delete[] m_buffer;
        }
        std::lock_guard<std::mutex> lock(other.m_mutex);
        m_buffer = other.m_buffer;
        m_capacity = other.m_capacity;
        m_used_offset = other.m_used_offset;
        m_alloc_count = other.m_alloc_count;
        m_mapped = other.m_mapped;

        other.m_buffer = nullptr;
        other.m_capacity = 0;
        other.m_used_offset = 0;
        other.m_alloc_count = 0;
        other.m_mapped = false;
    }
    return *this;
}

void* CommandMemory::allocate(size_t size, size_t alignment) {
    if (size == 0 || !m_buffer) return nullptr;
    std::lock_guard<std::mutex> lock(m_mutex);

    uintptr_t current = reinterpret_cast<uintptr_t>(m_buffer) + m_used_offset;
    uintptr_t aligned = (current + alignment - 1) & ~(alignment - 1);
    size_t new_offset = (aligned - reinterpret_cast<uintptr_t>(m_buffer)) + size;

    if (new_offset > m_capacity) {
        return nullptr; // Quota exceeded in command memory
    }

    m_used_offset = new_offset;
    m_alloc_count++;
    return reinterpret_cast<void*>(aligned);
}

void CommandMemory::reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_buffer && m_used_offset > 0) {
        secure_zero(m_buffer, m_used_offset);
    }
    m_used_offset = 0;
    m_alloc_count = 0;
}

void CommandMemory::scrub() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_buffer && m_capacity > 0) {
        secure_zero(m_buffer, m_capacity);
    }
    m_used_offset = 0;
    m_alloc_count = 0;
}

} // namespace dvargosh
