#pragma once

// stdnet — Flexible buffers (zero-copy friendly) and fixed-block memory pools.

#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

namespace dvargosh::stdnet {

// --- DynamicBuffer: append-only byte stream with a contiguous read window -----
// Designed so parsers can inspect in place (zero-copy) and consume exactly
// the bytes they understood; unconsumed bytes stay for the next round.

class DynamicBuffer {
public:
    explicit DynamicBuffer(size_t chunk = 8192) : m_chunk(chunk ? chunk : 8192) {}

    size_t size() const { return m_size; }
    bool empty() const { return m_size == 0; }

    // Appends bytes (copy-in; the network read is the only copy).
    void append(const void* data, size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        ensure_capacity(m_size + len);
        std::memcpy(m_data.get() + m_size, p, len);
        m_size += len;
    }

    // Contiguous view of all buffered bytes (zero-copy parse window).
    const uint8_t* data() const { return m_data.get(); }

    // Consumes n bytes from the front (memmove; unconsumed bytes compacted).
    void consume(size_t n) {
        if (n >= m_size) {
            m_size = 0;
            return;
        }
        std::memmove(m_data.get(), m_data.get() + n, m_size - n);
        m_size -= n;
    }

    void clear() { m_size = 0; }
    void reserve(size_t bytes) { ensure_capacity(bytes); }

private:
    void ensure_capacity(size_t needed) {
        if (needed <= m_capacity) return;
        size_t cap = m_capacity ? m_capacity : m_chunk;
        while (cap < needed) cap *= 2;
        auto fresh = std::make_unique<uint8_t[]>(cap);
        if (m_size) std::memcpy(fresh.get(), m_data.get(), m_size);
        m_data = std::move(fresh);
        m_capacity = cap;
    }

    size_t m_chunk;
    size_t m_size = 0;
    size_t m_capacity = 0;
    std::unique_ptr<uint8_t[]> m_data;
};

// --- BufferPool: fixed-size block freelist (minimizes heap fragmentation) ------

class BufferPool {
public:
    explicit BufferPool(size_t block_size = 4096, size_t soft_limit_blocks = 64)
        : m_block_size(block_size ? block_size : 4096), m_soft_limit(soft_limit_blocks) {}

    size_t block_size() const { return m_block_size; }

    // Returns a raw block of block_size bytes (never null); allocates a new
    // block when the freelist is empty, otherwise recycles.
    uint8_t* acquire() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_free.empty()) {
            uint8_t* block = m_free.back();
            m_free.pop_back();
            return block;
        }
        m_live++;
        return new uint8_t[m_block_size];
    }

    void release(uint8_t* block) {
        if (!block) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_free.size() < m_soft_limit) {
            m_free.push_back(block);
        } else {
            delete[] block;
            m_live--;
        }
    }

    // RAII handle: a uniquely-owned pool block.
    struct Block {
        BufferPool* pool = nullptr;
        uint8_t* ptr = nullptr;
        Block() = default;
        Block(BufferPool& p, uint8_t* raw) : pool(&p), ptr(raw) {}
        Block(Block&& o) noexcept : pool(o.pool), ptr(std::exchange(o.ptr, nullptr)) { o.pool = nullptr; }
        Block& operator=(Block&& o) noexcept {
            if (this != &o) {
                reset();
                pool = std::exchange(o.pool, nullptr);
                ptr = std::exchange(o.ptr, nullptr);
            }
            return *this;
        }
        Block(const Block&) = delete;
        Block& operator=(const Block&) = delete;
        ~Block() { reset(); }
        void reset() {
            if (pool && ptr) {
                pool->release(ptr);
            }
            pool = nullptr;
            ptr = nullptr;
        }
        uint8_t* get() const { return ptr; }
    };

    Block make_block() { return Block(*this, acquire()); }

private:
    size_t m_block_size;
    size_t m_soft_limit;
    std::mutex m_mutex;
    std::deque<uint8_t*> m_free;
    size_t m_live = 0;
};

} // namespace dvargosh::stdnet
