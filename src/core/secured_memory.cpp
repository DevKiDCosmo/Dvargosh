#include "dvargosh/secured_memory.hpp"
#include <unistd.h>
#include <sys/mman.h>
#include <cstring>
#include <iostream>

namespace dvargosh {

namespace {

// Volatile secure zeroing to prevent compiler dead-store elimination
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

Result<std::unique_ptr<SecuredMemorySpace>> SecuredMemorySpace::create(
    const SecuredMemoryConfig& config,
    const SecurityPolicy& policy
) {
    // Check permission to allocate secured memory
    auto perm_res = policy.check(Permission::SecuredMemory, config.container_name);
    if (!perm_res.is_ok()) {
        return Result<std::unique_ptr<SecuredMemorySpace>>::failure(
            StatusCode::PermissionDenied,
            "SecurityPolicy forbids SecuredMemory for container '" + config.container_name + "'"
        );
    }

    // Check quota
    if (config.capacity_bytes > policy.max_memory_bytes()) {
        return Result<std::unique_ptr<SecuredMemorySpace>>::failure(
            StatusCode::QuotaExceeded,
            "Requested " + std::to_string(config.capacity_bytes) +
            " bytes exceeds policy quota of " + std::to_string(policy.max_memory_bytes())
        );
    }

    std::unique_ptr<SecuredMemorySpace> space(new SecuredMemorySpace(config));
    auto init_res = space->initialize();
    if (!init_res.is_ok()) {
        return Result<std::unique_ptr<SecuredMemorySpace>>::failure(init_res.status(), init_res.error_message());
    }

    return Result<std::unique_ptr<SecuredMemorySpace>>::success(std::move(space));
}

SecuredMemorySpace::SecuredMemorySpace(const SecuredMemoryConfig& config)
    : m_config(config) {
    long ps = sysconf(_SC_PAGESIZE);
    m_page_size = (ps > 0) ? static_cast<size_t>(ps) : 4096;
}

SecuredMemorySpace::~SecuredMemorySpace() {
    if (m_total_mapped) {
        if (m_config.scrub_on_destroy && m_usable_memory && m_usable_size > 0) {
            scrub();
        }
        if (m_config.lock_in_ram && m_usable_memory) {
            munlock(m_usable_memory, m_usable_size);
        }
        munmap(m_total_mapped, m_total_mapped_size);
        m_total_mapped = nullptr;
        m_usable_memory = nullptr;
        m_total_mapped_size = 0;
        m_usable_size = 0;
    }
}

SecuredMemorySpace::SecuredMemorySpace(SecuredMemorySpace&& o) noexcept {
    std::lock_guard<std::mutex> lock(o.m_mutex);
    m_config = std::move(o.m_config);
    m_total_mapped = o.m_total_mapped;
    m_total_mapped_size = o.m_total_mapped_size;
    m_usable_memory = o.m_usable_memory;
    m_usable_size = o.m_usable_size;
    m_page_size = o.m_page_size;
    m_used_offset = o.m_used_offset;

    o.m_total_mapped = nullptr;
    o.m_usable_memory = nullptr;
    o.m_total_mapped_size = 0;
    o.m_usable_size = 0;
    o.m_used_offset = 0;
}

SecuredMemorySpace& SecuredMemorySpace::operator=(SecuredMemorySpace&& o) noexcept {
    if (this != &o) {
        if (m_total_mapped) {
            if (m_config.scrub_on_destroy && m_usable_memory) scrub();
            munmap(m_total_mapped, m_total_mapped_size);
        }
        std::lock_guard<std::mutex> lock(o.m_mutex);
        m_config = std::move(o.m_config);
        m_total_mapped = o.m_total_mapped;
        m_total_mapped_size = o.m_total_mapped_size;
        m_usable_memory = o.m_usable_memory;
        m_usable_size = o.m_usable_size;
        m_page_size = o.m_page_size;
        m_used_offset = o.m_used_offset;

        o.m_total_mapped = nullptr;
        o.m_usable_memory = nullptr;
        o.m_total_mapped_size = 0;
        o.m_usable_size = 0;
        o.m_used_offset = 0;
    }
    return *this;
}

Result<void> SecuredMemorySpace::initialize() {
    m_usable_size = align_up(m_config.capacity_bytes, m_page_size);

    if (m_config.use_guard_pages) {
        // [Front Guard Page] [Usable Memory] [Back Guard Page]
        m_total_mapped_size = m_usable_size + (2 * m_page_size);
    } else {
        m_total_mapped_size = m_usable_size;
    }

    // Allocate anonymous memory via mmap
    void* mapped = mmap(
        nullptr,
        m_total_mapped_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (mapped == MAP_FAILED) {
        return Result<void>::failure(StatusCode::OutOfMemory, "mmap failed to allocate secured memory space");
    }

    m_total_mapped = mapped;

    if (m_config.use_guard_pages) {
        uint8_t* base = static_cast<uint8_t*>(m_total_mapped);
        // Protect front guard page
        if (mprotect(base, m_page_size, PROT_NONE) != 0) {
            munmap(m_total_mapped, m_total_mapped_size);
            m_total_mapped = nullptr;
            return Result<void>::failure(StatusCode::InternalError, "Failed to set front guard page PROT_NONE");
        }

        m_usable_memory = base + m_page_size;

        // Protect rear guard page
        uint8_t* rear_guard = base + m_page_size + m_usable_size;
        if (mprotect(rear_guard, m_page_size, PROT_NONE) != 0) {
            munmap(m_total_mapped, m_total_mapped_size);
            m_total_mapped = nullptr;
            return Result<void>::failure(StatusCode::InternalError, "Failed to set rear guard page PROT_NONE");
        }
    } else {
        m_usable_memory = m_total_mapped;
    }

    if (m_config.lock_in_ram) {
        mlock(m_usable_memory, m_usable_size);
    }

    m_used_offset = 0;
    return Result<void>::success();
}

void* SecuredMemorySpace::allocate(size_t size, size_t alignment) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_usable_memory || size == 0) return nullptr;

    uintptr_t current = reinterpret_cast<uintptr_t>(m_usable_memory) + m_used_offset;
    uintptr_t aligned = (current + alignment - 1) & ~(alignment - 1);
    size_t new_offset = (aligned - reinterpret_cast<uintptr_t>(m_usable_memory)) + size;

    if (new_offset > m_usable_size) {
        return nullptr; // Quota exceeded in secured container
    }

    m_used_offset = new_offset;
    return reinterpret_cast<void*>(aligned);
}

void SecuredMemorySpace::reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_config.scrub_on_destroy && m_usable_memory && m_used_offset > 0) {
        secure_zero(m_usable_memory, m_used_offset);
    }
    m_used_offset = 0;
}

void SecuredMemorySpace::scrub() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_usable_memory && m_usable_size > 0) {
        secure_zero(m_usable_memory, m_usable_size);
    }
}

Result<std::unique_ptr<SecuredMemorySpace>> init_secured_memory_space(
    const std::string& module_name,
    size_t capacity_bytes,
    bool enable_guard_pages
) {
    SecuredMemoryConfig cfg;
    cfg.container_name = module_name;
    cfg.capacity_bytes = capacity_bytes;
    cfg.use_guard_pages = enable_guard_pages;
    cfg.scrub_on_destroy = true;
    cfg.lock_in_ram = false;

    SecurityPolicy policy = SecurityPolicy::standard();
    policy.set_max_memory_bytes(capacity_bytes * 2);
    policy.permissions().grant(Permission::SecuredMemory);

    return SecuredMemorySpace::create(cfg, policy);
}

Result<std::unique_ptr<SecuredMemorySpace>> init_own_memory_space(
    const std::string& name,
    size_t capacity_bytes,
    bool enable_guard_pages,
    bool lock_in_ram,
    bool scrub_on_destroy
) {
    SecuredMemoryConfig cfg;
    cfg.container_name = name;
    cfg.capacity_bytes = capacity_bytes;
    cfg.use_guard_pages = enable_guard_pages;
    cfg.lock_in_ram = lock_in_ram;
    cfg.scrub_on_destroy = scrub_on_destroy;

    SecurityPolicy policy = SecurityPolicy::standard();
    policy.set_max_memory_bytes(capacity_bytes * 2);
    policy.permissions().grant(Permission::SecuredMemory);

    return SecuredMemorySpace::create(cfg, policy);
}

} // namespace dvargosh
