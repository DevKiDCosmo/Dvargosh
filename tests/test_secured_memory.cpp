#include "test_framework.hpp"
#include "dvargosh/secured_memory.hpp"
#include "dvargosh/allocator.hpp"
#include <cstring>

using namespace dvargosh;

TEST_CASE(test_secured_memory_init) {
    auto res = init_secured_memory_space("test_module", 64 * 1024, true);
    ASSERT_TRUE(res.is_ok());

    auto& space = res.value();
    ASSERT_TRUE(space != nullptr);
    ASSERT_TRUE(space->capacity() >= 64 * 1024);
    ASSERT_TRUE(space->raw_base() != nullptr);

    // Sub-allocation
    void* p1 = space->allocate(128);
    ASSERT_TRUE(p1 != nullptr);
    std::memset(p1, 0xAB, 128);

    void* p2 = space->allocate(256);
    ASSERT_TRUE(p2 != nullptr);
    ASSERT_TRUE(p2 != p1);

    ASSERT_EQ(space->used_bytes(), 128 + 256);

    // Reset and scrub
    space->reset();
    ASSERT_EQ(space->used_bytes(), 0);
}

TEST_CASE(test_secured_memory_quota_exceeded) {
    auto res = init_secured_memory_space("quota_test", 4096, false);
    ASSERT_TRUE(res.is_ok());

    auto& space = res.value();
    void* p = space->allocate(space->capacity() + 1024); // Exceeds capacity on any architecture
    ASSERT_TRUE(p == nullptr);
}

TEST_CASE(test_tracked_allocator_quota_limit) {
    TrackedAllocator alloc(nullptr, "test_quota");
    alloc.set_max_capacity(1024);
    ASSERT_EQ(alloc.max_capacity(), 1024);

    void* p1 = alloc.allocate(512);
    ASSERT_TRUE(p1 != nullptr);
    ASSERT_EQ(alloc.get_stats().current_allocated_bytes, 512);

    void* p2 = alloc.allocate(256);
    ASSERT_TRUE(p2 != nullptr);
    ASSERT_EQ(alloc.get_stats().current_allocated_bytes, 768);

    // Exceeding 1024 bytes -> blocked by quota hijack
    void* p3 = alloc.allocate(512);
    ASSERT_TRUE(p3 == nullptr);
    ASSERT_EQ(alloc.get_stats().current_allocated_bytes, 768);

    alloc.deallocate(p1, 512);
    ASSERT_EQ(alloc.get_stats().current_allocated_bytes, 256);

    void* p4 = alloc.allocate(512);
    ASSERT_TRUE(p4 != nullptr);
    ASSERT_EQ(alloc.get_stats().current_allocated_bytes, 768);

    alloc.deallocate(p2, 256);
    alloc.deallocate(p4, 512);
    ASSERT_EQ(alloc.get_stats().current_allocated_bytes, 0);
}
