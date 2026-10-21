#include "test_framework.hpp"
#include "dvargosh/secured_memory.hpp"
#include "dvargosh/allocator.hpp"
#include "dvargosh/command_memory.hpp"
#include "dvargosh/execution_context.hpp"
#include "dvargosh/vault.hpp"
#include "dvargosh/domain.hpp"
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

TEST_CASE(test_command_memory_lifecycle_and_scrubbing) {
    CommandMemory mem(16 * 1024);
    ASSERT_TRUE(mem.capacity() >= 16 * 1024);
    ASSERT_EQ(mem.used_bytes(), 0);
    ASSERT_TRUE(mem.raw_base() != nullptr);

    // 1. Allocate block
    void* block1 = mem.allocate(128);
    ASSERT_TRUE(block1 != nullptr);
    ASSERT_TRUE(mem.used_bytes() >= 128);
    std::memset(block1, 0xEE, 128);

    // 2. Allocate second block with 16-byte alignment
    void* block2 = mem.allocate(256, 16);
    ASSERT_TRUE(block2 != nullptr);
    ASSERT_EQ(reinterpret_cast<uintptr_t>(block2) % 16, 0);
    ASSERT_TRUE(block2 > block1);

    // 3. Reset scrubs used portion
    mem.reset();
    ASSERT_EQ(mem.used_bytes(), 0);
    ASSERT_EQ(mem.allocation_count(), 0);

    // Verify memory was zeroed
    const uint8_t* check = static_cast<const uint8_t*>(block1);
    ASSERT_EQ(check[0], 0);
    ASSERT_EQ(check[127], 0);
}

TEST_CASE(test_execution_context_command_memory) {
    ASSERT_EQ(ExecutionContext::current_command_memory(), nullptr);

    {
        ScopedCallFrame frame("worker", "worker:job", "main", "main", 32 * 1024);
        CommandMemory* mem = ExecutionContext::current_command_memory();
        ASSERT_TRUE(mem != nullptr);
        ASSERT_TRUE(mem->capacity() >= 32 * 1024);

        // Allocate scratchpad memory within command frame
        void* scratch = ExecutionContext::allocate_command_memory(512);
        ASSERT_TRUE(scratch != nullptr);
        ASSERT_TRUE(ExecutionContext::command_memory_used() >= 512);

        std::memset(scratch, 0x55, 512);
    }

    // Frame exited -> command memory automatically purged and cleaned
    ASSERT_EQ(ExecutionContext::current_command_memory(), nullptr);
    ASSERT_EQ(ExecutionContext::command_memory_used(), 0);
}

TEST_CASE(test_vault_raw_memory_and_slot_wiping) {
    auto dm = std::make_shared<DomainManager>();
    dm->create_domain("vault_dom", SecurityPolicy::strict(), 64 * 1024, false);

    VaultConfig vcfg;
    vcfg.name = "binary_vault";
    vcfg.owner_domain = "vault_dom";
    vcfg.owner_module = "vault_mod";
    vcfg.capacity_bytes = 16 * 1024;
    vcfg.security_level = VaultSecurityLevel::TamperProof;
    vcfg.auto_seal_on_write = true;

    auto v_res = dm->create_vault(vcfg);
    ASSERT_TRUE(v_res.is_ok());
    auto vault = v_res.value();

    // 1. Write binary memory block
    uint8_t raw_bytes[64];
    for (int i = 0; i < 64; ++i) raw_bytes[i] = static_cast<uint8_t>(i ^ 0xAA);

    {
        ScopedCallFrame frame("vault_mod", "vault_dom");
        auto write_res = vault->write_memory("RAW_KEY_BLOCK", raw_bytes, sizeof(raw_bytes));
        ASSERT_TRUE(write_res.is_ok());
        ASSERT_TRUE(vault->is_sealed());

        // Read binary memory back
        auto read_res = vault->read_memory("RAW_KEY_BLOCK");
        ASSERT_TRUE(read_res.is_ok());
        ASSERT_EQ(read_res.value().size(), 64);
        ASSERT_EQ(std::memcmp(read_res.value().data(), raw_bytes, 64), 0);

        // 2. Wipe memory slot
        auto wipe_res = vault->wipe_secret("RAW_KEY_BLOCK");
        ASSERT_TRUE(wipe_res.is_ok());

        // Reading wiped secret must fail with NotFound
        auto post_wipe = vault->read_memory("RAW_KEY_BLOCK");
        ASSERT_FALSE(post_wipe.is_ok());
        ASSERT_EQ(post_wipe.status(), StatusCode::NotFound);
    }
}

TEST_CASE(test_vault_memory_stats_and_reporting) {
    auto dm = std::make_shared<DomainManager>();
    dm->create_domain("crypto_tier", SecurityPolicy::strict(), 64 * 1024, false);

    VaultConfig vcfg;
    vcfg.name = "stats_vault";
    vcfg.owner_domain = "crypto_tier";
    vcfg.owner_module = "crypto_mod";
    vcfg.capacity_bytes = 32 * 1024;
    auto v_res = dm->create_vault(vcfg);
    ASSERT_TRUE(v_res.is_ok());
    auto vault = v_res.value();

    {
        ScopedCallFrame frame("crypto_mod", "crypto_tier");
        vault->write_secret("TOKEN_A", "PAYLOAD_ALPHA_12345");
        vault->write_secret("TOKEN_B", "PAYLOAD_BETA_67890");

        // Inspect memory stats
        VaultMemoryStats stats = vault->memory_stats();
        ASSERT_EQ(stats.name, "stats_vault");
        ASSERT_EQ(stats.owner_domain, "crypto_tier");
        ASSERT_TRUE(stats.capacity_bytes >= 32 * 1024);
        ASSERT_TRUE(stats.used_bytes > 0);
        ASSERT_EQ(stats.slot_count, 2);

        // Inspect slots list
        auto slots = vault->list_slots();
        ASSERT_EQ(slots.size(), 2);
    }

    // Verify domain manager list vaults
    auto all_vaults = dm->list_all_vaults();
    ASSERT_EQ(all_vaults.size(), 1);
    ASSERT_EQ(all_vaults[0]->name(), "stats_vault");

    auto dom_vaults = dm->list_domain_vaults("crypto_tier");
    ASSERT_EQ(dom_vaults.size(), 1);
}
