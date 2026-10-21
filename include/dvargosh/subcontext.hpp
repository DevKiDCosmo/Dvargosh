#pragma once

#include "types.hpp"
#include "secured_memory.hpp"
#include "vault.hpp"
#include "crypto.hpp"
#include "execution_context.hpp"
#include <string>
#include <vector>
#include <unordered_set>
#include <memory>
#include <mutex>

namespace dvargosh {

// Forward declarations
class ModuleContext;
class Registry;
class DomainManager;
class EventBus;
class TrackedAllocator;
class ArenaAllocator;

/**
 * @brief SubContext represents an isolated execution container ("room space") within a Module.
 *
 * =========================================================================================
 * ARCHITECTURAL PRINCIPLES & ISOLATION METHODOLOGY:
 * =========================================================================================
 * 1. ONE CONTEXT, MULTIPLE SUBCONTEXTS:
 *    A ModuleContext owns one or more SubContexts. A SubContext is NOT a domain.
 *    Instead, a SubContext is a physical/logical container room space that can host one
 *    or multiple domains (e.g. domain "captives:vault" and "captives:keys" both reside
 *    in the SubContext "vault_room").
 *
 * 2. EXPLICIT SIZING (FIXED SECURED MEMORY OR DYNAMIC):
 *    SubContexts are explicitly created with a defined capacity:
 *    - capacity_bytes > 0: Allocates a hardware-guarded SecuredMemorySpace with
 *      PROT_NONE guard pages and RAM locking (mlock).
 *    - capacity_bytes == 0: Operates with dynamic heap allocations governed by the
 *      module's quota-enforced TrackedAllocator.
 *
 * 3. CRYPTOGRAPHIC HASH TRACKING & ANTI-COLLISION:
 *    Every SubContext computes an internal HMAC-SHA256 tracking token:
 *        hash = HMAC_SHA256(module_name + "::" + subcontext_name, internal_salt)
 *    This ensures that two modules using identical local subcontext names (e.g., "storage")
 *    produce globally distinct, non-colliding keys for tracking, telemetry, and auditing.
 *
 * 4. INTERNAL REGULATIONS & ACCESS BARRIERS:
 *    SubContexts regulate cross-subcontext memory and function access. A function executing
 *    in one subcontext cannot access the memory, vaults, or private services of another
 *    subcontext unless explicitly permitted by the DomainManager isolation matrix.
 * =========================================================================================
 */
class SubContext {
public:
    /**
     * @brief Constructs a new SubContext room space.
     * @param name Unique name of this subcontext within the parent module.
     * @param module_name Name of the owning parent module.
     * @param module_ctx Pointer to the root ModuleContext.
     * @param registry Pointer to the central service registry.
     * @param domain_mgr Pointer to the system DomainManager.
     * @param event_bus Pointer to the central event bus.
     * @param capacity_bytes Memory size (0 for dynamic memory, > 0 for hardware-guarded page space).
     * @param use_guard_pages Whether to surround allocated space with PROT_NONE guard pages.
     */
    SubContext(
        std::string name,
        std::string module_name,
        ModuleContext* module_ctx,
        Registry* registry,
        DomainManager* domain_mgr,
        EventBus* event_bus,
        size_t capacity_bytes = 0,
        bool use_guard_pages = true
    );

    ~SubContext();

    // Prevent accidental copying; SubContexts are move-only or uniquely managed
    SubContext(const SubContext&) = delete;
    SubContext& operator=(const SubContext&) = delete;

    /** @brief Returns the local name of this subcontext (e.g. "vault_room"). */
    const std::string& name() const noexcept { return m_name; }

    /** @brief Returns the owning module name. */
    const std::string& module_name() const noexcept { return m_module_name; }

    /**
     * @brief Returns the internal HMAC-SHA256 tracking hash of this subcontext.
     * Used for collision-free global indexing and tamper-detection.
     */
    const std::string& hash() const noexcept { return m_hash; }

    /** @brief Returns the memory capacity in bytes (0 indicates dynamic memory). */
    size_t capacity_bytes() const noexcept { return m_capacity_bytes; }

    /** @brief Returns true if this subcontext uses dynamic heap allocations. */
    bool is_dynamic() const noexcept { return m_capacity_bytes == 0; }

    /**
     * @brief Attaches a domain to this subcontext room space.
     * @param domain_name Name of the domain to attach (e.g. "captives:vault").
     * @return Result<void>::success() if attached, or StatusCode::InvalidState if duplicate.
     */
    Result<void> attach_domain(const std::string& domain_name);

    /**
     * @brief Checks if a domain is registered in this subcontext room space.
     * @param domain_name The domain name to query.
     */
    bool has_domain(const std::string& domain_name) const;

    /** @brief Returns the list of all domain names hosted inside this subcontext. */
    std::vector<std::string> domains() const;

    /**
     * @brief Retrieves the dedicated hardware-guarded memory container of this subcontext.
     * Returns nullptr if the subcontext was configured as dynamic (capacity_bytes == 0).
     */
    SecuredMemorySpace* secured_memory() noexcept;

    /**
     * @brief Retrieves the quota-tracked heap allocator of the owning module.
     */
    TrackedAllocator* allocator() noexcept;

    /**
     * @brief Retrieves the central event bus pointer.
     */
    EventBus* event_bus() noexcept { return m_event_bus; }

    /**
     * @brief Retrieves the fast bump-pointer arena for ephemeral scratchpad allocations.
     */
    ArenaAllocator* arena() noexcept;

    /**
     * @brief Invokes a service through the central registry tagged with this subcontext's identity.
     * Automatically validates the caller's active ExecutionContext frame to prevent spoofing.
     * @param method_name Canonical service alias (e.g. "demo_pkg.demo_pkg_vault_hash").
     * @param args Arguments passed to the service.
     * @param calling_domain Optional domain identifier within this subcontext initiating the call.
     * @return Result containing the service return value or failure code.
     */
    Result<Value> call(
        const std::string& method_name,
        const std::vector<Value>& args = {},
        const std::string& calling_domain = ""
    );

    /**
     * @brief Accesses a cryptographic vault belonging to a domain inside this subcontext.
     * @param domain_name The domain that owns the vault.
     * @param vault_name The vault identifier (default "default").
     * @return Result containing shared_ptr to Vault or PermissionDenied.
     */
    Result<std::shared_ptr<Vault>> vault(
        const std::string& domain_name,
        const std::string& vault_name = "default"
    );

    /**
     * @brief Grants this subcontext permission to interact with another target subcontext.
     * @param target_subcontext_name Local name of the target subcontext.
     */
    void allow_subcontext_access(const std::string& target_subcontext_name);

    /**
     * @brief Checks if this subcontext is permitted to access a target subcontext.
     * @param target_subcontext_name Local name of the target subcontext.
     */
    bool can_access_subcontext(const std::string& target_subcontext_name) const;

    /**
     * @brief Generates an internal HMAC-SHA256 tracking hash for a subcontext.
     * @param module_name Module name.
     * @param subcontext_name Subcontext name.
     */
    static std::string compute_tracking_hash(
        const std::string& module_name,
        const std::string& subcontext_name
    );

private:
    std::string m_name;
    std::string m_module_name;
    std::string m_hash;
    size_t m_capacity_bytes;

    ModuleContext* m_module_ctx;
    Registry* m_registry;
    DomainManager* m_domain_mgr;
    EventBus* m_event_bus;

    std::unique_ptr<SecuredMemorySpace> m_secured_memory;
    std::unique_ptr<ArenaAllocator> m_arena;

    mutable std::mutex m_mutex;
    std::unordered_set<std::string> m_domains;
    std::unordered_set<std::string> m_allowed_subcontexts;
};

} // namespace dvargosh
