#include "dvargosh/subcontext.hpp"
#include "dvargosh/di_container.hpp"
#include "dvargosh/registry.hpp"
#include "dvargosh/domain.hpp"
#include "dvargosh/event_bus.hpp"
#include "dvargosh/logger.hpp"
#include "dvargosh/allocator.hpp"

namespace dvargosh {

// Secret internal salt used for subcontext cryptographic token derivation
static const std::string s_subcontext_salt = "dvargosh_subcontext_internal_tracking_salt_772819";

std::string SubContext::compute_tracking_hash(
    const std::string& module_name,
    const std::string& subcontext_name
) {
    // Generate deterministic 64-character HMAC-SHA256 tracking key
    std::string payload = module_name + "::" + subcontext_name;
    return Crypto::hmac_sha256_hex(s_subcontext_salt, payload);
}

SubContext::SubContext(
    std::string name,
    std::string module_name,
    ModuleContext* module_ctx,
    Registry* registry,
    DomainManager* domain_mgr,
    EventBus* event_bus,
    size_t capacity_bytes,
    bool use_guard_pages
) : m_name(std::move(name)),
    m_module_name(std::move(module_name)),
    m_capacity_bytes(capacity_bytes),
    m_module_ctx(module_ctx),
    m_registry(registry),
    m_domain_mgr(domain_mgr),
    m_event_bus(event_bus) {

    // 1. Calculate cryptographically unique tracking hash
    m_hash = compute_tracking_hash(m_module_name, m_name);

    // 2. Initialize hardware-guarded memory container if capacity is specified
    if (m_capacity_bytes > 0) {
        SecuredMemoryConfig cfg;
        cfg.container_name = m_module_name + "_" + m_name;
        cfg.capacity_bytes = m_capacity_bytes;
        cfg.use_guard_pages = use_guard_pages;
        cfg.scrub_on_destroy = true;

        SecurityPolicy sec_policy;
        sec_policy.permissions().grant(Permission::SecuredMemory);
        sec_policy.set_max_memory_bytes(m_capacity_bytes + (use_guard_pages ? 8192 : 0));

        auto res = SecuredMemorySpace::create(cfg, sec_policy);
        if (res.is_ok()) {
            m_secured_memory = std::move(res.value());
        } else {
            log_error("SubContext '", m_name, "' failed to allocate secured memory space: ", res.error_message());
        }
    }

    // 3. SubContext always allows access to itself
    m_allowed_subcontexts.insert(m_name);
}

SubContext::~SubContext() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_secured_memory) {
        m_secured_memory->unload();
        m_secured_memory.reset();
    }
}

Result<void> SubContext::attach_domain(const std::string& domain_name) {
    if (domain_name.empty()) {
        return Result<void>::failure(StatusCode::InvalidArg, "Domain name cannot be empty");
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_domains.find(domain_name) != m_domains.end()) {
        return Result<void>::success(); // Already attached
    }

    m_domains.insert(domain_name);
    return Result<void>::success();
}

bool SubContext::has_domain(const std::string& domain_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_domains.find(domain_name) != m_domains.end();
}

std::vector<std::string> SubContext::domains() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return std::vector<std::string>(m_domains.begin(), m_domains.end());
}

SecuredMemorySpace* SubContext::secured_memory() noexcept {
    return m_secured_memory.get();
}

TrackedAllocator* SubContext::allocator() noexcept {
    return m_module_ctx ? m_module_ctx->allocator() : nullptr;
}

ArenaAllocator* SubContext::arena() noexcept {
    if (!m_arena && allocator()) {
        m_arena = std::make_unique<ArenaAllocator>(64 * 1024, allocator());
    }
    return m_arena ? m_arena.get() : (m_module_ctx ? m_module_ctx->arena() : nullptr);
}

Result<Value> SubContext::call(
    const std::string& method_name,
    const std::vector<Value>& args,
    const std::string& calling_domain
) {
    if (!m_registry) {
        return Result<Value>::failure(StatusCode::NullPointer, "Registry is null");
    }

    // 1. Resolve effective calling domain
    std::string eff_domain = calling_domain;
    if (eff_domain.empty()) {
        // Fall back to ExecutionContext domain or the first attached domain
        if (ExecutionContext::frame_depth() > 0) {
            eff_domain = ExecutionContext::current_domain();
        }
        if (eff_domain.empty() || eff_domain == "untrusted") {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_domains.empty()) {
                eff_domain = *m_domains.begin();
            } else {
                eff_domain = "default";
            }
        }
    }

    // 2. Execute via central registry with authenticated module and domain
    const SecurityPolicy* pol = m_module_ctx ? &m_module_ctx->policy() : nullptr;
    return m_registry->invoke(method_name, args, m_module_name, eff_domain, pol);
}

Result<std::shared_ptr<Vault>> SubContext::vault(
    const std::string& domain_name,
    const std::string& vault_name
) {
    if (!m_domain_mgr) {
        return Result<std::shared_ptr<Vault>>::failure(StatusCode::NullPointer, "DomainManager is null");
    }

    // Ensure the domain belongs to this subcontext or access is permitted
    if (!has_domain(domain_name)) {
        std::string caller_domain = ExecutionContext::current_domain();
        if (!m_domain_mgr->check_cross_domain_access(caller_domain, domain_name)) {
            return Result<std::shared_ptr<Vault>>::failure(
                StatusCode::PermissionDenied,
                "SubContext Access Denied: Domain '" + domain_name + "' is not hosted in subcontext '" + m_name + "'"
            );
        }
    }

    return m_domain_mgr->get_domain_vault(domain_name, vault_name);
}

void SubContext::allow_subcontext_access(const std::string& target_subcontext_name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_allowed_subcontexts.insert(target_subcontext_name);
}

bool SubContext::can_access_subcontext(const std::string& target_subcontext_name) const {
    if (target_subcontext_name.empty()) return false;
    if (target_subcontext_name == m_name) return true;
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_allowed_subcontexts.find(target_subcontext_name) != m_allowed_subcontexts.end();
}

} // namespace dvargosh
