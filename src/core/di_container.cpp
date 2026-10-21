#include "dvargosh/di_container.hpp"
#include "dvargosh/subcontext.hpp"
#include "dvargosh/runtime.hpp"
#include "dvargosh/execution_context.hpp"
#include <iostream>

namespace dvargosh {

ModuleContext::ModuleContext(
    std::string module_name,
    std::string domain_name,
    SecurityPolicy policy,
    std::shared_ptr<Registry> registry,
    std::shared_ptr<ResourceManager> resource_mgr,
    std::shared_ptr<EventBus> event_bus,
    std::shared_ptr<DomainManager> domain_mgr,
    std::unique_ptr<SecuredMemorySpace> secured_memory,
    std::unique_ptr<TrackedAllocator> tracked_allocator,
    std::unique_ptr<ArenaAllocator> arena
) : m_module_name(std::move(module_name)),
    m_domain_name(std::move(domain_name)),
    m_policy(std::move(policy)),
    m_registry(std::move(registry)),
    m_resource_mgr(std::move(resource_mgr)),
    m_event_bus(std::move(event_bus)),
    m_domain_mgr(std::move(domain_mgr)),
    m_secured_memory(std::move(secured_memory)),
    m_tracked_allocator(std::move(tracked_allocator)),
    m_arena(std::move(arena)) {
    if (m_domain_mgr && !m_domain_name.empty()) {
        auto domain = m_domain_mgr->get_domain(m_domain_name);
        if (domain) {
            domain->add_module(m_module_name);
        }
    }

    // Automatically create the default room space (SubContext) for this module
    auto def_sub = std::make_shared<SubContext>(
        "default",
        m_module_name,
        this,
        m_registry.get(),
        m_domain_mgr.get(),
        m_event_bus.get(),
        0, // dynamic memory
        true
    );
    if (!m_domain_name.empty()) {
        def_sub->attach_domain(m_domain_name);
    }
    m_subcontexts["default"] = def_sub;
    m_hash_to_subcontext[def_sub->hash()] = def_sub.get();
    Runtime::register_subcontext(def_sub->hash(), def_sub.get());
}

ModuleContext::~ModuleContext() {
    // 0. Unregister all subcontexts from global runtime tracking
    {
        std::lock_guard<std::mutex> lock(m_subcontext_mutex);
        for (auto& [_, sub] : m_subcontexts) {
            if (sub) {
                Runtime::unregister_subcontext(sub->hash());
            }
        }
    }

    // 1. Remove from domain
    if (m_domain_mgr && !m_domain_name.empty()) {
        auto domain = m_domain_mgr->get_domain(m_domain_name);
        if (domain) {
            domain->remove_module(m_module_name);
        }
    }

    // 2. Unregister all event subscriptions made by this module
    if (m_event_bus) {
        m_event_bus->unsubscribe_module(m_module_name);
    }

    // 3. Unregister services and methods provided by this module
    if (m_registry) {
        m_registry->unregister_provider(m_module_name);
    }

    // 4. Clean up all resources owned by this module
    if (m_resource_mgr) {
        m_resource_mgr->cleanup_owner(m_module_name);
    }

    // 5. Release scratchpad arena before auditing tracked allocator
    m_arena.reset();

    // 6. Check for leaks in the module's tracked allocator
    if (m_tracked_allocator && m_tracked_allocator->has_leaks()) {
        std::cerr << "[WARNING] Module '" << m_module_name << "' leaked memory upon destruction:\n";
        m_tracked_allocator->dump_report();
    }
}

SecuredMemorySpace* ModuleContext::domain_space() noexcept {
    if (m_domain_mgr && !m_domain_name.empty()) {
        return m_domain_mgr->get_domain_space(m_domain_name);
    }
    return nullptr;
}

void* ModuleContext::allocate_command_memory(size_t size, size_t alignment) {
    return ExecutionContext::allocate_command_memory(size, alignment);
}

CommandMemory* ModuleContext::command_memory() noexcept {
    return ExecutionContext::current_command_memory();
}

Result<SubContext*> ModuleContext::create_subcontext(
    const std::string& subcontext_name,
    size_t capacity_bytes,
    bool use_guard_pages
) {
    if (subcontext_name.empty()) {
        return Result<SubContext*>::failure(StatusCode::InvalidArg, "Subcontext name cannot be empty");
    }

    std::lock_guard<std::mutex> lock(m_subcontext_mutex);
    if (m_subcontexts.find(subcontext_name) != m_subcontexts.end()) {
        return Result<SubContext*>::failure(
            StatusCode::AlreadyExists,
            "SubContext '" + subcontext_name + "' already exists in module '" + m_module_name + "'"
        );
    }

    auto sub = std::make_shared<SubContext>(
        subcontext_name,
        m_module_name,
        this,
        m_registry.get(),
        m_domain_mgr.get(),
        m_event_bus.get(),
        capacity_bytes,
        use_guard_pages
    );

    SubContext* ptr = sub.get();
    m_subcontexts[subcontext_name] = sub;
    m_hash_to_subcontext[ptr->hash()] = ptr;

    // Register with runtime
    Runtime::register_subcontext(ptr->hash(), ptr);

    return Result<SubContext*>::success(ptr);
}

SubContext* ModuleContext::get_subcontext(const std::string& subcontext_name) {
    std::lock_guard<std::mutex> lock(m_subcontext_mutex);
    auto it = m_subcontexts.find(subcontext_name);
    return (it != m_subcontexts.end()) ? it->second.get() : nullptr;
}

SubContext* ModuleContext::get_subcontext_for_domain(const std::string& domain_name) {
    std::lock_guard<std::mutex> lock(m_subcontext_mutex);
    // 1. Direct domain attachment lookup
    for (auto& [_, sub] : m_subcontexts) {
        if (sub && sub->has_domain(domain_name)) {
            return sub.get();
        }
    }
    // 2. Fall back to subcontext with matching name
    auto it = m_subcontexts.find(domain_name);
    if (it != m_subcontexts.end()) return it->second.get();

    // 3. Fall back to default subcontext
    auto def_it = m_subcontexts.find("default");
    if (def_it != m_subcontexts.end()) return def_it->second.get();

    // 4. Fall back to first available subcontext
    if (!m_subcontexts.empty()) return m_subcontexts.begin()->second.get();

    return nullptr;
}

SubContext* ModuleContext::get_subcontext_by_hash(const std::string& hash) {
    std::lock_guard<std::mutex> lock(m_subcontext_mutex);
    auto it = m_hash_to_subcontext.find(hash);
    return (it != m_hash_to_subcontext.end()) ? it->second : nullptr;
}

std::vector<SubContext*> ModuleContext::list_subcontexts() const {
    std::lock_guard<std::mutex> lock(m_subcontext_mutex);
    std::vector<SubContext*> list;
    list.reserve(m_subcontexts.size());
    for (const auto& [_, sub] : m_subcontexts) {
        if (sub) list.push_back(sub.get());
    }
    return list;
}

DIContainer::DIContainer()
    : m_registry(std::make_shared<Registry>()),
      m_resource_mgr(std::make_shared<ResourceManager>()),
      m_event_bus(std::make_shared<EventBus>()),
      m_domain_mgr(std::make_shared<DomainManager>()) {
    m_registry->set_domain_manager(m_domain_mgr.get());
    register_instance<Registry>(m_registry);
    register_instance<ResourceManager>(m_resource_mgr);
    register_instance<EventBus>(m_event_bus);
    register_instance<DomainManager>(m_domain_mgr);
}

DIContainer::~DIContainer() = default;

Result<std::unique_ptr<ModuleContext>> DIContainer::create_module_context(
    const std::string& module_name,
    const std::string& domain_name,
    const SecurityPolicy& policy,
    size_t secured_memory_bytes
) {
    // Ensure domain exists
    std::string dom = domain_name.empty() ? "default" : domain_name;
    if (!m_domain_mgr->has_domain(dom)) {
        m_domain_mgr->create_domain(dom, policy);
    }

    // 1. Create SecuredMemorySpace for module containirization if permitted
    std::unique_ptr<SecuredMemorySpace> secured_mem = nullptr;
    if (policy.permissions().has(Permission::SecuredMemory) && secured_memory_bytes > 0) {
        SecuredMemoryConfig mem_cfg;
        mem_cfg.container_name = module_name;
        mem_cfg.capacity_bytes = secured_memory_bytes;
        mem_cfg.use_guard_pages = true;
        mem_cfg.scrub_on_destroy = true;

        auto sec_res = SecuredMemorySpace::create(mem_cfg, policy);
        if (!sec_res.is_ok()) {
            return Result<std::unique_ptr<ModuleContext>>::failure(
                sec_res.status(),
                "Failed to initialize secured memory space: " + sec_res.error_message()
            );
        }
        secured_mem = std::move(sec_res.value());
    }

    // 2. Create Scoped Tracked Allocator for this module
    auto tracked_alloc = std::make_unique<TrackedAllocator>(&SystemAllocator::instance(), "mod_" + module_name);

    // 3. Create Scoped Scratchpad Arena
    auto arena = std::make_unique<ArenaAllocator>(64 * 1024, tracked_alloc.get());

    auto ctx = std::make_unique<ModuleContext>(
        module_name,
        dom,
        policy,
        m_registry,
        m_resource_mgr,
        m_event_bus,
        m_domain_mgr,
        std::move(secured_mem),
        std::move(tracked_alloc),
        std::move(arena)
    );

    return Result<std::unique_ptr<ModuleContext>>::success(std::move(ctx));
}

} // namespace dvargosh
