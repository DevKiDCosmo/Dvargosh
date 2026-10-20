#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include "secured_memory.hpp"
#include "allocator.hpp"
#include "resource_manager.hpp"
#include "event_bus.hpp"
#include "registry.hpp"
#include "domain.hpp"
#include <memory>
#include <string>
#include <unordered_map>
#include <typeindex>
#include <functional>

namespace dvargosh {

class DIContainer;

// Injected Context provided to each loaded module
class ModuleContext {
public:
    ModuleContext(
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
    );

    ~ModuleContext();

    // Module identity & domain
    const std::string& module_name() const noexcept { return m_module_name; }
    const std::string& domain() const noexcept { return m_domain_name; }
    const SecurityPolicy& policy() const noexcept { return m_policy; }
    SecurityPolicy& policy() noexcept { return m_policy; }

    // Memory subsystems
    SecuredMemorySpace* secured_memory() noexcept { return m_secured_memory.get(); }
    SecuredMemorySpace* domain_space() noexcept;
    TrackedAllocator* allocator() noexcept { return m_tracked_allocator.get(); }
    ArenaAllocator* arena() noexcept { return m_arena.get(); }

    // Shared subsystems
    Registry* registry() noexcept { return m_registry.get(); }
    ResourceManager* resources() noexcept { return m_resource_mgr.get(); }
    EventBus* event_bus() noexcept { return m_event_bus.get(); }
    DomainManager* domain_manager() noexcept { return m_domain_mgr.get(); }

    // --- High-level Injected Operations ---

    // Service Injection (with domain boundary check)
    template<typename Interface>
    Result<std::shared_ptr<Interface>> inject(const std::string& service_name) {
        if (!m_registry) return Result<std::shared_ptr<Interface>>::failure(StatusCode::NullPointer, "Registry is null");
        return m_registry->get_service<Interface>(service_name, m_domain_name);
    }

    // Dynamic Global Calling
    Result<Value> call(const std::string& method_name, const std::vector<Value>& args = {}) {
        if (!m_registry) return Result<Value>::failure(StatusCode::NullPointer, "Registry is null");
        return m_registry->invoke(method_name, args, m_module_name, m_domain_name, &m_policy);
    }

    // Service Registration
    template<typename Interface>
    Result<void> register_service(
        const std::string& service_name,
        std::shared_ptr<Interface> impl,
        Version version = Version{1, 0, 0}
    ) {
        if (!m_registry) return Result<void>::failure(StatusCode::NullPointer, "Registry is null");
        return m_registry->register_service<Interface>(service_name, impl, version, m_module_name, m_domain_name, &m_policy);
    }

    // Method Registration
    Result<void> register_method(const std::string& method_name, const std::string& desc, DynamicMethodFn fn) {
        if (!m_registry) return Result<void>::failure(StatusCode::NullPointer, "Registry is null");
        return m_registry->register_method(method_name, desc, m_module_name, m_domain_name, std::move(fn), &m_policy);
    }

    // Pub/Sub
    Result<void> emit(const std::string& topic, const Value& payload) {
        if (!m_event_bus) return Result<void>::failure(StatusCode::NullPointer, "Event bus is null");
        return m_event_bus->publish(topic, payload, m_module_name, &m_policy);
    }

    Result<uint64_t> on(const std::string& topic, EventHandler handler) {
        if (!m_event_bus) return Result<uint64_t>::failure(StatusCode::NullPointer, "Event bus is null");
        return m_event_bus->subscribe(topic, m_module_name, std::move(handler), &m_policy);
    }

    // RAII Resource registration helper for module ownership
    template<typename T>
    Result<ResourceId> track_resource(const std::string& name, std::unique_ptr<T> obj) {
        if (!m_resource_mgr) return Result<ResourceId>::failure(StatusCode::NullPointer, "Resource manager is null");
        return m_resource_mgr->register_object<T>(name, m_module_name, std::move(obj));
    }

private:
    std::string m_module_name;
    std::string m_domain_name;
    SecurityPolicy m_policy;
    std::shared_ptr<Registry> m_registry;
    std::shared_ptr<ResourceManager> m_resource_mgr;
    std::shared_ptr<EventBus> m_event_bus;
    std::shared_ptr<DomainManager> m_domain_mgr;
    std::unique_ptr<SecuredMemorySpace> m_secured_memory;
    std::unique_ptr<TrackedAllocator> m_tracked_allocator;
    std::unique_ptr<ArenaAllocator> m_arena;
};

// Global Dependency Injection Container
class DIContainer {
public:
    DIContainer();
    ~DIContainer();

    // Register a singleton by type
    template<typename T>
    void register_instance(std::shared_ptr<T> instance) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_instances[std::type_index(typeid(T))] = std::static_pointer_cast<void>(instance);
    }

    // Resolve a singleton by type
    template<typename T>
    std::shared_ptr<T> resolve() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_instances.find(std::type_index(typeid(T)));
        if (it != m_instances.end()) {
            return std::static_pointer_cast<T>(it->second);
        }
        return nullptr;
    }

    // Create an isolated ModuleContext for a module
    Result<std::unique_ptr<ModuleContext>> create_module_context(
        const std::string& module_name,
        const std::string& domain_name,
        const SecurityPolicy& policy,
        size_t secured_memory_bytes = 4 * 1024 * 1024
    );

    std::shared_ptr<Registry> registry() const { return m_registry; }
    std::shared_ptr<ResourceManager> resource_manager() const { return m_resource_mgr; }
    std::shared_ptr<EventBus> event_bus() const { return m_event_bus; }
    std::shared_ptr<DomainManager> domain_manager() const { return m_domain_mgr; }

private:
    mutable std::mutex m_mutex;
    std::shared_ptr<Registry> m_registry;
    std::shared_ptr<ResourceManager> m_resource_mgr;
    std::shared_ptr<EventBus> m_event_bus;
    std::shared_ptr<DomainManager> m_domain_mgr;
    std::unordered_map<std::type_index, std::shared_ptr<void>> m_instances;
};

} // namespace dvargosh
