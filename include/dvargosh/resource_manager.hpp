#pragma once

#include "types.hpp"
#include <cstdint>
#include <string>
#include <functional>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <vector>

namespace dvargosh {

using ResourceId = uint64_t;
using ResourceDestructor = std::function<void(void*)>;

struct ResourceInfo {
    ResourceId id = 0;
    std::string name;
    std::string type_name;
    std::string owner_module;
    void* handle = nullptr;
    int32_t ref_count = 1;
    ResourceDestructor destructor;
};

class ResourceManager {
public:
    ResourceManager();
    ~ResourceManager();

    // Register a raw resource handle with destructor
    Result<ResourceId> register_resource(
        std::string name,
        std::string type_name,
        std::string owner_module,
        void* handle,
        ResourceDestructor destructor
    );

    // RAII Resource registration helper
    template<typename T>
    Result<ResourceId> register_object(
        std::string name,
        std::string owner_module,
        std::unique_ptr<T> obj
    ) {
        T* raw = obj.release();
        return register_resource(
            std::move(name),
            typeid(T).name(),
            std::move(owner_module),
            raw,
            [](void* p) { delete static_cast<T*>(p); }
        );
    }

    void* get(ResourceId id) const;
    void* find_by_name(const std::string& name) const;

    Result<void> retain(ResourceId id);
    Result<void> release(ResourceId id);

    // Scoped cleanup of all resources owned by a module (e.g. on hot-unplug)
    size_t cleanup_owner(const std::string& owner_module);

    size_t active_count() const;
    std::vector<ResourceInfo> list_all() const;
    void dump_report() const;

private:
    mutable std::mutex m_mutex;
    ResourceId m_next_id = 1;
    std::unordered_map<ResourceId, ResourceInfo> m_resources;
    std::unordered_map<std::string, ResourceId> m_name_index;
};

} // namespace dvargosh
