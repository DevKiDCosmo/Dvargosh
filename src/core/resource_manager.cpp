#include "dvargosh/resource_manager.hpp"
#include <iostream>

namespace dvargosh {

ResourceManager::ResourceManager() = default;

ResourceManager::~ResourceManager() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, res] : m_resources) {
        if (res.destructor && res.handle) {
            try {
                res.destructor(res.handle);
            } catch (...) {
                // Suppress destructor errors on shutdown
            }
        }
    }
    m_resources.clear();
    m_name_index.clear();
}

Result<ResourceId> ResourceManager::register_resource(
    std::string name,
    std::string type_name,
    std::string owner_module,
    void* handle,
    ResourceDestructor destructor
) {
    if (!handle) {
        return Result<ResourceId>::failure(StatusCode::NullPointer, "Resource handle cannot be null");
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!name.empty() && m_name_index.find(name) != m_name_index.end()) {
        return Result<ResourceId>::failure(StatusCode::AlreadyExists, "Resource named '" + name + "' already exists");
    }

    ResourceId id = m_next_id++;
    ResourceInfo info;
    info.id = id;
    info.name = name;
    info.type_name = std::move(type_name);
    info.owner_module = std::move(owner_module);
    info.handle = handle;
    info.ref_count = 1;
    info.destructor = std::move(destructor);

    m_resources[id] = std::move(info);
    if (!name.empty()) {
        m_name_index[name] = id;
    }

    return Result<ResourceId>::success(id);
}

void* ResourceManager::get(ResourceId id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_resources.find(id);
    if (it != m_resources.end()) {
        return it->second.handle;
    }
    return nullptr;
}

void* ResourceManager::find_by_name(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_name_index.find(name);
    if (it != m_name_index.end()) {
        auto res_it = m_resources.find(it->second);
        if (res_it != m_resources.end()) {
            return res_it->second.handle;
        }
    }
    return nullptr;
}

Result<void> ResourceManager::retain(ResourceId id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_resources.find(id);
    if (it == m_resources.end()) {
        return Result<void>::failure(StatusCode::NotFound, "Resource ID not found");
    }
    it->second.ref_count++;
    return Result<void>::success();
}

Result<void> ResourceManager::release(ResourceId id) {
    void* handle_to_destroy = nullptr;
    ResourceDestructor dtor = nullptr;
    std::string name_to_erase;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_resources.find(id);
        if (it == m_resources.end()) {
            return Result<void>::failure(StatusCode::NotFound, "Resource ID not found");
        }

        it->second.ref_count--;
        if (it->second.ref_count <= 0) {
            handle_to_destroy = it->second.handle;
            dtor = it->second.destructor;
            name_to_erase = it->second.name;
            m_resources.erase(it);
            if (!name_to_erase.empty()) {
                m_name_index.erase(name_to_erase);
            }
        }
    }

    if (handle_to_destroy && dtor) {
        dtor(handle_to_destroy);
    }

    return Result<void>::success();
}

size_t ResourceManager::cleanup_owner(const std::string& owner_module) {
    std::vector<std::pair<void*, ResourceDestructor>> to_destroy;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_resources.begin(); it != m_resources.end();) {
            if (it->second.owner_module == owner_module) {
                if (!it->second.name.empty()) {
                    m_name_index.erase(it->second.name);
                }
                if (it->second.handle && it->second.destructor) {
                    to_destroy.emplace_back(it->second.handle, it->second.destructor);
                }
                it = m_resources.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto& [handle, dtor] : to_destroy) {
        try {
            dtor(handle);
        } catch (...) {
            // Ignore
        }
    }

    return to_destroy.size();
}

size_t ResourceManager::active_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_resources.size();
}

std::vector<ResourceInfo> ResourceManager::list_all() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ResourceInfo> list;
    list.reserve(m_resources.size());
    for (const auto& [id, info] : m_resources) {
        list.push_back(info);
    }
    return list;
}

void ResourceManager::dump_report() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::cout << "--- [Resource Manager Registry: " << m_resources.size() << " active] ---\n";
    for (const auto& [id, res] : m_resources) {
        std::cout << "  [ID " << id << "] "
                  << (res.name.empty() ? "<anonymous>" : res.name)
                  << " | Type: " << res.type_name
                  << " | Owner: " << res.owner_module
                  << " | Refs: " << res.ref_count << "\n";
    }
    std::cout << "--------------------------------------------------\n";
}

} // namespace dvargosh
