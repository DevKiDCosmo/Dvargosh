#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <memory>

namespace dvargosh {

using EventHandler = std::function<void(const std::string& topic, const Value& payload)>;

struct Subscription {
    uint64_t id;
    std::string topic;
    std::string subscriber_module;
    EventHandler handler;
};

class EventBus {
public:
    EventBus();
    ~EventBus() = default;

    Result<uint64_t> subscribe(
        const std::string& topic,
        const std::string& subscriber_module,
        EventHandler handler,
        const SecurityPolicy* policy = nullptr
    );

    Result<void> unsubscribe(uint64_t subscription_id);

    // Unsubscribe all listeners registered by a specific module (on module unload)
    size_t unsubscribe_module(const std::string& subscriber_module);

    Result<void> publish(
        const std::string& topic,
        const Value& payload,
        const std::string& publisher_module = "system",
        const SecurityPolicy* policy = nullptr
    );

    size_t subscription_count(const std::string& topic = "") const;

private:
    mutable std::mutex m_mutex;
    uint64_t m_next_sub_id = 1;
    std::unordered_map<std::string, std::vector<Subscription>> m_topic_subscriptions;
    std::unordered_map<uint64_t, std::string> m_sub_id_to_topic;
};

} // namespace dvargosh
