#include "dvargosh/event_bus.hpp"

namespace dvargosh {

EventBus::EventBus() = default;

Result<uint64_t> EventBus::subscribe(
    const std::string& topic,
    const std::string& subscriber_module,
    EventHandler handler,
    const SecurityPolicy* policy
) {
    if (policy) {
        auto perm_res = policy->check(Permission::EventSubscribe, subscriber_module);
        if (!perm_res.is_ok()) return Result<uint64_t>::failure(perm_res.status(), perm_res.error_message());
    }

    if (!handler) {
        return Result<uint64_t>::failure(StatusCode::NullPointer, "Event handler is null");
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t id = m_next_sub_id++;
    Subscription sub;
    sub.id = id;
    sub.topic = topic;
    sub.subscriber_module = subscriber_module;
    sub.handler = std::move(handler);

    m_topic_subscriptions[topic].push_back(std::move(sub));
    m_sub_id_to_topic[id] = topic;

    return Result<uint64_t>::success(id);
}

Result<void> EventBus::unsubscribe(uint64_t subscription_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_sub_id_to_topic.find(subscription_id);
    if (it == m_sub_id_to_topic.end()) {
        return Result<void>::failure(StatusCode::NotFound, "Subscription ID not found");
    }

    const std::string& topic = it->second;
    auto topic_it = m_topic_subscriptions.find(topic);
    if (topic_it != m_topic_subscriptions.end()) {
        auto& subs = topic_it->second;
        for (auto sub_it = subs.begin(); sub_it != subs.end(); ++sub_it) {
            if (sub_it->id == subscription_id) {
                subs.erase(sub_it);
                break;
            }
        }
        if (subs.empty()) {
            m_topic_subscriptions.erase(topic_it);
        }
    }

    m_sub_id_to_topic.erase(it);
    return Result<void>::success();
}

size_t EventBus::unsubscribe_module(const std::string& subscriber_module) {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t removed = 0;

    for (auto it = m_topic_subscriptions.begin(); it != m_topic_subscriptions.end();) {
        auto& subs = it->second;
        for (auto sub_it = subs.begin(); sub_it != subs.end();) {
            if (sub_it->subscriber_module == subscriber_module) {
                m_sub_id_to_topic.erase(sub_it->id);
                sub_it = subs.erase(sub_it);
                removed++;
            } else {
                ++sub_it;
            }
        }
        if (subs.empty()) {
            it = m_topic_subscriptions.erase(it);
        } else {
            ++it;
        }
    }

    return removed;
}

Result<void> EventBus::publish(
    const std::string& topic,
    const Value& payload,
    const std::string& publisher_module,
    const SecurityPolicy* policy
) {
    if (policy) {
        auto perm_res = policy->check(Permission::EventPublish, publisher_module);
        if (!perm_res.is_ok()) return perm_res;
    }

    std::vector<EventHandler> handlers;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        // Direct topic match
        auto it = m_topic_subscriptions.find(topic);
        if (it != m_topic_subscriptions.end()) {
            for (const auto& sub : it->second) {
                handlers.push_back(sub.handler);
            }
        }

        // Wildcard match for topic "*"
        auto wildcard_it = m_topic_subscriptions.find("*");
        if (wildcard_it != m_topic_subscriptions.end()) {
            for (const auto& sub : wildcard_it->second) {
                handlers.push_back(sub.handler);
            }
        }
    }

    for (const auto& handler : handlers) {
        try {
            handler(topic, payload);
        } catch (...) {
            // Protect bus from subscriber exceptions
        }
    }

    return Result<void>::success();
}

size_t EventBus::subscription_count(const std::string& topic) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (topic.empty()) {
        return m_sub_id_to_topic.size();
    }
    auto it = m_topic_subscriptions.find(topic);
    if (it != m_topic_subscriptions.end()) {
        return it->second.size();
    }
    return 0;
}

} // namespace dvargosh
