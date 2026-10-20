#pragma once

#include "dvargosh/types.hpp"
#include "dvargosh/registry.hpp"
#include "dvargosh/di_container.hpp"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <stdexcept>
#include <type_traits>

namespace dvargosh {

/**
 * @brief Dynamic Service AutoMapper and Reflection Interface.
 *
 * The AutoMapper bridges dynamic runtime RPC registration and compile-time C++ typing.
 * It provides reflection introspection over active domains, and allows dynamic RPC methods
 * to be bound into strongly-typed `std::function<ReturnType(Args...)>` callables with
 * zero manual `Value` variant packing/unpacking boilerplate.
 */
class AutoMapper {
public:
    /**
     * @brief Constructs an AutoMapper bound to a Service Registry.
     * @param registry Shared pointer to the active ServiceRegistry.
     */
    explicit AutoMapper(std::shared_ptr<Registry> registry)
        : m_registry(std::move(registry)) {}

    /**
     * @brief Constructs an AutoMapper bound to a Dependency Injection Container.
     * @param di Shared pointer to the active DIContainer.
     */
    explicit AutoMapper(std::shared_ptr<DIContainer> di)
        : m_registry(di ? di->registry() : nullptr) {}

    /**
     * @brief Checks if a service method is registered in the registry.
     * @param method_name Name of the service/method.
     * @return True if method is registered, false otherwise.
     */
    bool has_service(const std::string& method_name) const {
        return m_registry && m_registry->has_method(method_name);
    }

    /**
     * @brief Finds the domain subsystem associated with a service method.
     * @param method_name Name of the service/method.
     * @return Domain identifier string, or empty string if not found.
     */
    std::string find_domain_for_service(const std::string& method_name) const {
        return m_registry ? m_registry->get_method_domain(method_name) : "";
    }

    /**
     * @brief Lists all registered services in a specific domain.
     * @param domain Domain name or filter pattern.
     * @return List of method names registered in that domain.
     */
    std::vector<std::string> list_services_in_domain(const std::string& domain) const {
        std::vector<std::string> result;
        if (!m_registry) return result;
        for (const auto& name : m_registry->list_methods()) {
            std::string d = m_registry->get_method_domain(name);
            if (d == domain || domain.empty() || domain == "*") {
                result.push_back(name);
            }
        }
        return result;
    }

    /**
     * @brief Dynamically binds an RPC service into a strongly-typed C++ std::function callable.
     *
     * Example:
     * @code
     * AutoMapper mapper(di);
     * auto hash_fn = mapper.bind<std::string, const std::string&>("demo_pkg_vault_hash");
     * std::string result = hash_fn("MySecretData");
     * @endcode
     *
     * @tparam ReturnType The expected return type (std::string, double, int64_t, bool, void).
     * @tparam Args The parameter types passed to the service.
     * @param method_name The registered service method name.
     * @return A std::function that forwards typed arguments through dynamic RPC and unboxes results.
     */
    template <typename ReturnType, typename... Args>
    std::function<ReturnType(Args...)> bind(const std::string& method_name) {
        if (!m_registry) {
            throw std::runtime_error("AutoMapper: Registry reference is null.");
        }
        auto reg = m_registry;
        return [reg, method_name](Args... args) -> ReturnType {
            std::vector<Value> vargs;
            (vargs.push_back(Value(args)), ...);
            auto res = reg->invoke(method_name, vargs);
            if (!res.is_ok()) {
                throw std::runtime_error("AutoMapper call to '" + method_name + "' failed: " + res.error_message());
            }

            if constexpr (std::is_void_v<ReturnType>) {
                return;
            } else if constexpr (std::is_same_v<ReturnType, std::string>) {
                return res.value().to_string();
            } else if constexpr (std::is_floating_point_v<ReturnType>) {
                return static_cast<ReturnType>(res.value().as_double());
            } else if constexpr (std::is_integral_v<ReturnType>) {
                return static_cast<ReturnType>(res.value().as_int());
            } else if constexpr (std::is_same_v<ReturnType, bool>) {
                return res.value().as_bool();
            } else {
                return ReturnType{};
            }
        };
    }

    /**
     * @brief Gets the underlying ServiceRegistry.
     */
    std::shared_ptr<Registry> registry() const noexcept { return m_registry; }

private:
    std::shared_ptr<Registry> m_registry;
};

} // namespace dvargosh
