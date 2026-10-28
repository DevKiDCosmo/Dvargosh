#pragma once

// ============================================================================
// Dvargosh Service Binder — ergonomic, compile-time-typed method registration
// ============================================================================
// Replaces raw registry()->invoke() ceremony on the EXPORT side. The compiler
// already knows each function's signature; this header deduces it and generates
// the Value unboxing/reboxing once, at compile time.
//
//   double stdtext_trim(const std::string& s);
//   ...
//   ctx.binds()
//       .fn<&stdtext_trim>("stdtext.trim", "Trims whitespace from both ends")
//       .fn<&stdtext_contains>("stdtext.contains", "Substring check")
//       .alias("stdtext.trim", "trim");
//
// Properties (docs/execution_plan.md WS-B):
//   * Exact argument count enforced per call (InvalidArg with a precise message).
//   * Strict argument typing: a type-confused argument throws DvargoshException
//     (TypeMismatch) inside the wrapper and becomes a catchable failed Result —
//     never a silent zero and never an unhandled crash.
//   * Unsupported argument/return types fail at COMPILE TIME with a readable
//     static_assert instead of silently coercing.
//   * Registration flows through Registry::register_method with the module's own
//     policy — same ServiceRegister permission gate as the manual path.
//   * No ABI change: the registry still stores a plain DynamicMethodFn.
// ============================================================================

#include "dvargosh/di_container.hpp"
#include "dvargosh/types.hpp"
#include <string>
#include <tuple>
#include <utility>

namespace dvargosh {

namespace bind_detail {

template <typename T>
struct dependent_false : std::false_type {};

// --- Argument extraction (strict, loud on type confusion) -------------------

template <typename T> struct arg_cast {
    static_assert(dependent_false<T>::value,
        "dvargosh bind: argument type is not Value-convertible. "
        "Supported: double, int64_t, int, bool, std::string, std::vector<uint8_t>");
    static int from(const Value&);
};
template <> struct arg_cast<double> {
    static double from(const Value& v) { return v.as_double(); }
};
template <> struct arg_cast<int64_t> {
    static int64_t from(const Value& v) { return v.as_int(); }
};
template <> struct arg_cast<int> {
    static int from(const Value& v) { return static_cast<int>(v.as_int()); }
};
template <> struct arg_cast<bool> {
    static bool from(const Value& v) { return v.as_bool(); }
};
template <> struct arg_cast<std::string> {
    static std::string from(const Value& v) { return v.as_string(); }
};
template <> struct arg_cast<std::vector<uint8_t>> {
    static std::vector<uint8_t> from(const Value& v) { return v.as_bytes(); }
};

// --- Result conversion -------------------------------------------------------

template <typename R> struct result_cast {
    static_assert(dependent_false<R>::value,
        "dvargosh bind: return type is not Value-convertible. "
        "Supported: void, double, int64_t, int, bool, std::string, std::vector<uint8_t>");
};
template <> struct result_cast<void> {
    static Value to() { return Value(true); }
};
template <> struct result_cast<double> {
    static Value to(double r) { return Value(r); }
};
template <> struct result_cast<int64_t> {
    static Value to(int64_t r) { return Value(r); }
};
template <> struct result_cast<int> {
    static Value to(int r) { return Value(static_cast<int64_t>(r)); }
};
template <> struct result_cast<bool> {
    static Value to(bool r) { return Value(r); }
};
template <> struct result_cast<std::string> {
    static Value to(std::string r) { return Value(std::move(r)); }
};
template <> struct result_cast<std::vector<uint8_t>> {
    static Value to(std::vector<uint8_t> r) { return Value(std::move(r)); }
};

// --- Function-pointer traits --------------------------------------------------

template <typename... Ts> struct typelist {};

template <typename Sig> struct fn_traits;
template <typename R, typename... Args>
struct fn_traits<R (*)(Args...)> {
    using ret = R;
    using args_tuple = std::tuple<std::decay_t<Args>...>;
    using arg_types = typelist<Args...>; // keeps the pack reifiable at the call site
    static constexpr size_t arity = sizeof...(Args);
};

// --- Wrapper synthesis ---------------------------------------------------------

// Two-hop expansion: invoke_bound re-materializes the Args pack from the typelist,
// then hands it to invoke_bound_seq together with a matching index sequence —
// both packs are guaranteed to have equal length there.
template <auto Fn, typename R, typename... Args, size_t... I>
Result<Value> invoke_bound_seq(
    const std::vector<Value>& args,
    std::index_sequence<I...>
) {
    // Extract all arguments BEFORE the call: function-argument evaluation order
    // is unspecified in C++, so per-index extraction inside the call expression
    // would be order-dependent. A tuple makes it deterministic.
    std::tuple<std::decay_t<Args>...> unpacked{ arg_cast<std::decay_t<Args>>::from(args[I])... };
    if constexpr (std::is_void_v<R>) {
        std::apply(Fn, std::move(unpacked));
        return Result<Value>::success(result_cast<void>::to());
    } else {
        auto r = std::apply(Fn, std::move(unpacked));
        return Result<Value>::success(result_cast<R>::to(std::move(r)));
    }
}

template <auto Fn, typename R, typename... Args>
Result<Value> invoke_bound(const std::vector<Value>& args, typelist<Args...>) {
    return invoke_bound_seq<Fn, R, Args...>(args, std::make_index_sequence<sizeof...(Args)>{});
}

template <auto Fn>
DynamicMethodFn make_wrapper(std::string method_name) {
    using traits = fn_traits<decltype(Fn)>;
    using R = typename traits::ret;

    if constexpr (std::is_same_v<R, Result<Value>> && traits::arity == 1 &&
                  std::is_same_v<typename traits::args_tuple, std::tuple<std::vector<Value>>>) {
        // Passthrough shape: the function already has the registry's native
        // signature (legacy bridges, parser-heavy services like stdnet).
        // It handles its own validation and error mapping.
        (void)method_name;
        return DynamicMethodFn(Fn);
    } else {
        return [method_name = std::move(method_name)](const std::vector<Value>& args) -> Result<Value> {
            if (args.size() != traits::arity) {
                return Result<Value>::failure(
                    StatusCode::InvalidArg,
                    "Method '" + method_name + "' expects exactly " + std::to_string(traits::arity) +
                    " argument(s), but " + std::to_string(args.size()) + " provided"
                );
            }
            try {
                return invoke_bound<Fn, R>(args, typename traits::arg_types{});
            } catch (const DvargoshException& e) {
                return Result<Value>::failure(e.code(), e.what());
            } catch (const std::exception& e) {
                return Result<Value>::failure(StatusCode::InvocationFailed, std::string("Binder: ") + e.what());
            } catch (...) {
                return Result<Value>::failure(StatusCode::InvocationFailed, "Binder: unknown error in '" + method_name + "'");
            }
        };
    }
}

} // namespace bind_detail

// ============================================================================
// ServiceBinder — fluent registration handle scoped to a ModuleContext
// ============================================================================

class ServiceBinder {
public:
    explicit ServiceBinder(ModuleContext& ctx) : m_ctx(ctx) {}

    /**
     * @brief Registers a plain C++ function as a dynamic RPC method (chainable).
     * Signature (return + parameter types AND count) is deduced at compile time.
     * Chain ends with .result(), which carries the FIRST registration failure.
     *
     *   ctx.binds().fn<&f>("name", "desc").fn<&g>("n2", "d2").result();
     *
     * @param name     Registry method name (e.g. "stdtext.trim").
     * @param desc     Human-readable description.
     * @param domain   Optional explicit domain; defaults to the module's context domain.
     */
    template <auto Fn>
    ServiceBinder& fn(
        const std::string& name,
        const std::string& desc,
        const std::string& domain = ""
    ) {
        if (m_result.is_ok()) {
            m_result = m_ctx.registry()->register_method(
                name,
                desc,
                m_ctx.module_name(),
                domain.empty() ? m_ctx.domain() : domain,
                bind_detail::make_wrapper<Fn>(name),
                &m_ctx.policy()
            );
        }
        return *this;
    }

    /**
     * @brief Registers an alias for a method this module owns (chainable).
     * Cross-provider aliases are rejected by the registry (audit C5).
     */
    ServiceBinder& alias(const std::string& alias_name, const std::string& target_method) {
        if (m_result.is_ok()) {
            m_result = m_ctx.registry()->register_alias(alias_name, target_method, m_ctx.module_name());
        }
        return *this;
    }

    /**
     * @brief Terminates a registration chain; carries the first failure (if any).
     */
    [[nodiscard]] Result<void> result() const { return m_result; }

private:
    ModuleContext& m_ctx;
    Result<void> m_result = Result<void>::success();
};

} // namespace dvargosh

// Defined here (after ServiceBinder is complete) to avoid a circular include.
namespace dvargosh {
inline ServiceBinder ModuleContext::binds() {
    return ServiceBinder(*this);
}
} // namespace dvargosh
