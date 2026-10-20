#include "dvargosh/dvargosh.hpp"
#include "math_interface.hpp"
#include "../logger/logger_interface.hpp"
#include <iostream>

namespace dvargosh {

class MathServiceImpl : public IMathService {
public:
    double add(double a, double b) override { return a + b; }
    double multiply(double a, double b) override { return a * b; }
    int64_t factorial(int64_t n) override {
        if (n <= 1) return 1;
        int64_t res = 1;
        for (int64_t i = 2; i <= n; ++i) res *= i;
        return res;
    }
};

class MathModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "math";
            m.domain = "compute";
            m.version = Version{1, 2, 0};
            m.description = "Mathematical Computations with Arena Memory and Event Emission";
            m.author = "Dvargosh Team";
            m.requested_permissions = PermissionSet({
                Permission::ServiceRegister,
                Permission::DynamicInvoke,
                Permission::EventPublish
            });
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        m_service = std::make_shared<MathServiceImpl>();

        // 1. Dependency Injection: Inquire logger service from DI container
        auto logger_res = ctx.inject<ILogger>("logger");
        if (logger_res.is_ok()) {
            m_logger = logger_res.value();
            m_logger->info("[MathModule] Injected ILogger dependency successfully.");
        }

        // 2. Register typed service interface in global registry
        auto reg_res = ctx.register_service<IMathService>("math", m_service, Version{1, 2, 0});
        if (!reg_res.is_ok()) return reg_res;

        // 3. Register dynamic RPC callable methods: "math.add", "math.factorial", "math.sum_range"
        ctx.register_method("math.add", "Adds two numbers", [this](const std::vector<Value>& args) -> Result<Value> {
            if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "math.add requires 2 arguments");
            double res = m_service->add(args[0].as_double(), args[1].as_double());
            return Result<Value>::success(Value(res));
        });

        ctx.register_method("math.factorial", "Calculates factorial of n", [this](const std::vector<Value>& args) -> Result<Value> {
            if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "math.factorial requires 1 integer argument");
            int64_t n = args[0].as_int();
            if (n < 0 || n > 20) return Result<Value>::failure(StatusCode::InvalidArg, "Argument out of bounds [0, 20]");
            int64_t res = m_service->factorial(n);
            return Result<Value>::success(Value(res));
        });

        // Demonstrating Scoped Arena Allocator & Event Publishing
        ctx.register_method("math.sum_range", "Allocates scratchpad memory in Arena, sums [1..N], and emits event",
            [&ctx, this](const std::vector<Value>& args) -> Result<Value> {
                if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "math.sum_range requires count N");
                int64_t n = args[0].as_int();
                if (n <= 0 || n > 1000000) return Result<Value>::failure(StatusCode::InvalidArg, "N must be in [1, 1000000]");

                // Allocate array in module's scoped scratchpad arena
                ArenaAllocator* arena = ctx.arena();
                int64_t* buffer = static_cast<int64_t*>(arena->allocate(n * sizeof(int64_t)));
                if (!buffer) return Result<Value>::failure(StatusCode::OutOfMemory, "Arena out of memory");

                int64_t sum = 0;
                for (int64_t i = 0; i < n; ++i) {
                    buffer[i] = i + 1;
                    sum += buffer[i];
                }

                // Reset arena for next call (zero cost deallocation)
                arena->reset();

                // Emit event to event bus
                ctx.emit("math.calculation_done", Value(sum));

                if (m_logger) {
                    m_logger->info("[MathModule] Computed sum_range(1.." + std::to_string(n) + ") = " + std::to_string(sum));
                }

                return Result<Value>::success(Value(sum));
            }
        );

        if (m_logger) m_logger->info("MathModule loaded with dynamic methods and Arena support.");
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext& /*ctx*/) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext& /*ctx*/) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext& /*ctx*/) override {
        m_service.reset();
        m_logger.reset();
        return Result<void>::success();
    }

private:
    std::shared_ptr<MathServiceImpl> m_service;
    std::shared_ptr<ILogger> m_logger;
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::MathModule)
