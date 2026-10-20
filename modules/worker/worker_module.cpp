#include "dvargosh/dvargosh.hpp"
#include <iostream>
#include <cstring>

namespace dvargosh {

// A mock hardware session or custom resource
struct WorkerSessionHandle {
    std::string session_id;
    int32_t active_jobs = 0;
    ~WorkerSessionHandle() {
        std::cout << "[Resource Destructor] WorkerSessionHandle '" << session_id << "' cleanly finalized.\n";
    }
};

class WorkerModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "worker";
            m.domain = "worker";
            m.version = Version{1, 0, 0};
            m.description = "Isolated Secure Worker Module with Containerized Memory and Event Hooks";
            m.author = "Dvargosh Team";
            m.requested_permissions = PermissionSet({
                Permission::SecuredMemory,
                Permission::ServiceRegister,
                Permission::DynamicInvoke,
                Permission::EventSubscribe,
                Permission::EventPublish
            });
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        // 1. Verify Secured Memory Container
        SecuredMemorySpace* sec_mem = ctx.secured_memory();
        if (sec_mem) {
            std::cout << "[WorkerModule] Secured memory space container initialized at "
                      << sec_mem->raw_base() << " with " << sec_mem->capacity() << " bytes.\n";

            // Store a protected secret / token inside the secured memory space
            char* secure_token = static_cast<char*>(sec_mem->allocate(128));
            if (secure_token) {
                std::snprintf(secure_token, 128, "SECURE_VAULT_TOKEN_%p_DV77", secure_token);
                m_vault_token_ptr = secure_token;
            }
        }

        // 2. Track an owned resource with ResourceManager to prove clean scoped destruction
        auto session = std::make_unique<WorkerSessionHandle>();
        session->session_id = "WORKER_SESSION_ALPHA";
        session->active_jobs = 42;
        auto res_track = ctx.track_resource("session_alpha", std::move(session));
        if (res_track.is_ok()) {
            m_session_res_id = res_track.value();
        }

        // 3. Subscribe to math calculation events
        ctx.on("math.calculation_done", [](const std::string& topic, const Value& payload) {
            std::cout << "[WorkerModule Listener] Received event on topic '" << topic
                      << "' with calculated result: " << payload.to_string() << "\n";
        });

        // 4. Register dynamic callable method "worker.inspect_security"
        ctx.register_method("worker.inspect_security", "Returns secured memory container stats",
            [&ctx, this](const std::vector<Value>& /*args*/) -> Result<Value> {
                SecuredMemorySpace* mem = ctx.secured_memory();
                if (!mem) return Result<Value>::failure(StatusCode::NotFound, "No secured memory attached");

                std::string info = "Container: " + mem->name() +
                                   " | Capacity: " + std::to_string(mem->capacity()) +
                                   " | Used: " + std::to_string(mem->used_bytes()) +
                                   " | Protected Token Present: " + (m_vault_token_ptr ? "YES" : "NO");
                return Result<Value>::success(Value(info));
            }
        );

        // 5. Register dynamic callable method "worker.execute_task"
        ctx.register_method("worker.execute_task", "Demonstrates dynamic calling math & logger services",
            [&ctx](const std::vector<Value>& args) -> Result<Value> {
                int64_t n = args.empty() ? 5 : args[0].as_int();

                // Dynamic call to math.factorial
                auto fact_res = ctx.call("math.factorial", {Value(n)});
                if (!fact_res.is_ok()) return fact_res;

                std::string log_msg = "Worker computed factorial(" + std::to_string(n) + ") = " + fact_res.value().to_string();

                // Dynamic call to logger.log
                ctx.call("logger.log", {Value(log_msg)});

                return Result<Value>::success(fact_res.value());
            }
        );

        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext& /*ctx*/) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext& /*ctx*/) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext& /*ctx*/) override {
        m_vault_token_ptr = nullptr;
        return Result<void>::success();
    }

private:
    char* m_vault_token_ptr = nullptr;
    ResourceId m_session_res_id = 0;
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::WorkerModule)
