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

        // 6. Register Native Boxed Process Invoker with Kill Capability
        // Invokes tasks in an isolated box boundary and terminates/kills execution if a kill value or tamper trigger is encountered.
        ctx.register_method("worker.box_invoke", "Executes a method in an isolated box with kill-on-trigger protection",
            [&ctx](const std::vector<Value>& args) -> Result<Value> {
                if (args.empty()) {
                    return Result<Value>::failure(StatusCode::InvalidArg, "worker.box_invoke requires at least target method name");
                }
                std::string target_method = args[0].to_string();
                std::string call_input = args.size() > 1 ? args[1].to_string() : "";
                std::string kill_trigger = args.size() > 2 ? args[2].to_string() : "KILL_EXECUTION";

                // Immediate pre-execution kill check
                if (!kill_trigger.empty() && call_input == kill_trigger) {
                    std::cout << "[Worker Box Guard] Process killed before invocation: input matched kill value '"
                              << kill_trigger << "'!\n";
                    return Result<Value>::failure(
                        StatusCode::SecurityTampering,
                        "Process execution terminated: Box guard killed execution matching trigger value '" + kill_trigger + "'"
                    );
                }

                // Execute inside isolated box execution context
                ScopedCallFrame box_frame("worker", "worker:box", "worker", "worker");

                auto exec_res = ctx.call(target_method, {Value(call_input)});
                if (!exec_res.is_ok()) {
                    if (exec_res.status() == StatusCode::SecurityTampering) {
                        std::cout << "[Worker Box Guard] Tampering detected during boxed invocation! Terminating process.\n";
                        return Result<Value>::failure(
                            StatusCode::SecurityTampering,
                            "Execution killed by box security guard: Tampering violation caught in box."
                        );
                    }
                    return exec_res;
                }

                // Post-execution output kill check
                std::string result_str = exec_res.value().to_string();
                if (!kill_trigger.empty() && result_str.find(kill_trigger) != std::string::npos) {
                    std::cout << "[Worker Box Guard] Process output matched kill value '"
                              << kill_trigger << "'! Forcibly terminating execution.\n";
                    return Result<Value>::failure(
                        StatusCode::SecurityTampering,
                        "Execution killed by box guard: output matched kill trigger '" + kill_trigger + "'"
                    );
                }

                return exec_res;
            }
        );

        // 7. Register dynamic process termination trigger
        ctx.register_method("worker.kill_process", "Forcibly terminates an execution box or active job",
            [](const std::vector<Value>& args) -> Result<Value> {
                std::string target = args.empty() ? "DEFAULT_BOX" : args[0].to_string();
                std::cout << "[Worker Box Guard] Forcibly killing execution box '" << target << "'.\n";
                return Result<Value>::success(Value("BOX_TERMINATED_" + target));
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
