#include "dvargosh/dvargosh.hpp"
#include "dvargosh/telemetry.hpp"
#include "monitor_interface.hpp"
#include "../logger/logger_interface.hpp"
#include <iostream>
#include <chrono>
#include <mutex>
#include <iomanip>
#include <sstream>

namespace dvargosh {

class MonitoringServiceImpl : public IMonitoringService {
public:
    explicit MonitoringServiceImpl(DomainManager* dm, TrackedAllocator* alloc, TelemetryHub* hub)
        : m_domain_mgr(dm), m_allocator(alloc), m_hub(hub) {}

    void record_metric(const std::string& name, double value) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_metrics[name] = value;
    }

    double get_metric(const std::string& name) const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_metrics.find(name);
        return (it != m_metrics.end()) ? it->second : 0.0;
    }

    std::unordered_map<std::string, double> get_all_metrics() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_metrics;
    }

    SystemMemoryOccupation get_memory_occupation() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        SystemMemoryOccupation occ;

        if (m_allocator) {
            auto stats = m_allocator->get_stats();
            occ.host_current_allocated_bytes = stats.current_allocated_bytes;
            occ.host_peak_allocated_bytes = stats.peak_allocated_bytes;
            occ.host_active_allocations = stats.active_allocations;
        }

        if (m_domain_mgr) {
            auto domain_names = m_domain_mgr->list_domains();
            for (const auto& name : domain_names) {
                const Domain* dom = m_domain_mgr->get_domain(name);
                if (!dom) continue;

                DomainMemoryInfo info;
                info.domain_name = name;
                info.module_count = dom->modules().size();
                info.service_count = dom->services().size();

                const SecuredMemorySpace* space = dom->secured_space();
                if (space) {
                    info.capacity_bytes = space->capacity();
                    info.used_bytes = space->used_bytes();
                    info.remaining_bytes = space->remaining_bytes();
                    occ.total_secured_capacity_bytes += space->capacity();
                    occ.total_secured_used_bytes += space->used_bytes();
                }

                occ.domains.push_back(info);
            }
        }

        return occ;
    }

    void dump_dashboard() const override {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::cout << "\n┌─────────────────────────────────────────────────────────────┐\n";
        std::cout << "│                 TELEMETRY MONITOR DASHBOARD                 │\n";
        std::cout << "├────────────────────────────────────────┬────────────────────┤\n";
        std::cout << "│ Metric Name                            │ Value              │\n";
        std::cout << "├────────────────────────────────────────┼────────────────────┤\n";
        for (const auto& [name, val] : m_metrics) {
            std::cout << "│ " << name;
            for (size_t i = name.length(); i < 38; ++i) std::cout << " ";
            std::ostringstream val_ss;
            val_ss << std::fixed << std::setprecision(2) << val;
            std::string v = val_ss.str();
            std::cout << " │ " << v;
            for (size_t i = v.length(); i < 18; ++i) std::cout << " ";
            std::cout << " │\n";
        }
        std::cout << "└────────────────────────────────────────┴────────────────────┘\n";
    }

    // --- TelemetryHub-backed views (displaying functions over live streams) ---

    TelemetryHub* hub() const { return m_hub; }

    std::string hub_snapshot_table(const std::string& glob) const {
        if (!m_hub) return "TelemetryHub unavailable";
        auto items = m_hub->snapshot(glob);
        std::ostringstream ss;
        ss << "\n┌────────────────────────────────────────────────────────────────────────┐\n";
        ss << "│                    TELEMETRY HUB SNAPSHOT ('" << glob << "')\n";
        ss << "├──────────────────────────────────────────┬──────────────┬──────────────┤\n";
        ss << "│ Stream                                   │   Last/Avg   │  Count/Drop  │\n";
        ss << "├──────────────────────────────────────────┼──────────────┼──────────────┤\n";
        for (const auto& item : items) {
            std::string name = item.name;
            if (name.length() > 40) name = name.substr(0, 37) + "...";
            ss << "│ " << name;
            for (size_t i = name.length(); i < 41; ++i) ss << " ";
            std::ostringstream vals;
            vals << std::fixed << std::setprecision(3) << item.last << "/" << item.avg;
            std::string v = vals.str();
            if (v.length() > 12) v = v.substr(0, 12);
            ss << " │ ";
            for (size_t i = v.length(); i < 12; ++i) ss << " ";
            ss << v;
            std::string c = std::to_string(item.count) + "/" + std::to_string(item.dropped);
            ss << " │ ";
            for (size_t i = c.length(); i < 12; ++i) ss << " ";
            ss << c << " │\n";
        }
        ss << "└──────────────────────────────────────────┴──────────────┴──────────────┘\n";
        return ss.str();
    }

    std::string hub_top_table(size_t n) const {
        if (!m_hub) return "TelemetryHub unavailable";
        auto items = m_hub->top_streams(n);
        std::ostringstream ss;
        ss << "\n[TelemetryHub] Top " << items.size() << " stream(s) by last value:\n";
        for (const auto& item : items) {
            ss << "  * " << item.name << " = " << std::fixed << std::setprecision(3) << item.last
               << " (count=" << item.count << ", max=" << item.max << ")\n";
        }
        return ss.str();
    }

private:
    mutable std::mutex m_mutex;
    DomainManager* m_domain_mgr = nullptr;
    TrackedAllocator* m_allocator = nullptr;
    TelemetryHub* m_hub = nullptr;
    std::unordered_map<std::string, double> m_metrics;
};

class MonitorModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "monitor";
            m.domain = "telemetry";
            m.version = Version{1, 0, 0};
            m.description = "Live Telemetry, System Metrics, and Memory Occupation Monitor";
            m.author = "Dvargosh Team";
            m.requested_permissions = PermissionSet({
                Permission::SecuredMemory,
                Permission::ServiceRegister,
                Permission::DynamicInvoke,
                Permission::EventSubscribe,
                Permission::EventPublish,
                Permission::SystemInfo
            });
            return m;
        }();
        return s_manifest;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        m_service = std::make_shared<MonitoringServiceImpl>(ctx.domain_manager(), ctx.allocator(), ctx.telemetry());

        // Record a module-scoped metric through the hub-facing helper.
        (void)ctx.record_metric("startup", 1.0);

        // 1. Inquire logger service
        auto logger_res = ctx.inject<ILogger>("logger");
        if (logger_res.is_ok()) {
            m_logger = logger_res.value();
            m_logger->info("[MonitorModule] Injected ILogger dependency into telemetry domain.");
        }

        // 2. Register typed service interface in global registry
        auto reg_res = ctx.register_service<IMonitoringService>("monitor", m_service, Version{1, 0, 0});
        if (!reg_res.is_ok()) return reg_res;

        // 3. Initialize metrics
        m_service->record_metric("system.uptime_sec", 0.0);
        m_service->record_metric("events.received_total", 0.0);
        m_service->record_metric("math.calculations_total", 0.0);
        m_service->record_metric("telemetry.heartbeat", 1.0);

        // 4. Subscribe to math calculation events
        ctx.on("math.calculation_done", [this](const std::string& /*topic*/, const Value& val) {
            double current = m_service->get_metric("math.calculations_total");
            m_service->record_metric("math.calculations_total", current + 1.0);
            m_service->record_metric("math.last_result", val.as_double());
            double ev_total = m_service->get_metric("events.received_total");
            m_service->record_metric("events.received_total", ev_total + 1.0);
        });

        // 5. Register dynamic callable RPC methods
        ctx.register_method("monitor.record", "Records a telemetry metric (name, value)",
            [this](const std::vector<Value>& args) -> Result<Value> {
                if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "monitor.record requires (name, value)");
                std::string name = args[0].to_string();
                double val = args[1].as_double();
                m_service->record_metric(name, val);
                return Result<Value>::success(Value(true));
            }
        );

        ctx.register_method("monitor.get", "Retrieves a telemetry metric by name",
            [this](const std::vector<Value>& args) -> Result<Value> {
                if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "monitor.get requires metric name");
                std::string name = args[0].to_string();
                double val = m_service->get_metric(name);
                return Result<Value>::success(Value(val));
            }
        );

        ctx.register_method("monitor.dashboard", "Prints visual telemetry dashboard",
            [this](const std::vector<Value>& /*args*/) -> Result<Value> {
                m_service->dump_dashboard();
                return Result<Value>::success(Value(true));
            }
        );

        // Memory occupation RPC - reports memory, secured spaces, and domains
        ctx.register_method("monitor.memory_status", "Returns live occupation of memory, secured spaces, and domains",
            [this](const std::vector<Value>& /*args*/) -> Result<Value> {
                auto occ = m_service->get_memory_occupation();
                std::ostringstream ss;
                ss << "\n┌────────────────────────────────────────────────────────────────────────┐\n"
                   << "│                   MEMORY & SECURED SPACES OCCUPATION                   │\n"
                   << "├────────────────────────────────────────────────────────────────────────┤\n"
                   << "│ Host Allocator Active: " << occ.host_current_allocated_bytes << " B (Peak: "
                   << occ.host_peak_allocated_bytes << " B, " << occ.host_active_allocations << " blocks)\n"
                   << "│ Total Secured Spaces:  " << (occ.total_secured_capacity_bytes / 1024) << " KB capacity ("
                   << (occ.total_secured_used_bytes) << " B used)\n"
                   << "├──────────────────┬──────────────┬──────────────┬───────────────────────┤\n"
                   << "│ Domain           │ Capacity     │ Used         │ Modules / Services    │\n"
                   << "├──────────────────┼──────────────┼──────────────┼───────────────────────┤\n";
                for (const auto& d : occ.domains) {
                    ss << "│ " << d.domain_name;
                    for (size_t i = d.domain_name.length(); i < 16; ++i) ss << " ";
                    std::string cap_s = std::to_string(d.capacity_bytes / 1024) + " KB";
                    ss << " │ " << cap_s;
                    for (size_t i = cap_s.length(); i < 12; ++i) ss << " ";
                    std::string used_s = std::to_string(d.used_bytes) + " B";
                    ss << " │ " << used_s;
                    for (size_t i = used_s.length(); i < 12; ++i) ss << " ";
                    std::string mods_s = std::to_string(d.module_count) + " mods / " + std::to_string(d.service_count) + " svcs";
                    ss << " │ " << mods_s;
                    for (size_t i = mods_s.length(); i < 21; ++i) ss << " ";
                    ss << " │\n";
                }
                ss << "└──────────────────┴──────────────┴──────────────┴───────────────────────┘\n";
                return Result<Value>::success(Value(ss.str()));
            }
        );

        // --- TelemetryHub views (display functions over the native invoke streams) ---
        // Hub snapshots expose per-method invoke counts/durations; SystemInfo-gated.
        ctx.register_method("monitor.hub_snapshot", "Live TelemetryHub stream table (optional glob)",
            [this](const std::vector<Value>& args) -> Result<Value> {
                std::string glob = args.empty() ? "*" : args[0].to_string();
                return Result<Value>::success(Value(m_service->hub_snapshot_table(glob)));
            }
        );

        ctx.register_method("monitor.hub_top", "Top-N TelemetryHub streams by last value",
            [this](const std::vector<Value>& args) -> Result<Value> {
                size_t n = args.empty() ? 5 : static_cast<size_t>(args[0].as_int());
                return Result<Value>::success(Value(m_service->hub_top_table(n)));
            }
        );

        ctx.register_method("monitor.hub_dashboard", "Full hub dashboard + watches overview",
            [this](const std::vector<Value>& /*args*/) -> Result<Value> {
                auto* hub = m_service->hub();
                if (!hub) return Result<Value>::failure(StatusCode::NullPointer, "TelemetryHub unavailable");
                std::ostringstream ss;
                ss << m_service->hub_snapshot_table("*");
                ss << m_service->hub_top_table(10);
                ss << "Active watchdog watches: " << hub->list_watches().size() << "\n";
                return Result<Value>::success(Value(ss.str()));
            }
        );

        ctx.register_method("monitor.hub_watch", "Register a watchdog: (stream_glob, op, threshold, action[, module])",
            [this](const std::vector<Value>& args) -> Result<Value> {
                auto* hub = m_service->hub();
                if (!hub) return Result<Value>::failure(StatusCode::NullPointer, "TelemetryHub unavailable");
                if (args.size() < 4) {
                    return Result<Value>::failure(StatusCode::InvalidArg,
                        "monitor.hub_watch requires (stream_glob, op, threshold, action[, module])");
                }
                std::string module = args.size() > 4 ? args[4].to_string() : "";
                auto w_res = hub->watch(args[0].to_string(), args[1].to_string(),
                                        args[2].as_double(), args[3].to_string(), module);
                if (!w_res.is_ok()) {
                    return Result<Value>::failure(w_res.status(), w_res.error_message());
                }
                return Result<Value>::success(Value(static_cast<int64_t>(w_res.value())));
            }
        );

        if (m_logger) m_logger->info("MonitorModule initialized with live memory occupation tracking.");
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
    std::shared_ptr<MonitoringServiceImpl> m_service;
    std::shared_ptr<ILogger> m_logger;
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::MonitorModule)
