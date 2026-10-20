#include "dvargosh/dvargosh.hpp"
#include "logger_interface.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>

namespace dvargosh {

class ConsoleLogger : public ILogger {
public:
    void log(LogLevel level, const std::string& message) override {
        const char* prefix = "[INFO]";
        const char* color = "\033[32m"; // Green
        switch (level) {
            case LogLevel::Debug:   prefix = "[DEBUG]"; color = "\033[36m"; break; // Cyan
            case LogLevel::Info:    prefix = "[INFO] "; color = "\033[32m"; break; // Green
            case LogLevel::Warning: prefix = "[WARN] "; color = "\033[33m"; break; // Yellow
            case LogLevel::Error:   prefix = "[ERROR]"; color = "\033[31m"; break; // Red
        }

        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm = *std::localtime(&in_time_t);

        std::cout << color << prefix << "\033[0m ["
                  << std::put_time(&tm, "%H:%M:%S") << "] "
                  << message << std::endl;
    }

    void info(const std::string& message) override { log(LogLevel::Info, message); }
    void warn(const std::string& message) override { log(LogLevel::Warning, message); }
    void error(const std::string& message) override { log(LogLevel::Error, message); }
    void debug(const std::string& message) override { log(LogLevel::Debug, message); }
};

class LoggerModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest s_manifest = []() {
            ModuleManifest m;
            m.name = "logger";
            m.version = Version{1, 0, 0};
            m.description = "Plug-and-play Console Logging Service";
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
        m_logger = std::make_shared<ConsoleLogger>();

        // Register typed service interface in global registry
        auto reg_res = ctx.register_service<ILogger>("logger", m_logger, Version{1, 0, 0});
        if (!reg_res.is_ok()) return reg_res;

        // Register dynamic RPC callable method "logger.log"
        auto meth_res = ctx.register_method(
            "logger.log",
            "Logs a message via dynamic global calling",
            [this](const std::vector<Value>& args) -> Result<Value> {
                if (args.empty()) {
                    return Result<Value>::failure(StatusCode::InvalidArg, "logger.log requires at least 1 string argument");
                }
                std::string msg = args[0].to_string();
                m_logger->info("[RPC] " + msg);
                return Result<Value>::success(Value(true));
            }
        );
        if (!meth_res.is_ok()) return meth_res;

        m_logger->info("LoggerModule loaded successfully into Dvargosh runtime.");
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext& /*ctx*/) override {
        if (m_logger) m_logger->debug("LoggerModule started.");
        return Result<void>::success();
    }

    Result<void> on_stop(ModuleContext& /*ctx*/) override {
        if (m_logger) m_logger->debug("LoggerModule stopping.");
        return Result<void>::success();
    }

    Result<void> on_unload(ModuleContext& /*ctx*/) override {
        if (m_logger) m_logger->info("LoggerModule unloaded.");
        m_logger.reset();
        return Result<void>::success();
    }

private:
    std::shared_ptr<ConsoleLogger> m_logger;
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::LoggerModule)
