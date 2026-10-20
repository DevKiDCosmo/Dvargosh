#pragma once

#include <string>

namespace dvargosh {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log(LogLevel level, const std::string& message) = 0;
    virtual void info(const std::string& message) = 0;
    virtual void warn(const std::string& message) = 0;
    virtual void error(const std::string& message) = 0;
    virtual void debug(const std::string& message) = 0;
};

} // namespace dvargosh
