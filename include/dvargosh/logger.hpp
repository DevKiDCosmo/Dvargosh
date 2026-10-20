#pragma once

#include <iostream>
#include <sstream>
#include <string>
#include <mutex>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <utility>

namespace dvargosh {

/**
 * @brief Log Severity Levels.
 */
enum class LogSeverity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal
};

/**
 * @brief Full-featured, Zero-Conversion C++ Logger.
 *
 * Accepts arbitrary original C++ types (integers, floating point, booleans, strings,
 * raw pointers, custom types with operator<<) natively without manual conversion to
 * strings or Value variant boxing.
 */
class Logger {
public:
    static Logger& instance() {
        static Logger s_inst;
        return s_inst;
    }

    void set_level(LogSeverity level) noexcept {
        m_min_level = level;
    }

    LogSeverity level() const noexcept {
        return m_min_level;
    }

    void set_colored(bool enabled) noexcept {
        m_colored = enabled;
    }

    /**
     * @brief Logs an arbitrary sequence of native C++ arguments at the specified severity.
     */
    template <typename... Args>
    void log(LogSeverity severity, Args&&... args) {
        if (severity < m_min_level) return;

        std::ostringstream oss;
        (oss << ... << std::forward<Args>(args));
        write_record(severity, oss.str());
    }

    template <typename... Args>
    void trace(Args&&... args) {
        log(LogSeverity::Trace, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void debug(Args&&... args) {
        log(LogSeverity::Debug, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void info(Args&&... args) {
        log(LogSeverity::Info, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void warn(Args&&... args) {
        log(LogSeverity::Warn, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void error(Args&&... args) {
        log(LogSeverity::Error, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void fatal(Args&&... args) {
        log(LogSeverity::Fatal, std::forward<Args>(args)...);
    }

    /**
     * @brief Stream helper for stream-style syntax: logger.stream(LogSeverity::Info) << a << b;
     */
    class StreamLogger {
    public:
        StreamLogger(Logger& parent, LogSeverity severity)
            : m_parent(parent), m_severity(severity), m_active(severity >= parent.level()) {}

        ~StreamLogger() {
            if (m_active) {
                m_parent.write_record(m_severity, m_ss.str());
            }
        }

        template <typename T>
        StreamLogger& operator<<(const T& val) {
            if (m_active) {
                m_ss << val;
            }
            return *this;
        }

    private:
        Logger& m_parent;
        LogSeverity m_severity;
        bool m_active;
        std::ostringstream m_ss;
    };

    StreamLogger stream(LogSeverity severity) {
        return StreamLogger(*this, severity);
    }

    StreamLogger info_stream()  { return stream(LogSeverity::Info); }
    StreamLogger warn_stream()  { return stream(LogSeverity::Warn); }
    StreamLogger error_stream() { return stream(LogSeverity::Error); }
    StreamLogger debug_stream() { return stream(LogSeverity::Debug); }

private:
    Logger() = default;

    void write_record(LogSeverity severity, const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        std::tm tm_buf{};
#if defined(_WIN32)
        localtime_s(&tm_buf, &in_time_t);
#else
        localtime_r(&in_time_t, &tm_buf);
#endif

        const char* color = "";
        const char* reset = "\033[0m";
        const char* tag = "INFO";

        switch (severity) {
            case LogSeverity::Trace: color = "\033[37m"; tag = "TRACE"; break;
            case LogSeverity::Debug: color = "\033[36m"; tag = "DEBUG"; break;
            case LogSeverity::Info:  color = "\033[32m"; tag = "INFO "; break;
            case LogSeverity::Warn:  color = "\033[33m"; tag = "WARN "; break;
            case LogSeverity::Error: color = "\033[31m"; tag = "ERROR"; break;
            case LogSeverity::Fatal: color = "\033[1;31m"; tag = "FATAL"; break;
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_colored) {
            std::cout << "\033[90m["
                      << std::put_time(&tm_buf, "%H:%M:%S")
                      << "." << std::setfill('0') << std::setw(3) << ms.count()
                      << "]\033[0m "
                      << color << "[" << tag << "]" << reset << " "
                      << message << "\n";
        } else {
            std::cout << "["
                      << std::put_time(&tm_buf, "%H:%M:%S")
                      << "." << std::setfill('0') << std::setw(3) << ms.count()
                      << "] [" << tag << "] "
                      << message << "\n";
        }
    }

    LogSeverity m_min_level = LogSeverity::Info;
    bool m_colored = true;
    std::mutex m_mutex;
};

// Global convenience functions accepting any original C++ types
template <typename... Args>
inline void log_info(Args&&... args) {
    Logger::instance().info(std::forward<Args>(args)...);
}

template <typename... Args>
inline void log_warn(Args&&... args) {
    Logger::instance().warn(std::forward<Args>(args)...);
}

template <typename... Args>
inline void log_error(Args&&... args) {
    Logger::instance().error(std::forward<Args>(args)...);
}

template <typename... Args>
inline void log_debug(Args&&... args) {
    Logger::instance().debug(std::forward<Args>(args)...);
}

} // namespace dvargosh
