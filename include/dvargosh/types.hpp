#pragma once

#include <string>
#include <variant>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <sstream>
#include <functional>
#include <optional>

namespace dvargosh {

/* Status Codes */
enum class StatusCode : int {
    Ok = 0,
    InvalidArg = -1,
    NullPointer = -2,
    OutOfMemory = -3,
    NotFound = -4,
    AlreadyExists = -5,
    LoadFailed = -6,
    SymbolNotFound = -7,
    DependencyUnsatisfied = -8,
    TypeMismatch = -9,
    InvocationFailed = -10,
    PermissionDenied = -11,
    SignatureInvalid = -12,
    QuotaExceeded = -13,
    SecurityTampering = -14,
    InternalError = -99
};

inline const char* status_code_to_string(StatusCode code) {
    switch (code) {
        case StatusCode::Ok: return "Ok";
        case StatusCode::InvalidArg: return "Invalid Argument";
        case StatusCode::NullPointer: return "Null Pointer";
        case StatusCode::OutOfMemory: return "Out of Memory";
        case StatusCode::NotFound: return "Not Found";
        case StatusCode::AlreadyExists: return "Already Exists";
        case StatusCode::LoadFailed: return "Load Failed";
        case StatusCode::SymbolNotFound: return "Symbol Not Found";
        case StatusCode::DependencyUnsatisfied: return "Dependency Unsatisfied";
        case StatusCode::TypeMismatch: return "Type Mismatch";
        case StatusCode::InvocationFailed: return "Invocation Failed";
        case StatusCode::PermissionDenied: return "Permission Denied";
        case StatusCode::SignatureInvalid: return "Signature Invalid";
        case StatusCode::QuotaExceeded: return "Quota Exceeded";
        case StatusCode::SecurityTampering: return "Security Tampering Detected";
        case StatusCode::InternalError: return "Internal Error";
        default: return "Unknown Error";
    }
}

inline std::ostream& operator<<(std::ostream& os, StatusCode code) {
    return os << status_code_to_string(code);
}

/* Exceptions */
class DvargoshException : public std::runtime_error {
public:
    explicit DvargoshException(StatusCode code, const std::string& msg)
        : std::runtime_error(std::string("[") + status_code_to_string(code) + "] " + msg),
          m_code(code) {}
    StatusCode code() const noexcept { return m_code; }
private:
    StatusCode m_code;
};

class SecurityException : public DvargoshException {
public:
    explicit SecurityException(const std::string& msg)
        : DvargoshException(StatusCode::PermissionDenied, msg) {}
};

class TamperingException : public DvargoshException {
public:
    explicit TamperingException(const std::string& msg)
        : DvargoshException(StatusCode::SecurityTampering, msg) {}
};

class MemoryLimitException : public DvargoshException {
public:
    explicit MemoryLimitException(const std::string& msg)
        : DvargoshException(StatusCode::QuotaExceeded, msg) {}
};

class SignatureException : public DvargoshException {
public:
    explicit SignatureException(const std::string& msg)
        : DvargoshException(StatusCode::SignatureInvalid, msg) {}
};

/* Result Type */
template<typename T>
class Result {
public:
    Result(T val) : m_value(std::move(val)), m_status(StatusCode::Ok) {}
    Result(StatusCode code, std::string err_msg = "")
        : m_value(std::nullopt), m_status(code), m_message(std::move(err_msg)) {}

    static Result<T> success(T val) { return Result<T>(std::move(val)); }
    static Result<T> failure(StatusCode code, std::string err_msg = "") {
        return Result<T>(code, std::move(err_msg));
    }

    bool is_ok() const noexcept { return m_status == StatusCode::Ok; }
    bool is_err() const noexcept { return !is_ok(); }

    const T& value() const {
        if (!is_ok()) {
            throw DvargoshException(m_status, m_message.empty() ? status_code_to_string(m_status) : m_message);
        }
        return *m_value;
    }

    T& value() {
        if (!is_ok()) {
            throw DvargoshException(m_status, m_message.empty() ? status_code_to_string(m_status) : m_message);
        }
        return *m_value;
    }

    T value_or(T default_val) const {
        return is_ok() ? *m_value : default_val;
    }

    StatusCode status() const noexcept { return m_status; }
    const std::string& error_message() const noexcept { return m_message; }

private:
    std::optional<T> m_value;
    StatusCode m_status;
    std::string m_message;
};

/* Void specialization for Result<void> */
template<>
class Result<void> {
public:
    Result() : m_status(StatusCode::Ok) {}
    Result(StatusCode code, std::string err_msg = "")
        : m_status(code), m_message(std::move(err_msg)) {}

    static Result<void> success() { return Result<void>(); }
    static Result<void> failure(StatusCode code, std::string err_msg = "") {
        return Result<void>(code, std::move(err_msg));
    }

    bool is_ok() const noexcept { return m_status == StatusCode::Ok; }
    bool is_err() const noexcept { return !is_ok(); }

    void value() const {
        if (!is_ok()) {
            throw DvargoshException(m_status, m_message.empty() ? status_code_to_string(m_status) : m_message);
        }
    }

    StatusCode status() const noexcept { return m_status; }
    const std::string& error_message() const noexcept { return m_message; }

private:
    StatusCode m_status;
    std::string m_message;
};

/* Version Struct */
struct Version {
    uint16_t major = 1;
    uint16_t minor = 0;
    uint16_t patch = 0;

    constexpr Version() = default;
    constexpr Version(uint16_t maj, uint16_t min, uint16_t pat)
        : major(maj), minor(min), patch(pat) {}

    bool operator==(const Version& o) const noexcept {
        return major == o.major && minor == o.minor && patch == o.patch;
    }
    bool operator!=(const Version& o) const noexcept { return !(*this == o); }
    bool operator<(const Version& o) const noexcept {
        if (major != o.major) return major < o.major;
        if (minor != o.minor) return minor < o.minor;
        return patch < o.patch;
    }
    bool operator>=(const Version& o) const noexcept { return !(*this < o); }

    std::string to_string() const {
        std::ostringstream ss;
        ss << major << "." << minor << "." << patch;
        return ss.str();
    }
};

/* Variant Value for Global Calling / Dynamic RPC */
class Value {
public:
    using VariantType = std::variant<
        std::monostate,
        bool,
        int64_t,
        double,
        std::string,
        void*,
        std::vector<uint8_t>
    >;

    Value() : m_var(std::monostate{}) {}
    Value(bool b) : m_var(b) {}
    Value(int i) : m_var(static_cast<int64_t>(i)) {}
    Value(int64_t i) : m_var(i) {}
    Value(double d) : m_var(d) {}
    Value(const char* s) : m_var(std::string(s ? s : "")) {}
    Value(std::string s) : m_var(std::move(s)) {}
    Value(void* ptr) : m_var(ptr) {}
    Value(std::vector<uint8_t> bytes) : m_var(std::move(bytes)) {}

    bool is_nil() const noexcept { return std::holds_alternative<std::monostate>(m_var); }
    bool is_bool() const noexcept { return std::holds_alternative<bool>(m_var); }
    bool is_int() const noexcept { return std::holds_alternative<int64_t>(m_var); }
    bool is_double() const noexcept { return std::holds_alternative<double>(m_var); }
    bool is_string() const noexcept { return std::holds_alternative<std::string>(m_var); }
    bool is_ptr() const noexcept { return std::holds_alternative<void*>(m_var); }
    bool is_bytes() const noexcept { return std::holds_alternative<std::vector<uint8_t>>(m_var); }

    // Typed accessors throw DvargoshException (not std::bad_variant_access) on type
    // mismatch: a type-confused RPC argument must be a loud, catchable error at every
    // call site — Registry::invoke already wraps method bodies accordingly.
    [[noreturn]] void type_error(const char* accessor) const {
        throw DvargoshException(
            StatusCode::TypeMismatch,
            std::string("Value::") + accessor + "(): value holds '" + to_string() + "'"
        );
    }

    bool as_bool() const {
        if (!is_bool()) type_error("as_bool");
        return std::get<bool>(m_var);
    }
    int64_t as_int() const {
        if (!is_int()) type_error("as_int");
        return std::get<int64_t>(m_var);
    }
    double as_double() const {
        if (is_double()) return std::get<double>(m_var);
        if (is_int()) return static_cast<double>(std::get<int64_t>(m_var));
        if (is_bool()) return std::get<bool>(m_var) ? 1.0 : 0.0;
        type_error("as_double");
    }
    const std::string& as_string() const { return std::get<std::string>(m_var); }
    void* as_ptr() const { return std::get<void*>(m_var); }
    const std::vector<uint8_t>& as_bytes() const { return std::get<std::vector<uint8_t>>(m_var); }

    std::string to_string() const {
        if (is_nil()) return "nil";
        if (is_bool()) return as_bool() ? "true" : "false";
        if (is_int()) return std::to_string(as_int());
        if (is_double()) return std::to_string(as_double());
        if (is_string()) return as_string();
        if (is_ptr()) {
            std::ostringstream ss;
            ss << as_ptr();
            return ss.str();
        }
        if (is_bytes()) {
            return "<binary " + std::to_string(as_bytes().size()) + " bytes>";
        }
        return "unknown";
    }

private:
    VariantType m_var;
};

} // namespace dvargosh
