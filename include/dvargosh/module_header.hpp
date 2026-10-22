#pragma once

#include "types.hpp"
#include "permissions.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>

#ifndef DVARGOSH_ABI_VERSION_STR
#define DVARGOSH_ABI_VERSION_STR "dvargosh-abi-v1"
#endif

#ifndef DVARGOSH_MODULE_MAGIC
#define DVARGOSH_MODULE_MAGIC "DVARGOSH_MODULE_V1"
#endif

#define DVARGOSH_HEADER_MAGIC_V1 0x48534F4752415644ULL // "DVARGOSH" in 64-bit uint little endian

namespace dvargosh {

#pragma pack(push, 1)
/**
 * @brief Plain C-compatible packed binary header embedded directly into dynamic modules.
 * Can be inspected in .rodata without invoking dynamic constructors or initializing objects.
 */
struct ModuleHeaderRaw {
    uint64_t magic;             ///< DVARGOSH_HEADER_MAGIC_V1
    uint32_t header_version;    ///< Format revision (1)
    uint32_t header_size;       ///< sizeof(ModuleHeaderRaw)

    // Identity & Versioning
    char module_name[64];
    char version_str[32];
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t version_patch;

    // ABI & Build Determinism
    char abi_version[64];       ///< e.g. "dvargosh-abi-v1"
    char build_id[128];         ///< Deterministic build hash / commit
    char build_timestamp[64];   ///< ISO 8601 build timestamp
    char compiler_info[64];     ///< Compiler & platform identification

    // Isolation & Security Configuration
    char domain[64];            ///< Primary operational domain
    char supported_domains[512];///< Comma-separated list of authorized domains
    uint32_t secured_memory_kb; ///< Memory quota limit in KB
    uint32_t required_permissions_mask; ///< Bitmask of Permission enum

    // Attribution & Description
    char description[512];
    char author[64];

    // Exported Services Summary
    uint32_t services_count;
    char services_summary[1024];///< Comma-separated list of exported methods

    // Extended Flags
    uint64_t flags;
};
#pragma pack(pop)

} // namespace dvargosh

// C linkage symbols exported by modules compiled with metadata headers
extern "C" {
    #if defined(__GNUC__) || defined(__clang__)
    __attribute__((weak)) const dvargosh::ModuleHeaderRaw* dvargosh_get_module_header();
    #else
    const dvargosh::ModuleHeaderRaw* dvargosh_get_module_header();
    #endif
}

namespace dvargosh {

/**
 * @brief Strongly-typed C++ module header representation.
 * Enables zero-execution, read-only inspection of module binaries.
 */
struct ModuleHeader {
    std::string name;
    Version version;
    std::string version_str;
    std::string abi_version;
    std::string build_id;
    std::string build_timestamp;
    std::string compiler_info;
    std::string domain;
    std::vector<std::string> supported_domains;
    size_t secured_memory_bytes = 0;
    PermissionSet required_permissions;
    std::string description;
    std::string author;
    uint32_t services_count = 0;
    std::vector<std::string> services;
    uint64_t flags = 0;
    bool is_valid = false;

    Result<void> validate() const {
        if (!is_valid) {
            return Result<void>::failure(StatusCode::TypeMismatch, "Module header is invalid or uninitialized");
        }
        if (name.empty()) {
            return Result<void>::failure(StatusCode::InvalidArg, "Module name in header is empty");
        }
        if (abi_version.empty()) {
            return Result<void>::failure(StatusCode::TypeMismatch, "ABI version in module header is empty");
        }
        if (abi_version != DVARGOSH_ABI_VERSION_STR) {
            return Result<void>::failure(
                StatusCode::TypeMismatch,
                "ABI mismatch in module header: expected '" + std::string(DVARGOSH_ABI_VERSION_STR) +
                "', found '" + abi_version + "'"
            );
        }
        return Result<void>::success();
    }

    static Result<ModuleHeader> from_raw(const ModuleHeaderRaw& raw) {
        if (raw.magic != DVARGOSH_HEADER_MAGIC_V1) {
            return Result<ModuleHeader>::failure(StatusCode::TypeMismatch, "Invalid module header magic value");
        }
        if (raw.header_size != sizeof(ModuleHeaderRaw)) {
            return Result<ModuleHeader>::failure(StatusCode::TypeMismatch, "Module header size mismatch");
        }

        ModuleHeader h;
        h.name = std::string(raw.module_name, strnlen(raw.module_name, sizeof(raw.module_name)));
        h.version_str = std::string(raw.version_str, strnlen(raw.version_str, sizeof(raw.version_str)));
        h.version = Version{
            static_cast<uint16_t>(raw.version_major),
            static_cast<uint16_t>(raw.version_minor),
            static_cast<uint16_t>(raw.version_patch)
        };
        h.abi_version = std::string(raw.abi_version, strnlen(raw.abi_version, sizeof(raw.abi_version)));
        h.build_id = std::string(raw.build_id, strnlen(raw.build_id, sizeof(raw.build_id)));
        h.build_timestamp = std::string(raw.build_timestamp, strnlen(raw.build_timestamp, sizeof(raw.build_timestamp)));
        h.compiler_info = std::string(raw.compiler_info, strnlen(raw.compiler_info, sizeof(raw.compiler_info)));
        h.domain = std::string(raw.domain, strnlen(raw.domain, sizeof(raw.domain)));

        std::string raw_domains(raw.supported_domains, strnlen(raw.supported_domains, sizeof(raw.supported_domains)));
        std::stringstream ss(raw_domains);
        std::string dom;
        while (std::getline(ss, dom, ',')) {
            size_t s = dom.find_first_not_of(" \t");
            size_t e = dom.find_last_not_of(" \t");
            if (s != std::string::npos && e != std::string::npos) {
                h.supported_domains.push_back(dom.substr(s, e - s + 1));
            }
        }

        h.secured_memory_bytes = static_cast<size_t>(raw.secured_memory_kb) * 1024;
        h.required_permissions = PermissionSet(static_cast<Permission>(raw.required_permissions_mask));
        h.description = std::string(raw.description, strnlen(raw.description, sizeof(raw.description)));
        h.author = std::string(raw.author, strnlen(raw.author, sizeof(raw.author)));
        h.services_count = raw.services_count;

        std::string raw_svcs(raw.services_summary, strnlen(raw.services_summary, sizeof(raw.services_summary)));
        std::stringstream ss_s(raw_svcs);
        std::string svc;
        while (std::getline(ss_s, svc, ',')) {
            size_t s = svc.find_first_not_of(" \t");
            size_t e = svc.find_last_not_of(" \t");
            if (s != std::string::npos && e != std::string::npos) {
                h.services.push_back(svc.substr(s, e - s + 1));
            }
        }

        h.flags = raw.flags;
        h.is_valid = true;
        return Result<ModuleHeader>::success(std::move(h));
    }

    /**
     * @brief Reads and validates module header from an opened library handle.
     * Prioritizes direct read-only data (.rodata / rd) static const symbol inspection.
     */
    static Result<ModuleHeader> read_from_handle(void* lib_handle) {
        if (!lib_handle) {
            return Result<ModuleHeader>::failure(StatusCode::NullPointer, "Library handle is null");
        }
        // 1. Try exported static const symbol (directly in .rodata / rd, zero code execution)
        auto* raw = reinterpret_cast<const ModuleHeaderRaw*>(dlsym(lib_handle, "dvargosh_module_header"));
        if (raw) {
            return from_raw(*raw);
        }
        // 2. Try exported accessor function
        auto fn = reinterpret_cast<const ModuleHeaderRaw* (*)()>(dlsym(lib_handle, "dvargosh_get_module_header"));
        if (fn) {
            const ModuleHeaderRaw* raw_fn = fn();
            if (raw_fn) return from_raw(*raw_fn);
        }
        return Result<ModuleHeader>::failure(StatusCode::SymbolNotFound, "No Dvargosh module header found in library symbols");
    }

    /**
     * @brief Direct zero-execution inspection of module binary from disk.
     * Scans and parses the embedded ModuleHeaderRaw struct from .rodata / read-only data without dlopen().
     */
    static Result<ModuleHeader> read_from_file(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            return Result<ModuleHeader>::failure(StatusCode::NotFound, "Cannot open library file: " + filepath);
        }

        file.seekg(0, std::ios::end);
        std::streamsize file_size = file.tellg();
        file.seekg(0, std::ios::beg);

        const size_t header_sz = sizeof(ModuleHeaderRaw);
        if (file_size < static_cast<std::streamsize>(header_sz)) {
            return Result<ModuleHeader>::failure(StatusCode::TypeMismatch, "File smaller than ModuleHeaderRaw");
        }

        std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
            return Result<ModuleHeader>::failure(StatusCode::LoadFailed, "Failed to read library file: " + filepath);
        }

        const uint64_t magic = DVARGOSH_HEADER_MAGIC_V1;
        for (size_t i = 0; i + header_sz <= buffer.size(); ++i) {
            if (*reinterpret_cast<const uint64_t*>(buffer.data() + i) == magic) {
                const auto* candidate = reinterpret_cast<const ModuleHeaderRaw*>(buffer.data() + i);
                if (candidate->header_version == 1 && candidate->header_size == sizeof(ModuleHeaderRaw)) {
                    auto res = from_raw(*candidate);
                    if (res.is_ok()) {
                        return res;
                    }
                }
            }
        }

        // Fallback: safe dlopen + symbol inspection
        dlerror();
        void* handle = dlopen(filepath.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (!handle) {
            return Result<ModuleHeader>::failure(StatusCode::SymbolNotFound, "No Dvargosh module header found in binary");
        }
        auto res = read_from_handle(handle);
        dlclose(handle);
        return res;
    }
};

} // namespace dvargosh
