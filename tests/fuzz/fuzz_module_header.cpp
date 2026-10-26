// libFuzzer harness: ModuleHeader parsing.
// The module binary header is the runtime's primary untrusted-input surface:
// read_from_file() scans arbitrary bytes and reinterprets them as a packed struct.
// Build: ENABLE_FUZZING=ON preset (see CMakePresets.json).
#include "dvargosh/module_header.hpp"
#include <cstring>
#include <cstdio>
#include <vector>

using dvargosh::ModuleHeader;
using dvargosh::ModuleHeaderRaw;

static void exercise_from_raw(const uint8_t* data, size_t size) {
    // Direct struct parse: mimic a module whose .rodata contains exactly our struct.
    std::vector<uint8_t> buf(sizeof(ModuleHeaderRaw), 0);
    std::memcpy(buf.data(), data, size < buf.size() ? size : buf.size());
    const auto* raw = reinterpret_cast<const ModuleHeaderRaw*>(buf.data());
    auto res = ModuleHeader::from_raw(*raw);
    (void)res; // must never crash regardless of field contents
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    exercise_from_raw(data, size);

    // Full disk path: magic scan loop + header validation (+ safe dlopen fallback).
    const char* tmp = "/tmp/dvargosh_fuzz_module.dylib";
    FILE* f = std::fopen(tmp, "wb");
    if (!f) return 0;
    std::fwrite(data, 1, size, f);
    std::fclose(f);

    auto res = ModuleHeader::read_from_file(tmp);
    (void)res;
    std::remove(tmp);
    return 0;
}
