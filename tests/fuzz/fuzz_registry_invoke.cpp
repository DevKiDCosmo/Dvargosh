// libFuzzer harness: Registry::invoke with adversarial method names and argument
// vectors — protects alias resolution, Levenshtein suggestions, and the Value
// unboxing path (as_string-heavy code) from pathological input.
#include "dvargosh/registry.hpp"
#include "dvargosh/types.hpp"
#include <string>
#include <vector>

using dvargosh::Registry;
using dvargosh::Value;

static std::string to_str(const uint8_t* p, size_t n) {
    return std::string(reinterpret_cast<const char*>(p), n);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    Registry reg;

    // Deterministic seed method so some inputs resolve and exercise dispatch,
    // while most miss and exercise the not-found/suggestion path.
    (void)reg.register_method(
        "fuzz.seed", "seed", "fuzz", "fuzz:*",
        [](const std::vector<Value>& args) -> dvargosh::Result<Value> {
            return dvargosh::Result<Value>::success(Value(static_cast<int64_t>(args.size())));
        },
        nullptr);

    const uint8_t name_len = data[0];
    const uint8_t arg_count = data[1] % 6;
    std::string method = to_str(data + 2, size - 2 < name_len ? size - 2 : name_len);

    std::vector<Value> args;
    size_t offset = 2 + (size - 2 < name_len ? size - 2 : name_len);
    for (uint8_t i = 0; i < arg_count && offset < size; ++i) {
        const uint8_t tag = data[offset++] % 3;
        size_t take = (size - offset) / 2;
        if (tag == 0) {
            args.emplace_back(static_cast<double>(take));
        } else if (tag == 1) {
            args.emplace_back(to_str(data + offset, take));
            offset += take;
        } else {
            args.emplace_back(static_cast<int64_t>(take));
        }
    }

    auto res = reg.invoke(method, args, "fuzz_caller", "fuzz:*", nullptr);
    (void)res; // must never crash: OOB names, huge args, unicode soup, etc.
    return 0;
}
