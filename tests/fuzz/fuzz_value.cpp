// libFuzzer harness: Value boxing/unboxing round-trips (the payload type of every RPC).
#include "dvargosh/types.hpp"
#include <string>
#include <vector>

using dvargosh::Value;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    const uint8_t tag = data[0] % 5;
    const uint8_t* payload = data + 1;
    const size_t payload_size = size - 1;

    Value v;
    switch (tag) {
        case 0: v = Value(static_cast<double>(payload_size)); break;
        case 1: v = Value(static_cast<int64_t>(payload_size)); break;
        case 2: v = Value((payload_size % 2) == 0); break;
        case 3: v = Value(std::string(reinterpret_cast<const char*>(payload), payload_size)); break;
        default: v = Value(std::vector<uint8_t>(payload, payload + payload_size)); break;
    }

    // Every accessor must tolerate every value shape without crashing the process.
    // Type mismatches legitimately throw DvargoshException (catchable everywhere);
    // what this harness asserts is: no abort, no UB, no unhandled crash.
    std::string s = v.to_string();
    (void)s;
    try {
        volatile double d = v.as_double();
        (void)d;
    } catch (...) {
    }
    return 0;
}
