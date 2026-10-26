// libFuzzer harness: signatures.json parsing (hand-rolled string-find JSON scanner
// in module_loader.cpp — a local-attacker-controlled file).
#include "dvargosh/module_loader.hpp"
#include <cstdio>
#include <unordered_map>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const char* tmp = "/tmp/dvargosh_fuzz_signatures.json";
    FILE* f = std::fopen(tmp, "wb");
    if (!f) return 0;
    std::fwrite(data, 1, size, f);
    std::fclose(f);

    std::unordered_map<std::string, std::string> sigs;
    dvargosh::load_signatures_from_file(tmp, sigs); // must terminate & never overflow
    std::remove(tmp);
    return 0;
}
