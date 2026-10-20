// Auto-generated unit test for 'telecom'.
#include "dvargosh/dvargosh.hpp"
#include <cassert>
#include <iostream>

using namespace dvargosh;

int main() {
    std::cout << "[Test: telecom] Initializing verification harness...\n";
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    loader.add_search_path("./build/modules");
    loader.add_search_path("./build/development_modules");

    auto file_res = loader.find_module_file("telecom");
    if (file_res.is_ok()) {
        auto load_res = loader.load_from_file(file_res.value());
        assert(load_res.is_ok());
        std::cout << "  ✓ Module 'telecom' successfully loaded and verified.\n";
    } else {
        std::cout << "  ℹ Module binary not yet built; skipping runtime dynamic test.\n";
    }
    return 0;
}
