#include "test_framework.hpp"
#include <iostream>

int main() {
    std::cout << "=========================================\n";
    std::cout << "       DVARGOSH UNIT TEST SUITE          \n";
    std::cout << "=========================================\n";

    const auto& tests = dvargosh::test::get_registry();
    std::cout << "Running " << tests.size() << " test cases...\n\n";

    size_t passed = 0;
    for (const auto& test : tests) {
        std::cout << "  [RUN]  " << test.name << "..." << std::flush;
        try {
            test.fn();
            std::cout << " \033[32m[PASS]\033[0m\n";
            passed++;
        } catch (const std::exception& e) {
            std::cout << " \033[31m[FAIL: " << e.what() << "]\033[0m\n";
        } catch (...) {
            std::cout << " \033[31m[FAIL: unknown exception]\033[0m\n";
        }
    }

    std::cout << "\n-----------------------------------------\n";
    std::cout << "Result: " << passed << "/" << tests.size() << " tests passed.\n";
    std::cout << "=========================================\n";

    return (passed == tests.size()) ? 0 : 1;
}
