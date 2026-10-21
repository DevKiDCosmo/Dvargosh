#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <cstdlib>

namespace dvargosh::test {

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& get_registry() {
    static std::vector<TestCase> s_cases;
    return s_cases;
}

inline void register_test(const std::string& name, std::function<void()> fn) {
    get_registry().push_back({name, std::move(fn)});
}

#define TEST_CASE(name) \
    void name(); \
    namespace { \
        struct Reg_##name { \
            Reg_##name() { ::dvargosh::test::register_test(#name, name); } \
        } s_reg_##name; \
    } \
    void name()

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "Assertion FAILED: (" #cond ") at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_NE(a, b) \
    do { \
        if ((a) == (b)) { \
            std::cerr << "Assertion FAILED: (" #a " != " #b ") [" << (a) << " == " << (b) << "] at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if (!((a) == (b))) { \
            std::cerr << "Assertion FAILED: (" #a " == " #b ") [" << (a) << " != " << (b) << "] at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

} // namespace dvargosh::test
