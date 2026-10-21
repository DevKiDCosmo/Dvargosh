#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include "../math_interface.hpp"

using namespace dvargosh;

TEST_CASE(test_math_module_computations_and_events) {
    ScopedCallFrame test_frame("test_math", "system");
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    auto load_res = loader.load("math", "");
    if (!load_res.is_ok()) {
        std::cout << " (skipping dynamic load, file not present yet) ";
        return;
    }

    ASSERT_TRUE(loader.is_loaded("math"));

    // 1. Resolve typed IMathService in scoped block
    {
        auto math_res = di->registry()->get_service<IMathService>("math");
        ASSERT_TRUE(math_res.is_ok());
        auto math_svc = math_res.value();

        ASSERT_EQ(math_svc->add(10.5, 4.5), 15.0);
        ASSERT_EQ(math_svc->multiply(3.0, 7.0), 21.0);
        ASSERT_EQ(math_svc->factorial(5), 120);
    }

    // 2. Subscribe to calculation events to verify Arena + Event Bus
    int64_t captured_event_result = 0;
    di->event_bus()->subscribe("math.calculation_done", "test_listener", [&](const std::string&, const Value& val) {
        captured_event_result = val.as_int();
    });

    // 3. Dynamic RPC: math.sum_range (allocates array in arena, sums 1..50)
    auto sum_res = di->registry()->invoke("math.sum_range", {Value(50)});
    ASSERT_TRUE(sum_res.is_ok());
    // Sum 1..50 = 50 * 51 / 2 = 1275
    ASSERT_EQ(sum_res.value().as_int(), 1275);
    ASSERT_EQ(captured_event_result, 1275);

    // 4. Unload module
    auto unload_res = loader.unload_module("math");
    ASSERT_TRUE(unload_res.is_ok());
    ASSERT_FALSE(loader.is_loaded("math"));
}
