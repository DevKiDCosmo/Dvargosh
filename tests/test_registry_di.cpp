#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

struct ITestService {
    virtual ~ITestService() = default;
    virtual int compute(int x) = 0;
};

struct TestServiceImpl : public ITestService {
    int compute(int x) override { return x * 3; }
};

TEST_CASE(test_typed_service_registry) {
    Registry reg;
    auto svc = std::make_shared<TestServiceImpl>();

    auto reg_res = reg.register_service<ITestService>("test_svc", svc, Version{1, 0, 0}, "mod_provider");
    ASSERT_TRUE(reg_res.is_ok());

    auto get_res = reg.get_service<ITestService>("test_svc");
    ASSERT_TRUE(get_res.is_ok());
    ASSERT_EQ(get_res.value()->compute(5), 15);

    // Duplicate registration should fail
    auto dup_res = reg.register_service<ITestService>("test_svc", svc, Version{1, 0, 0}, "mod_provider");
    ASSERT_FALSE(dup_res.is_ok());
    ASSERT_EQ(dup_res.status(), StatusCode::AlreadyExists);
}

TEST_CASE(test_dynamic_method_invocation) {
    Registry reg;
    reg.register_method("str.concat", "Concatenates two strings", "mod_str",
        [](const std::vector<Value>& args) -> Result<Value> {
            if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "Need 2 strings");
            return Result<Value>::success(Value(args[0].to_string() + args[1].to_string()));
        }
    );

    auto res = reg.invoke("str.concat", {Value("Hello, "), Value("World!")});
    ASSERT_TRUE(res.is_ok());
    ASSERT_EQ(res.value().to_string(), "Hello, World!");
}

TEST_CASE(test_event_bus) {
    EventBus bus;
    int received_count = 0;
    int received_val = 0;

    auto sub_res = bus.subscribe("system.alert", "test_sub", [&](const std::string&, const Value& val) {
        received_count++;
        received_val = static_cast<int>(val.as_int());
    });
    ASSERT_TRUE(sub_res.is_ok());

    bus.publish("system.alert", Value(99));
    ASSERT_EQ(received_count, 1);
    ASSERT_EQ(received_val, 99);

    bus.unsubscribe(sub_res.value());
    bus.publish("system.alert", Value(100));
    ASSERT_EQ(received_count, 1); // Not called after unsubscribe
}
