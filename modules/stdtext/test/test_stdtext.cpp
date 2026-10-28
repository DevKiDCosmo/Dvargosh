// stdtext module tests: dynamic load + end-to-end binder-registered services.
#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

TEST_CASE(test_stdtext_module_services) {
    ScopedCallFrame test_frame("test_stdtext", "system");
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    loader.add_search_path("./build/modules");
    loader.add_search_path("./modules");
    loader.add_search_path("../build/modules");

    auto load_res = loader.load("stdtext");
    if (!load_res.is_ok()) {
        std::cout << " (skipping dynamic load, file not present yet) ";
        return;
    }
    ASSERT_TRUE(loader.is_loaded("stdtext"));

    auto& reg = *di->registry();
    auto invoke = [&](const std::string& method, std::vector<Value> args) {
        return reg.invoke(method, std::move(args), "host_test", "system", nullptr);
    };

    // Happy paths — zero Value boxing in the module, exact types on the wire.
    auto trimmed = invoke("stdtext.trim", {Value("   padded   ")});
    ASSERT_TRUE(trimmed.is_ok());
    ASSERT_EQ(trimmed.value().to_string(), "padded");

    auto upper = invoke("stdtext.to_upper", {Value(std::string("dvargosh"))});
    ASSERT_TRUE(upper.is_ok());
    ASSERT_EQ(upper.value().to_string(), "DVARGOSH");

    auto replaced = invoke("stdtext.replace", {Value("a-b-c"), Value("-"), Value("+")});
    ASSERT_TRUE(replaced.is_ok());
    ASSERT_EQ(replaced.value().to_string(), "a+b+c");

    auto repeated = invoke("stdtext.repeat", {Value("ab"), Value(static_cast<int64_t>(3))});
    ASSERT_TRUE(repeated.is_ok());
    ASSERT_EQ(repeated.value().to_string(), "ababab");

    auto padded = invoke("stdtext.pad_left", {Value("7"), Value(static_cast<int64_t>(3)), Value("0")});
    ASSERT_TRUE(padded.is_ok());
    ASSERT_EQ(padded.value().to_string(), "007");

    auto contains = invoke("stdtext.contains", {Value("hello world"), Value("world")});
    ASSERT_TRUE(contains.is_ok());
    ASSERT_EQ(contains.value().as_bool(), true);

    auto starts = invoke("stdtext.starts_with", {Value("hello world"), Value("hello")});
    ASSERT_TRUE(starts.is_ok());
    ASSERT_EQ(starts.value().as_bool(), true);

    auto len = invoke("stdtext.length", {Value(std::string("four"))});
    ASSERT_TRUE(len.is_ok());
    ASSERT_EQ(len.value().as_int(), 4);

    // Exact-arity enforcement comes free from the binder.
    auto arity = invoke("stdtext.repeat", {Value("ab")});
    ASSERT_FALSE(arity.is_ok());
    ASSERT_EQ(arity.status(), StatusCode::InvalidArg);

    // Type confusion is a loud TypeMismatch, never a silent conversion.
    auto confused = invoke("stdtext.to_upper", {Value(42.0)});
    ASSERT_FALSE(confused.is_ok());
    ASSERT_EQ(confused.status(), StatusCode::TypeMismatch);

    // Unload cleanly (binder-registered methods must be unregistered too).
    ASSERT_TRUE(loader.unload_module("stdtext").is_ok());
    auto gone = invoke("stdtext.trim", {Value("x")});
    ASSERT_FALSE(gone.is_ok());
    ASSERT_EQ(gone.status(), StatusCode::SymbolNotFound);
}
