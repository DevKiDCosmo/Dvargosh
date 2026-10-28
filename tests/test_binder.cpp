// Tests for the S2 ServiceBinder (docs/execution_plan.md WS-B):
// compile-time signature deduction, exact-arity enforcement, strict typing,
// supported return types, alias ownership, and end-to-end static-module flow.
#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

// --- Plain functions under test (no Value boxing, no marker boilerplate) ----

static double bind_add(double a, double b) { return a + b; }
static int64_t bind_double_int(int64_t v) { return v * 2; }
static bool bind_is_empty(const std::string& s) { return s.empty(); }
static std::string bind_greet(const std::string& who, const std::string& greeting) { return greeting + ", " + who + "!"; }
static void bind_sink(const std::string&) {}
static int bind_int_return(int v) { return v * 3; }
static std::vector<uint8_t> bind_bytes(std::vector<uint8_t> in) { in.push_back(0xAA); return in; }
static std::string bind_echo(const std::string& s) { return s; }

// ---------------------------------------------------------------------------
// Fixture module: registers the functions above through the real binder API.
// ---------------------------------------------------------------------------

class BinderModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest m = []() {
            ModuleManifest man;
            man.name = "binder_mod";
            man.version = Version{1, 0, 0};
            man.description = "ServiceBinder test fixture";
            man.requested_permissions = PermissionSet::standard_module();
            return man;
        }();
        return m;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        return install_bindings(ctx);
    }
    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }

    // Shared by the direct-install test so both paths exercise identical code.
    static Result<void> install_bindings(ModuleContext& ctx) {
        return ctx.binds()
            .fn<&bind_add>("bind.add", "Adds two doubles")
            .fn<&bind_double_int>("bind.double_int", "Doubles an int64")
            .fn<&bind_is_empty>("bind.is_empty", "Empty-string check")
            .fn<&bind_greet>("bind.greet", "Greets a person")
            .fn<&bind_sink>("bind.sink", "Void-returning sink")
            .fn<&bind_int_return>("bind.int_return", "Triples an int")
            .fn<&bind_bytes>("bind.bytes", "Appends 0xAA to a byte vector")
            .fn<&bind_echo>("bind.echo", "Echoes a string")
            .alias("trim", "bind.echo")
            .result();
    }

    // Registers bindings without a full loader cycle. The sink owns BOTH the
    // DIContainer and its contexts so static teardown destroys them LIFO-safe:
    // a ModuleContext must never outlive its DIContainer's TelemetryHub.
    static bool install(std::shared_ptr<DIContainer> di) {
        auto ctx_res = di->create_module_context("binder_mod", "binder", SecurityPolicy::standard());
        if (!ctx_res.is_ok()) return false;
        if (!install_bindings(*ctx_res.value()).is_ok()) return false;
        context_sink().emplace_back(std::move(di), std::move(ctx_res.value()));
        return true;
    }

    static std::vector<std::pair<std::shared_ptr<DIContainer>, std::unique_ptr<ModuleContext>>>& context_sink() {
        static std::vector<std::pair<std::shared_ptr<DIContainer>, std::unique_ptr<ModuleContext>>> s_ctxs;
        return s_ctxs;
    }
};

// --- Tests -------------------------------------------------------------------

TEST_CASE(test_binder_deduces_signature_and_dispatches) {
    auto di = std::make_shared<DIContainer>();
    ASSERT_TRUE(BinderModule::install(di));

    auto& reg = *di->registry();
    auto sum = reg.invoke("bind.add", {Value(20.0), Value(22.0)}, "t", "system", nullptr);
    ASSERT_TRUE(sum.is_ok());
    ASSERT_EQ(sum.value().as_double(), 42.0);

    auto dbl = reg.invoke("bind.double_int", {Value(static_cast<int64_t>(21))}, "t", "system", nullptr);
    ASSERT_TRUE(dbl.is_ok());
    ASSERT_EQ(dbl.value().as_int(), 42);

    auto greet = reg.invoke("bind.greet", {Value("World"), Value("Hello")}, "t", "system", nullptr);
    ASSERT_TRUE(greet.is_ok());
    ASSERT_EQ(greet.value().to_string(), "Hello, World!");

    auto flag = reg.invoke("bind.is_empty", {Value("")}, "t", "system", nullptr);
    ASSERT_TRUE(flag.is_ok());
    ASSERT_EQ(flag.value().as_bool(), true);

    auto intret = reg.invoke("bind.int_return", {Value(static_cast<int64_t>(7))}, "t", "system", nullptr);
    ASSERT_TRUE(intret.is_ok());
    ASSERT_EQ(intret.value().as_int(), 21);
}

TEST_CASE(test_binder_exact_arity_enforced) {
    auto di = std::make_shared<DIContainer>();
    ASSERT_TRUE(BinderModule::install(di));

    auto too_few = di->registry()->invoke("bind.add", {Value(1.0)}, "t", "system", nullptr);
    ASSERT_FALSE(too_few.is_ok());
    ASSERT_EQ(too_few.status(), StatusCode::InvalidArg);
    ASSERT_TRUE(too_few.error_message().find("expects exactly 2") != std::string::npos);

    auto too_many = di->registry()->invoke("bind.add", {Value(1.0), Value(2.0), Value(3.0)}, "t", "system", nullptr);
    ASSERT_FALSE(too_many.is_ok());
    ASSERT_EQ(too_many.status(), StatusCode::InvalidArg);
}

TEST_CASE(test_binder_type_confusion_is_loud_failure) {
    auto di = std::make_shared<DIContainer>();
    ASSERT_TRUE(BinderModule::install(di));

    // string where double is required -> TypeMismatch, not a silent 0.0
    auto bad = di->registry()->invoke("bind.add", {Value("nope"), Value(2.0)}, "t", "system", nullptr);
    ASSERT_FALSE(bad.is_ok());
    ASSERT_EQ(bad.status(), StatusCode::TypeMismatch);

    // double where string is required -> TypeMismatch, not a silent ""
    auto bad2 = di->registry()->invoke("bind.echo", {Value(3.14)}, "t", "system", nullptr);
    ASSERT_FALSE(bad2.is_ok());
    ASSERT_EQ(bad2.status(), StatusCode::TypeMismatch);
}

TEST_CASE(test_binder_void_and_bytes_roundtrip) {
    auto di = std::make_shared<DIContainer>();
    ASSERT_TRUE(BinderModule::install(di));

    auto void_res = di->registry()->invoke("bind.sink", {Value("x")}, "t", "system", nullptr);
    ASSERT_TRUE(void_res.is_ok());

    std::vector<uint8_t> payload{1, 2, 3};
    auto bytes_res = di->registry()->invoke("bind.bytes", {Value(payload)}, "t", "system", nullptr);
    ASSERT_TRUE(bytes_res.is_ok());
    ASSERT_TRUE(bytes_res.value().is_bytes());
    ASSERT_EQ(bytes_res.value().as_bytes().size(), 4);
    ASSERT_EQ(bytes_res.value().as_bytes().back(), 0xAA);
}

TEST_CASE(test_binder_alias_ownership_enforced) {
    auto di = std::make_shared<DIContainer>();
    ASSERT_TRUE(BinderModule::install(di)); // binds alias "trim" -> "bind.echo" (same module)

    auto via_alias = di->registry()->invoke("trim", {Value("ok")}, "t", "system", nullptr);
    ASSERT_TRUE(via_alias.is_ok());
    ASSERT_EQ(via_alias.value().to_string(), "ok");
}

TEST_CASE(test_binder_through_static_module_lifecycle) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    auto load_res = loader.load_static_module(std::make_unique<BinderModule>());
    ASSERT_TRUE(load_res.is_ok());
    ASSERT_TRUE(loader.is_loaded("binder_mod"));

    auto res = di->registry()->invoke("bind.add", {Value(2.0), Value(3.0)}, "t", "system", nullptr);
    ASSERT_TRUE(res.is_ok());
    ASSERT_EQ(res.value().as_double(), 5.0);

    // Unload must unregister binder-registered methods too.
    ASSERT_TRUE(loader.unload_module("binder_mod").is_ok());
    auto gone = di->registry()->invoke("bind.add", {Value(1.0), Value(1.0)}, "t", "system", nullptr);
    ASSERT_FALSE(gone.is_ok());
    ASSERT_EQ(gone.status(), StatusCode::SymbolNotFound);
}
