#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

static bool g_custom_resource_destroyed = false;

struct MockResource {
    ~MockResource() {
        g_custom_resource_destroyed = true;
    }
};

class MockModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest m = []() {
            ModuleManifest man;
            man.name = "mock_mod";
            man.version = Version{1, 0, 0};
            man.description = "Mock module for lifecycle unit testing";
            man.requested_permissions = PermissionSet::all();
            return man;
        }();
        return m;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        // Track a resource
        g_custom_resource_destroyed = false;
        ctx.track_resource("mock_res", std::make_unique<MockResource>());

        // Register a dynamic method
        ctx.register_method("mock.ping", "ping", [](const std::vector<Value>&) -> Result<Value> {
            return Result<Value>::success(Value("pong"));
        });
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }
};

TEST_CASE(test_module_lifecycle_and_scoped_cleanup) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    // Load static module
    auto load_res = loader.load_static_module(std::make_unique<MockModule>());
    ASSERT_TRUE(load_res.is_ok());
    ASSERT_TRUE(loader.is_loaded("mock_mod"));
    ASSERT_FALSE(g_custom_resource_destroyed);

    // Call method
    auto ping_res = di->registry()->invoke("mock.ping");
    ASSERT_TRUE(ping_res.is_ok());
    ASSERT_EQ(ping_res.value().to_string(), "pong");

    // Unload module
    auto unload_res = loader.unload_module("mock_mod");
    ASSERT_TRUE(unload_res.is_ok());
    ASSERT_FALSE(loader.is_loaded("mock_mod"));

    // Verify owned resource was destroyed automatically
    ASSERT_TRUE(g_custom_resource_destroyed);

    // Verify registered method was cleaned up
    auto post_res = di->registry()->invoke("mock.ping");
    ASSERT_FALSE(post_res.is_ok());
    ASSERT_EQ(post_res.status(), StatusCode::NotFound);
}
