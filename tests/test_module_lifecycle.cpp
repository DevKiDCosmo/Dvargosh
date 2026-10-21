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
    ASSERT_EQ(post_res.status(), StatusCode::SymbolNotFound);
}

TEST_CASE(test_module_header_raw_validation) {
    ModuleHeaderRaw raw{};
    raw.magic = DVARGOSH_HEADER_MAGIC_V1;
    raw.header_version = 1;
    raw.header_size = sizeof(ModuleHeaderRaw);
    std::strncpy(raw.module_name, "test_mod", sizeof(raw.module_name) - 1);
    std::strncpy(raw.version_str, "2.3.4", sizeof(raw.version_str) - 1);
    raw.version_major = 2;
    raw.version_minor = 3;
    raw.version_patch = 4;
    std::strncpy(raw.abi_version, DVARGOSH_ABI_VERSION_STR, sizeof(raw.abi_version) - 1);
    std::strncpy(raw.build_id, "bld_test123", sizeof(raw.build_id) - 1);
    std::strncpy(raw.domain, "test:domain", sizeof(raw.domain) - 1);
    std::strncpy(raw.supported_domains, "test:domain, test:worker, *", sizeof(raw.supported_domains) - 1);
    raw.secured_memory_kb = 4096;
    raw.required_permissions_mask = 0x83; // MemoryExpand | FileIO | SecuredMemory
    std::strncpy(raw.description, "Test module header description", sizeof(raw.description) - 1);
    std::strncpy(raw.author, "Test Author", sizeof(raw.author) - 1);
    raw.services_count = 2;
    std::strncpy(raw.services_summary, "test_mod.fn1, test_mod.fn2", sizeof(raw.services_summary) - 1);

    auto res = ModuleHeader::from_raw(raw);
    ASSERT_TRUE(res.is_ok());
    auto hdr = res.value();
    ASSERT_EQ(hdr.name, "test_mod");
    ASSERT_EQ(hdr.version.major, 2);
    ASSERT_EQ(hdr.version.minor, 3);
    ASSERT_EQ(hdr.version.patch, 4);
    ASSERT_EQ(hdr.version_str, "2.3.4");
    ASSERT_EQ(hdr.abi_version, DVARGOSH_ABI_VERSION_STR);
    ASSERT_EQ(hdr.build_id, "bld_test123");
    ASSERT_EQ(hdr.domain, "test:domain");
    ASSERT_EQ(hdr.secured_memory_bytes, 4096 * 1024);
    ASSERT_EQ(hdr.supported_domains.size(), 3);
    ASSERT_EQ(hdr.supported_domains[0], "test:domain");
    ASSERT_EQ(hdr.supported_domains[1], "test:worker");
    ASSERT_EQ(hdr.supported_domains[2], "*");
    ASSERT_EQ(hdr.services.size(), 2);
    ASSERT_EQ(hdr.services[0], "test_mod.fn1");
    ASSERT_EQ(hdr.services[1], "test_mod.fn2");
    ASSERT_TRUE(hdr.validate().is_ok());

    // Test Corrupt Magic Rejection
    raw.magic = 0xDEADBEEF;
    auto bad_magic = ModuleHeader::from_raw(raw);
    ASSERT_FALSE(bad_magic.is_ok());
    ASSERT_EQ(bad_magic.status(), StatusCode::TypeMismatch);
    raw.magic = DVARGOSH_HEADER_MAGIC_V1;

    // Test Header Size Mismatch Rejection
    raw.header_size = sizeof(ModuleHeaderRaw) - 16;
    auto bad_sz = ModuleHeader::from_raw(raw);
    ASSERT_FALSE(bad_sz.is_ok());
    raw.header_size = sizeof(ModuleHeaderRaw);

    // Test Empty Name Rejection
    raw.module_name[0] = '\0';
    auto empty_name = ModuleHeader::from_raw(raw);
    ASSERT_TRUE(empty_name.is_ok());
    ASSERT_FALSE(empty_name.value().validate().is_ok());
    ASSERT_EQ(empty_name.value().validate().status(), StatusCode::InvalidArg);
    std::strncpy(raw.module_name, "test_mod", sizeof(raw.module_name) - 1);

    // Test ABI Version Mismatch Rejection
    std::strncpy(raw.abi_version, "dvargosh-abi-v999", sizeof(raw.abi_version) - 1);
    auto bad_abi = ModuleHeader::from_raw(raw);
    ASSERT_TRUE(bad_abi.is_ok());
    ASSERT_FALSE(bad_abi.value().validate().is_ok());
    ASSERT_EQ(bad_abi.value().validate().status(), StatusCode::TypeMismatch);
}

TEST_CASE(test_module_header_zero_execution_inspection_from_binary) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    loader.add_search_path("./build/modules");
    loader.add_search_path("build/modules");
    loader.add_search_path("./modules");

    auto file_res = loader.find_module_file("math");
    if (!file_res.is_ok()) {
        file_res = loader.find_module_file("logger");
    }
    ASSERT_TRUE(file_res.is_ok());

    dlerror();
    void* handle = dlopen(file_res.value().c_str(), RTLD_LAZY | RTLD_LOCAL);
    if (!handle) {
        std::cerr << "dlopen failed for " << file_res.value() << ": " << (dlerror() ? dlerror() : "unknown") << std::endl;
    }
    ASSERT_TRUE(handle != nullptr);

    // Read static embedded header without instantiating module objects
    auto hdr_res = ModuleHeader::read_from_handle(handle);
    ASSERT_TRUE(hdr_res.is_ok());
    const auto& hdr = hdr_res.value();
    ASSERT_FALSE(hdr.name.empty());
    ASSERT_EQ(hdr.abi_version, DVARGOSH_ABI_VERSION_STR);
    ASSERT_FALSE(hdr.build_id.empty());
    ASSERT_TRUE(hdr.validate().is_ok());

    dlclose(handle);
}

TEST_CASE(test_module_header_preflight_duplicate_rejection) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    loader.add_search_path("./build/modules");

    auto load1 = loader.load("math", "");
    ASSERT_TRUE(load1.is_ok());
    ASSERT_TRUE(loader.is_loaded("math"));

    // Attempt second load: pre-flight check in load_from_file must reject with AlreadyExists
    auto load2 = loader.load("math", "");
    ASSERT_FALSE(load2.is_ok());
    ASSERT_EQ(load2.status(), StatusCode::AlreadyExists);
}
