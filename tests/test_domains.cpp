#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

TEST_CASE(test_domain_creation_and_memory_space) {
    DomainManager dm;

    // 1. Create a custom domain with its own secured space
    auto create_res = dm.create_domain("analytics", SecurityPolicy::standard(), 128 * 1024, true);
    ASSERT_TRUE(create_res.is_ok());
    Domain* domain = create_res.value();
    ASSERT_TRUE(domain != nullptr);
    ASSERT_EQ(domain->name(), "analytics");

    // 2. Verify domain-level secured memory space was initialized
    SecuredMemorySpace* space = dm.get_domain_space("analytics");
    ASSERT_TRUE(space != nullptr);
    ASSERT_TRUE(space->capacity() >= 128 * 1024);

    // Sub-allocate within domain space
    void* p = space->allocate(512);
    ASSERT_TRUE(p != nullptr);
}

TEST_CASE(test_init_domain_space_function) {
    DomainManager dm;
    dm.create_domain("ml_inference", SecurityPolicy::standard());

    // Call explicit function to init secured space for domain
    auto res = dm.init_domain_space("ml_inference", 256 * 1024, true);
    ASSERT_TRUE(res.is_ok());

    SecuredMemorySpace* space = res.value();
    ASSERT_TRUE(space != nullptr);
    ASSERT_TRUE(space->capacity() >= 256 * 1024);
}

// Mock domain module to test plug and unplug
class DomainTestModule : public IModule {
public:
    DomainTestModule(std::string name, std::string domain)
        : m_name(std::move(name)), m_domain(std::move(domain)) {}

    const ModuleManifest& manifest() const override {
        static ModuleManifest m;
        m.name = m_name;
        m.domain = m_domain;
        m.version = Version{1, 0, 0};
        m.requested_permissions = PermissionSet::all();
        return m;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        m_loaded = true;
        // Verify domain space is accessible from within module context
        SecuredMemorySpace* d_space = ctx.domain_space();
        m_had_domain_space = (d_space != nullptr);
        return Result<void>::success();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override {
        m_loaded = false;
        return Result<void>::success();
    }

    bool m_loaded = false;
    bool m_had_domain_space = false;
private:
    std::string m_name;
    std::string m_domain;
};

TEST_CASE(test_domain_unplug_and_plug) {
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    // Initialize domain with domain-level secured memory space
    di->domain_manager()->create_domain("cloud_compute", SecurityPolicy::permissive(), 64 * 1024, false);

    // 1. Plug static module into domain "cloud_compute"
    auto mod1 = std::make_unique<DomainTestModule>("compute_node_1", "cloud_compute");
    DomainTestModule* ptr1 = mod1.get();

    auto load_res = loader.load_static_module(std::move(mod1));
    ASSERT_TRUE(load_res.is_ok());
    ASSERT_TRUE(loader.is_loaded("compute_node_1"));
    ASSERT_TRUE(ptr1->m_loaded);
    ASSERT_TRUE(ptr1->m_had_domain_space);

    // Verify module is in domain
    Domain* dom = di->domain_manager()->get_domain("cloud_compute");
    ASSERT_TRUE(dom != nullptr);
    ASSERT_TRUE(dom->has_module("compute_node_1"));

    // 2. Unplug entire domain
    auto unplug_res = di->domain_manager()->unplug_domain("cloud_compute", loader);
    ASSERT_TRUE(unplug_res.is_ok());
    ASSERT_EQ(unplug_res.value(), 1); // 1 module unplugged
    ASSERT_FALSE(loader.is_loaded("compute_node_1"));
    ASSERT_FALSE(dom->has_module("compute_node_1"));

    // 3. Re-plug module back into domain
    auto mod2 = std::make_unique<DomainTestModule>("compute_node_1", "cloud_compute");
    DomainTestModule* ptr2 = mod2.get();
    auto replug_res = loader.load_static_module(std::move(mod2));
    ASSERT_TRUE(replug_res.is_ok());
    ASSERT_TRUE(loader.is_loaded("compute_node_1"));
    ASSERT_TRUE(ptr2->m_loaded);
    ASSERT_TRUE(dom->has_module("compute_node_1"));

    loader.unload_module("compute_node_1");
}
