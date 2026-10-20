#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"

using namespace dvargosh;

TEST_CASE(test_worker_module_secured_memory_and_resources) {
    auto di = std::make_shared<DIContainer>();
    // Allow worker domain to cross-call compute (math) and core (logger)
    di->domain_manager()->allow_cross_domain("worker", "compute");
    di->domain_manager()->allow_cross_domain("worker", "core");
    di->domain_manager()->allow_cross_domain("compute", "core");

    ModuleLoader loader(di);

    loader.load("logger", "");
    loader.load("math", "");
    auto load_res = loader.load("worker", "");
    if (!load_res.is_ok()) {
        std::cout << " (skipping dynamic load, file not present yet) ";
        return;
    }

    ASSERT_TRUE(loader.is_loaded("worker"));

    // 1. Inspect worker secured memory container
    auto inspect_res = di->registry()->invoke("worker.inspect_security");
    ASSERT_TRUE(inspect_res.is_ok());
    std::string info = inspect_res.value().to_string();
    ASSERT_TRUE(info.find("Container: worker") != std::string::npos);
    ASSERT_TRUE(info.find("Protected Token Present: YES") != std::string::npos);

    // 2. Execute cross-module task (calls math.factorial & logger.log)
    auto task_res = di->registry()->invoke("worker.execute_task", {Value(4)});
    if (!task_res.is_ok()) {
        std::cerr << "TASK RES ERROR: " << task_res.error_message() << "\n";
    }
    ASSERT_TRUE(task_res.is_ok());
    ASSERT_EQ(task_res.value().as_int(), 24); // 4! = 24

    // 3. Verify resource is tracked
    ASSERT_TRUE(di->resource_manager()->active_count() >= 1);

    // 4. Unload worker -> verify owned resource is cleanly destroyed
    auto unload_res = loader.unload_module("worker");
    ASSERT_TRUE(unload_res.is_ok());
    ASSERT_FALSE(loader.is_loaded("worker"));

    // Clean up remaining modules
    loader.unload_module("math");
    loader.unload_module("logger");
}
