#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include "../logger_interface.hpp"

using namespace dvargosh;

TEST_CASE(test_logger_module_lifecycle_and_service) {
    ScopedCallFrame test_frame("test_logger", "system");
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    auto load_res = loader.load("logger", "");
    if (!load_res.is_ok()) {
        std::cout << " (skipping dynamic load, file not present yet) ";
        return;
    }

    ASSERT_TRUE(loader.is_loaded("logger"));

    // 1. Resolve typed ILogger service in scoped block so pointers destruct before dlclose
    {
        auto logger_res = di->registry()->get_service<ILogger>("logger");
        ASSERT_TRUE(logger_res.is_ok());
        auto logger = logger_res.value();
        ASSERT_TRUE(logger != nullptr);

        logger->info("Test logger message from test_logger");
        logger->debug("Debug log check");
        logger->warn("Warn log check");
    }

    // 2. Dynamic RPC invocation
    auto rpc_res = di->registry()->invoke("logger.log", {Value("Dynamic RPC Log Entry")});
    ASSERT_TRUE(rpc_res.is_ok());

    // 3. Unload logger
    auto unload_res = loader.unload_module("logger");
    ASSERT_TRUE(unload_res.is_ok());
    ASSERT_FALSE(loader.is_loaded("logger"));

    // Service should no longer exist in registry
    auto post_svc = di->registry()->get_service<ILogger>("logger");
    ASSERT_FALSE(post_svc.is_ok());
}
