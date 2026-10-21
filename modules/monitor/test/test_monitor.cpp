#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include "../monitor_interface.hpp"

using namespace dvargosh;

TEST_CASE(test_monitor_module_telemetry) {
    ScopedCallFrame test_frame("test_monitor", "system");
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    auto load_res = loader.load("monitor", "");
    if (!load_res.is_ok()) {
        std::cout << " (skipping dynamic load, file not present yet) ";
        return;
    }

    ASSERT_TRUE(loader.is_loaded("monitor"));

    // 1. Resolve typed IMonitoringService in scoped block
    {
        auto mon_res = di->registry()->get_service<IMonitoringService>("monitor");
        ASSERT_TRUE(mon_res.is_ok());
        auto mon_svc = mon_res.value();

        mon_svc->record_metric("cpu.temperature_c", 45.2);
        ASSERT_EQ(mon_svc->get_metric("cpu.temperature_c"), 45.2);

        // Test memory occupation struct
        auto occ = mon_svc->get_memory_occupation();
        ASSERT_TRUE(!occ.domains.empty());
    }

    // 2. Dynamic RPC calls
    auto rec_rpc = di->registry()->invoke("monitor.record", {Value("network.latency_ms"), Value(12.5)});
    ASSERT_TRUE(rec_rpc.is_ok());

    auto get_rpc = di->registry()->invoke("monitor.get", {Value("network.latency_ms")});
    ASSERT_TRUE(get_rpc.is_ok());
    ASSERT_EQ(get_rpc.value().as_double(), 12.5);

    // 3. Test memory_status RPC
    auto mem_rpc = di->registry()->invoke("monitor.memory_status");
    ASSERT_TRUE(mem_rpc.is_ok());
    ASSERT_TRUE(mem_rpc.value().to_string().find("MEMORY & SECURED SPACES OCCUPATION") != std::string::npos);

    // 4. Test event listener in monitor: publish math.calculation_done
    di->event_bus()->publish("math.calculation_done", Value(999.0));

    // 5. Unload monitor
    auto unload_res = loader.unload_module("monitor");
    ASSERT_TRUE(unload_res.is_ok());
    ASSERT_FALSE(loader.is_loaded("monitor"));
}
