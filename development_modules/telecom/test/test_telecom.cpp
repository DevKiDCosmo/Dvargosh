// Comprehensive verification test for 'telecom' development package.
#include "dvargosh/dvargosh.hpp"
#include <cassert>
#include <iostream>
#include <vector>
#include <string>

using namespace dvargosh;

void run_telecom_tests() {
    std::cout << "====================================================\n";
    std::cout << " [TEST SUITE] Telecom Package Verification Harness   \n";
    std::cout << "====================================================\n";

    ScopedCallFrame test_frame("host_telecom_test", "system");
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);

    loader.add_search_path("./build/modules");
    loader.add_search_path("./build/development_modules");
    loader.add_search_path("./modules");
    loader.add_search_path("./development_modules");
    loader.add_search_path("../build/modules");
    loader.add_search_path("../build/development_modules");

    // 1. Locate and dynamically load telecom module
    std::cout << "\n[Step 1] Loading telecom module...\n";
    auto file_res = loader.find_module_file("telecom");
    if (!file_res.is_ok()) {
        std::cerr << "  ✖ Failed to locate telecom shared library: " << file_res.error_message() << "\n";
        std::exit(1);
    }
    std::cout << "  ✓ Found library: " << file_res.value() << "\n";

    auto load_res = loader.load_from_file(file_res.value());
    if (!load_res.is_ok()) {
        std::cerr << "  ✖ Failed to load telecom module: " << load_res.error_message() << "\n";
        std::exit(1);
    }
    assert(loader.is_loaded("telecom"));
    std::cout << "  ✓ Module 'telecom' loaded successfully.\n";

    // 2. Validate registry methods
    std::cout << "\n[Step 2] Validating registered services in registry...\n";
    assert(di->registry()->has_method("telecom.telecom_echo") || di->registry()->has_method("telecom_echo"));
    std::string echo_fn = di->registry()->has_method("telecom.telecom_echo") ? "telecom.telecom_echo" : "telecom_echo";
    std::cout << "  ✓ Found echo service: " << echo_fn << "\n";

    // 3. Test echo service invocation
    std::cout << "\n[Step 3] Testing packet echo invocations...\n";
    std::vector<std::string> test_packets = {
        "SYN_SEQ_001",
        "SYN_ACK_SEQ_002",
        "ACK_SEQ_003",
        "DATA_PAYLOAD:HTTP/1.1 200 OK",
        "FIN_SEQ_004"
    };

    for (const auto& pkt : test_packets) {
        auto res = di->registry()->invoke(echo_fn, {Value(pkt)});
        assert(res.is_ok());
        std::string expected = "[telecom] " + pkt;
        assert(res.value().to_string() == expected);
        std::cout << "  ✓ Echo roundtrip for '" << pkt << "' -> '" << res.value().to_string() << "'\n";
    }

    // 4. Test route packet service
    std::string route_fn = di->registry()->has_method("telecom.telecom_route_packet") ? "telecom.telecom_route_packet" : "telecom_route_packet";
    if (di->registry()->has_method(route_fn)) {
        std::cout << "\n[Step 4] Testing packet routing service...\n";
        auto empty_res = di->registry()->invoke(route_fn, {Value("")});
        assert(empty_res.is_ok());
        assert(empty_res.value().to_string() == "ERR_EMPTY_PACKET");

        auto route_res = di->registry()->invoke(route_fn, {Value("PACKET_IP_192_168_1_1")});
        assert(route_res.is_ok());
        assert(route_res.value().to_string() == "[ROUTED:telecom:packet] PACKET_IP_192_168_1_1");
        std::cout << "  ✓ Packet successfully routed: " << route_res.value().to_string() << "\n";
    }

    // 5. Test domain isolation & scoped execution
    std::cout << "\n[Step 5] Testing domain isolation under scoped frames...\n";
    {
        ScopedCallFrame packet_frame("telecom_caller", "telecom:packet");
        auto res = di->registry()->invoke(echo_fn, {Value("DOMAIN_VERIFIED_PACKET")});
        assert(res.is_ok());
        std::cout << "  ✓ Scoped call under 'telecom:packet' succeeded.\n";
    }

    // 6. Burst packet throughput test
    std::cout << "\n[Step 6] Running burst throughput stress test (100 packets)...\n";
    for (int i = 0; i < 100; ++i) {
        std::string pkt = "BURST_PKT_" + std::to_string(i);
        auto res = di->registry()->invoke(echo_fn, {Value(pkt)});
        assert(res.is_ok());
    }
    std::cout << "  ✓ 100 packets processed successfully without error.\n";

    // 7. Unload module and verify registry cleanup
    std::cout << "\n[Step 7] Testing module unloading & deregistration invariants...\n";
    auto unload_res = loader.unload_module("telecom");
    assert(unload_res.is_ok());
    assert(!loader.is_loaded("telecom"));
    std::cout << "  ✓ Module 'telecom' unloaded cleanly.\n";

    // Verify method is no longer invokable
    auto post_unload_call = di->registry()->invoke(echo_fn, {Value("AFTER_UNLOAD")});
    assert(!post_unload_call.is_ok());
    assert(post_unload_call.status() == StatusCode::NotFound);
    std::cout << "  ✓ Calling unmapped service after unload correctly rejected with NotFound.\n";

    std::cout << "\n====================================================\n";
    std::cout << " [SUCCESS] All Telecom Package Tests Passed!        \n";
    std::cout << "====================================================\n";
}

int main() {
    try {
        run_telecom_tests();
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "FATAL ERROR IN TELECOM TEST: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "FATAL UNKNOWN ERROR IN TELECOM TEST\n";
        return 1;
    }
}
