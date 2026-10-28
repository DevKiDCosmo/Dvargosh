// netprobe tests: connection probes over cross-module RPC into stdnet.
// Exercises the C4-correct trust flow: the host declares dev:netprobe -> std:net.
#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace dvargosh;

namespace {

int make_listen_socket(uint16_t& out_port) {
    int srv = ::socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(srv, 4) != 0) {
        ::close(srv);
        return -1;
    }
    socklen_t len = sizeof(addr);
    ::getsockname(srv, reinterpret_cast<sockaddr*>(&addr), &len);
    out_port = ntohs(addr.sin_port);
    return srv;
}

} // namespace

TEST_CASE(test_netprobe_probes_over_cross_module_rpc) {
    ScopedCallFrame test_frame("test_netprobe", "system");
    auto di = std::make_shared<DIContainer>();

    // Host-declared trust edge: netprobe may invoke stdnet services (audit C4).
    ASSERT_TRUE(di->domain_manager()->allow_cross_domain("dev:netprobe", "std:net").is_ok());

    ModuleLoader loader(di);
    loader.add_search_path("./build/modules");
    loader.add_search_path("./build/development_modules");
    loader.add_search_path("./modules");
    loader.add_search_path("./development_modules");
    loader.add_search_path("../build/modules");

    auto stdnet_loaded = loader.load("stdnet");
    auto probe_loaded = loader.load("netprobe");
    if (!stdnet_loaded.is_ok() || !probe_loaded.is_ok()) {
        std::cout << " (skipping, stdnet/netprobe not built yet) ";
        return;
    }
    ASSERT_TRUE(loader.is_loaded("netprobe"));

    auto& reg = *di->registry();
    auto invoke = [&](const std::string& m, std::vector<Value> a) {
        return reg.invoke(m, std::move(a), "host_test", "system", nullptr);
    };

    // 1. TCP connect ping against a real local listener.
    std::atomic<bool> running{true};
    uint16_t port = 0;
    int srv = make_listen_socket(port);
    ASSERT_TRUE(srv >= 0);
    std::thread echo([srv, &running] {
        while (running.load()) {
            struct pollfd pfd{srv, POLLIN, 0};
            if (::poll(&pfd, 1, 50) <= 0) continue;
            int c = ::accept(srv, nullptr, nullptr);
            if (c < 0) continue;
            char buf[2048];
            ssize_t n = ::recv(c, buf, sizeof(buf), 0);
            if (n > 0) (void)::send(c, buf, static_cast<size_t>(n), 0);
            ::close(c);
        }
        ::close(srv);
    });

    auto tcp = invoke("netprobe.tcp_ping", {Value("127.0.0.1"), Value(static_cast<int64_t>(port)), Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(tcp.is_ok());
    ASSERT_TRUE(tcp.value().to_string().find("rtt_ms=") != std::string::npos);

    // 2. UDP ping against a loopback echo.
    int usrv = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in uaddr{};
    uaddr.sin_family = AF_INET;
    uaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    uaddr.sin_port = 0;
    ASSERT_TRUE(::bind(usrv, reinterpret_cast<sockaddr*>(&uaddr), sizeof(uaddr)) == 0);
    socklen_t ulen = sizeof(uaddr);
    ::getsockname(usrv, reinterpret_cast<sockaddr*>(&uaddr), &ulen);
    uint16_t uport = ntohs(uaddr.sin_port);
    std::atomic<bool> uring{true};
    std::thread uecho([usrv, &uring] {
        while (uring.load()) {
            struct pollfd pfd{usrv, POLLIN, 0};
            if (::poll(&pfd, 1, 50) <= 0) continue;
            char buf[2048];
            sockaddr_in from{};
            socklen_t flen = sizeof(from);
            ssize_t n = ::recvfrom(usrv, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &flen);
            if (n > 0) (void)::sendto(usrv, buf, static_cast<size_t>(n), 0, reinterpret_cast<sockaddr*>(&from), flen);
        }
        ::close(usrv);
    });

    auto udp = invoke("netprobe.udp_ping", {Value("127.0.0.1"), Value(static_cast<int64_t>(uport)), Value("probe-packet"), Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(udp.is_ok());
    ASSERT_TRUE(udp.value().to_string().find("echoed=yes") != std::string::npos);

    // 3. DNS probe on a literal IP.
    auto dns = invoke("netprobe.dns_probe", {Value("127.0.0.1"), Value("80")});
    ASSERT_TRUE(dns.is_ok());
    ASSERT_TRUE(dns.value().to_string().find("127.0.0.1") != std::string::npos);

    // 4. HTTP ping against the stdnet built-in server (full cross-module chain).
    auto port_res = invoke("stdnet.http_server_listen", {Value(static_cast<int64_t>(0))});
    ASSERT_TRUE(port_res.is_ok());
    auto http = invoke("netprobe.http_ping", {
        Value("http://127.0.0.1:" + std::to_string(port_res.value().as_int()) + "/probe"),
        Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(http.is_ok());
    ASSERT_TRUE(http.value().to_string().find("rtt_ms=") != std::string::npos);
    (void)invoke("stdnet.http_server_stop", {});

    // 5. Failing probe surfaces the stdnet error through the RPC boundary.
    auto refused = invoke("netprobe.tcp_ping", {Value("127.0.0.1"), Value(static_cast<int64_t>(1)), Value(static_cast<int64_t>(300))});
    ASSERT_FALSE(refused.is_ok());

    ASSERT_TRUE(loader.unload_module("netprobe").is_ok());
    running = false;
    uring = false;
    echo.join();
    uecho.join();
}
