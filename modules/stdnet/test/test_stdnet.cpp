// stdnet module tests — loopback only (no external network in CI):
// URI parsing, DNS (literal IP), TCP connect/send/recv/close, HTTP request
// packaging + response parsing, UDP roundtrip, and telemetry accounting.
#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace dvargosh;

namespace {

// Minimal TCP echo server on 127.0.0.1:0 (ephemeral). Echoes one recv per accept.
int start_tcp_echo(std::atomic<bool>& running, uint16_t& out_port) {
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

    std::thread([srv, &running] {
        while (running.load()) {
            struct pollfd pfd{srv, POLLIN, 0};
            if (::poll(&pfd, 1, 50) <= 0) continue;
            int c = ::accept(srv, nullptr, nullptr);
            if (c < 0) continue;
            char buf[4096];
            ssize_t n = ::recv(c, buf, sizeof(buf), 0);
            if (n > 0) (void)::send(c, buf, static_cast<size_t>(n), 0);
            ::close(c);
        }
        ::close(srv);
    }).detach();
    return 0;
}

// Minimal HTTP server: answers any request with a fixed 200 + Content-Length body.
int start_http_server(std::atomic<bool>& running, uint16_t& out_port, const std::string& body) {
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

    std::thread([srv, &running, body] {
        while (running.load()) {
            struct pollfd pfd{srv, POLLIN, 0};
            if (::poll(&pfd, 1, 50) <= 0) continue;
            int c = ::accept(srv, nullptr, nullptr);
            if (c < 0) continue;
            std::string req;
            char buf[2048];
            while (req.find("\r\n\r\n") == std::string::npos) {
                ssize_t n = ::recv(c, buf, sizeof(buf), 0);
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
            }
            std::string resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: " + std::to_string(body.size()) + "\r\n"
                "X-Test-Server: dvargosh\r\n"
                "Connection: close\r\n\r\n" + body;
            (void)::send(c, resp.data(), resp.size(), 0);
            ::close(c);
        }
        ::close(srv);
    }).detach();
    return 0;
}

// Minimal UDP echo server.
int start_udp_echo(std::atomic<bool>& running, uint16_t& out_port) {
    int srv = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (srv < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(srv);
        return -1;
    }
    socklen_t len = sizeof(addr);
    ::getsockname(srv, reinterpret_cast<sockaddr*>(&addr), &len);
    out_port = ntohs(addr.sin_port);

    std::thread([srv, &running] {
        while (running.load()) {
            struct pollfd pfd{srv, POLLIN, 0};
            if (::poll(&pfd, 1, 50) <= 0) continue;
            char buf[2048];
            sockaddr_in from{};
            socklen_t flen = sizeof(from);
            ssize_t n = ::recvfrom(srv, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &flen);
            if (n > 0) (void)::sendto(srv, buf, static_cast<size_t>(n), 0, reinterpret_cast<sockaddr*>(&from), flen);
        }
        ::close(srv);
    }).detach();
    return 0;
}

} // namespace

TEST_CASE(test_stdnet_module_networking_surface) {
    ScopedCallFrame test_frame("test_stdnet", "system");
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    loader.add_search_path("./build/modules");
    loader.add_search_path("./modules");
    loader.add_search_path("../build/modules");

    auto load_res = loader.load("stdnet");
    if (!load_res.is_ok()) {
        std::cout << " (skipping dynamic load, file not present yet) ";
        return;
    }
    ASSERT_TRUE(loader.is_loaded("stdnet"));

    auto& reg = *di->registry();
    auto invoke = [&](const std::string& m, std::vector<Value> a) {
        return reg.invoke(m, std::move(a), "host_test", "system", nullptr);
    };

    // 1. URI parsing
    auto uri = invoke("stdnet.uri_parse", {Value("http://example.com:8080/path/seg?q=1&x=2#frag")});
    ASSERT_TRUE(uri.is_ok());
    ASSERT_TRUE(uri.value().to_string().find("host=example.com") != std::string::npos);
    ASSERT_TRUE(uri.value().to_string().find("port=8080") != std::string::npos);
    ASSERT_TRUE(uri.value().to_string().find("q=1&x=2") != std::string::npos);
    auto bad_uri = invoke("stdnet.uri_parse", {Value("no-scheme.example.com")});
    ASSERT_FALSE(bad_uri.is_ok());

    // 2. DNS on a literal IP (no network dependency)
    auto resolved = invoke("stdnet.resolve", {Value("127.0.0.1"), Value("80")});
    ASSERT_TRUE(resolved.is_ok());
    ASSERT_TRUE(resolved.value().to_string().find("127.0.0.1") != std::string::npos);

    // 3. TCP echo roundtrip through the connection table
    std::atomic<bool> echo_running{true};
    uint16_t echo_port = 0;
    ASSERT_TRUE(start_tcp_echo(echo_running, echo_port) == 0);

    auto open = invoke("stdnet.tcp_open", {Value("tcp://127.0.0.1:" + std::to_string(echo_port) + "/"), Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(open.is_ok());
    const int64_t conn = open.value().as_int();

    auto sent = invoke("stdnet.tcp_send", {Value(conn), Value("dvargosh-echo-payload")});
    ASSERT_TRUE(sent.is_ok());
    ASSERT_EQ(sent.value().as_int(), static_cast<int64_t>(strlen("dvargosh-echo-payload")));

    auto recvd = invoke("stdnet.tcp_recv", {Value(conn), Value(static_cast<int64_t>(4096)), Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(recvd.is_ok());
    ASSERT_EQ(recvd.value().to_string(), "dvargosh-echo-payload");

    auto closed = invoke("stdnet.tcp_close", {Value(conn)});
    ASSERT_TRUE(closed.is_ok() && closed.value().as_bool());
    auto send_gone = invoke("stdnet.tcp_send", {Value(conn), Value("x")});
    ASSERT_FALSE(send_gone.is_ok()); // unknown connection id after close

    // 4. HTTP request packaging + response parsing against the local server
    const std::string http_body = "dvargosh-stdnet-http-body";
    std::atomic<bool> http_running{true};
    uint16_t http_port = 0;
    ASSERT_TRUE(start_http_server(http_running, http_port, http_body) == 0);

    auto get = invoke("stdnet.http_get", {
        Value("http://127.0.0.1:" + std::to_string(http_port) + "/idx?a=b"),
        Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(get.is_ok());
    ASSERT_EQ(get.value().to_string(), http_body);

    // Raw exchange exposes status line + headers.
    auto raw = invoke("stdnet.http_request", {
        Value("GET"),
        Value("http://127.0.0.1:" + std::to_string(http_port) + "/"),
        Value(""),
        Value(""),
        Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(raw.is_ok());
    ASSERT_TRUE(raw.value().to_string().find("HTTP/1.1 200 OK") != std::string::npos);
    ASSERT_TRUE(raw.value().to_string().find("X-Test-Server: dvargosh") != std::string::npos);

    // 5. UDP roundtrip
    std::atomic<bool> udp_running{true};
    uint16_t udp_port = 0;
    ASSERT_TRUE(start_udp_echo(udp_running, udp_port) == 0);
    auto udp = invoke("stdnet.udp_roundtrip", {
        Value("127.0.0.1"), Value(static_cast<int64_t>(udp_port)),
        Value("udp-datagram"), Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(udp.is_ok());
    ASSERT_EQ(udp.value().to_string(), "udp-datagram");

    // 6. Telemetry accounting: the module's traffic landed in the hub.
    auto* hub = di->telemetry();
    ASSERT_TRUE(hub != nullptr);
    auto txs = hub->snapshot("net.bytes_tx");
    ASSERT_EQ(txs.size(), 1);
    ASSERT_TRUE(txs[0].last > 0.0);
    auto rxs = hub->snapshot("net.bytes_rx");
    ASSERT_EQ(rxs.size(), 1);
    ASSERT_TRUE(rxs[0].last > 0.0);

    // 7. Unload closes remaining connections and unregisters services.
    ASSERT_TRUE(loader.unload_module("stdnet").is_ok());
    auto gone = invoke("stdnet.uri_parse", {Value("http://x.io/")});
    ASSERT_FALSE(gone.is_ok());

    echo_running = false;
    http_running = false;
    udp_running = false;
}
