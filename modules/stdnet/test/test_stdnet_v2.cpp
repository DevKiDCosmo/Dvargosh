// stdnet v2 tests — reactor/coroutines/strands, framing, buffers, rate limiting,
// UDS, WebSockets, the built-in HTTP server, and async DNS (loopback only).
#include "test_framework.hpp"
#include "dvargosh/dvargosh.hpp"
#include "../stdnet_buffer.hpp"
#include "../stdnet_framing.hpp"
#include "../stdnet_strand.hpp"
#include "../stdnet_ws.hpp"
#include "../stdnet_uds.hpp"
#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <set>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace dvargosh;

// --- pure header-only pieces ---------------------------------------------------

TEST_CASE(test_stdnet_buffer_pool_and_framing) {
    // BufferPool: recycle behavior
    stdnet::BufferPool pool(128, 2);
    auto b1 = pool.make_block();
    auto b2 = pool.make_block();
    ASSERT_TRUE(b1.get() != nullptr && b2.get() != nullptr && b1.get() != b2.get());
    b1.reset();
    auto b3 = pool.make_block(); // should recycle b1's memory
    ASSERT_TRUE(b3.get() != nullptr);

    // DynamicBuffer: append/parse/consume with zero-copy window
    stdnet::DynamicBuffer buf;
    stdnet::length_prefix::append_frame(buf, "hello", 5);
    stdnet::length_prefix::append_frame(buf, "!!", 2);
    ASSERT_EQ(buf.size(), (4 + 5) + (4 + 2));
    std::vector<uint8_t> msg;
    ASSERT_TRUE(stdnet::length_prefix::try_pop(buf, msg));
    ASSERT_TRUE(std::string(msg.begin(), msg.end()) == "hello");
    ASSERT_TRUE(stdnet::length_prefix::try_pop(buf, msg));
    ASSERT_TRUE(std::string(msg.begin(), msg.end()) == "!!");
    ASSERT_TRUE(buf.empty());
    ASSERT_TRUE(!stdnet::length_prefix::try_pop(buf, msg)); // nothing left

    // Delimited framing
    stdnet::DynamicBuffer d;
    stdnet::delimited::append_frame(d, "line1", 5);
    stdnet::delimited::append_frame(d, "line2", 5);
    ASSERT_TRUE(stdnet::delimited::try_pop(d, msg));
    ASSERT_TRUE(std::string(msg.begin(), msg.end()) == "line1");
    ASSERT_TRUE(stdnet::delimited::try_pop(d, msg));
    ASSERT_TRUE(std::string(msg.begin(), msg.end()) == "line2");
}

TEST_CASE(test_stdnet_strand_serializes_execution) {
    auto strand = stdnet::Strand::make();
    std::atomic<int> counter{0};
    std::atomic<size_t> distinct_threads{0};
    std::mutex tset_mutex;
    std::set<std::thread::id> threads;

    std::vector<std::thread> posters;
    for (int t = 0; t < 4; ++t) {
        posters.emplace_back([&] {
            for (int i = 0; i < 50; ++i) {
                strand->post([&counter, &threads, &tset_mutex] {
                    counter++;
                    std::lock_guard<std::mutex> lk(tset_mutex);
                    threads.insert(std::this_thread::get_id());
                });
            }
        });
    }
    for (auto& t : posters) t.join();

    for (int i = 0; i < 200 && counter.load() < 200; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_EQ(counter.load(), 200);                    // nothing lost, nothing duplicated
    ASSERT_TRUE(strand->idle());
    ASSERT_EQ(threads.size(), 1);                      // strictly single-threaded execution
}

TEST_CASE(test_stdnet_ws_frame_codec_and_handshake_key) {
    // RFC 6455 known-answer: key "dGhlIHNhbXBsZSBub25jZQ==" ->
    // accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    ASSERT_EQ(stdnet::ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

    // Frame roundtrip: masked client frame decodes back to the payload.
    stdnet::DynamicBuffer out;
    stdnet::WsFrame f;
    f.opcode = stdnet::WsOpcode::Text;
    f.fin = true;
    f.payload.assign({'h', 'i', '!', 0x01});
    stdnet::ws_encode_frame(std::move(f), out, /*mask=*/true);

    stdnet::WsFrame decoded;
    ASSERT_EQ(stdnet::ws_try_decode(out, decoded), 1);
    ASSERT_TRUE(decoded.fin);
    ASSERT_TRUE(decoded.opcode == stdnet::WsOpcode::Text);
    ASSERT_TRUE(decoded.payload.size() == 4);
    ASSERT_TRUE(decoded.payload[0] == 'h' && decoded.payload[2] == '!');
    ASSERT_TRUE(out.empty());
}

// --- module-level integration (loopback) ----------------------------------------

namespace {

int make_listen_socket(uint16_t& out_port, std::string& error) {
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
    (void)error;
    return srv;
}

} // namespace

TEST_CASE(test_stdnet_v2_module_async_uds_ws_server) {
    ScopedCallFrame test_frame("test_stdnet_v2", "system");
    auto di = std::make_shared<DIContainer>();
    ModuleLoader loader(di);
    loader.add_search_path("./build/modules");
    loader.add_search_path("./modules");
    loader.add_search_path("../build/modules");

    auto load_res = loader.load("stdnet");
    if (!load_res.is_ok()) {
        std::cout << " (skipping, stdnet not built yet) ";
        return;
    }

    auto& reg = *di->registry();
    auto invoke = [&](const std::string& m, std::vector<Value> a) {
        return reg.invoke(m, std::move(a), "host_test", "system", nullptr);
    };

    // 1. Reactor backend + coroutine probe (steady timer + post under co_await).
    auto backend = invoke("stdnet.reactor_backend", {});
    ASSERT_TRUE(backend.is_ok());
    std::string backend_name = backend.value().to_string();
    ASSERT_TRUE(backend_name == "kqueue" || backend_name == "epoll");

    auto probed = invoke("stdnet.coro_delay_probe", {Value(static_cast<int64_t>(40))});
    ASSERT_TRUE(probed.is_ok());
    ASSERT_EQ(probed.value().as_int(), 40);

    // 2. Async DNS: completion arrives as an EventBus event with the caller tag.
    std::atomic<bool> dns_done{false};
    std::string dns_payload;
    (void)di->event_bus()->subscribe("net.dns.resolved", "test_sub",
        [&](const std::string&, const Value& v) {
            dns_payload = v.to_string();
            dns_done = true;
        }, nullptr);
    ASSERT_TRUE(invoke("stdnet.resolve_async", {Value("127.0.0.1"), Value("80"), Value("probe-1")}).is_ok());
    for (int i = 0; i < 200 && !dns_done.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(dns_done.load());
    ASSERT_TRUE(dns_payload.find("tag=probe-1") != std::string::npos);
    ASSERT_TRUE(dns_payload.find("127.0.0.1") != std::string::npos);

    // 3. UDS echo: local stream socket through the module's connection table.
    std::string uds_path = "/tmp/dvargosh_stdnet_test_uds";
    stdnet::UdsStream::remove_path(uds_path);
    int uds_listen = -1;
    std::string uerr;
    ASSERT_TRUE(stdnet::UdsStream::listen(uds_path, uds_listen, uerr));
    std::atomic<bool> uds_running{true};
    std::thread uds_server([uds_listen, &uds_running] {
        while (uds_running.load()) {
            struct pollfd pfd{uds_listen, POLLIN, 0};
            if (::poll(&pfd, 1, 50) <= 0) continue;
            stdnet::UdsStream conn;
            std::string aerr;
            if (!stdnet::UdsStream::accept(uds_listen, conn, aerr)) continue;
            std::vector<uint8_t> buf;
            if (conn.recv_some(buf, 4096, 1000, aerr)) {
                (void)conn.send_all(buf.data(), buf.size(), 1000, aerr);
            }
        }
        ::close(uds_listen);
    });
    auto uds_open = invoke("stdnet.uds_open", {Value(uds_path)});
    ASSERT_TRUE(uds_open.is_ok());
    const int64_t uds_id = uds_open.value().as_int();
    ASSERT_TRUE(invoke("stdnet.uds_send", {Value(uds_id), Value("uds-payload")}).is_ok());
    auto uds_recv = invoke("stdnet.uds_recv", {Value(uds_id), Value(static_cast<int64_t>(4096)), Value(static_cast<int64_t>(1000))});
    ASSERT_TRUE(uds_recv.is_ok());
    ASSERT_EQ(uds_recv.value().to_string(), "uds-payload");
    ASSERT_TRUE(invoke("stdnet.uds_close", {Value(uds_id)}).is_ok());

    // 4. Built-in HTTP/1.1 server on the reactor (echo/JSON handler).
    auto port_res = invoke("stdnet.http_server_listen", {Value(static_cast<int64_t>(0))});
    ASSERT_TRUE(port_res.is_ok());
    const int64_t http_port = port_res.value().as_int();
    ASSERT_TRUE(http_port > 0);

    int req_sock = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(static_cast<uint16_t>(http_port));
    ASSERT_TRUE(::connect(req_sock, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 0);
    std::string req = "POST /api/test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
    (void)::send(req_sock, req.data(), req.size(), 0);
    std::string resp;
    char rbuf[2048];
    for (;;) {
        ssize_t n = ::recv(req_sock, rbuf, sizeof(rbuf), 0);
        if (n <= 0) break;
        resp.append(rbuf, static_cast<size_t>(n));
    }
    ::close(req_sock);
    ASSERT_TRUE(resp.find("HTTP/1.1 200 OK") != std::string::npos);
    ASSERT_TRUE(resp.find("\"method\":\"POST\"") != std::string::npos);
    ASSERT_TRUE(resp.find("\"target\":\"/api/test\"") != std::string::npos);
    ASSERT_TRUE(resp.find("\"body_bytes\":5") != std::string::npos);
    ASSERT_TRUE(invoke("stdnet.http_server_stop", {}).is_ok());

    // 5. WebSocket echo: server handshake + masked client frames through the module.
    std::atomic<bool> ws_running{true};
    uint16_t ws_port = 0;
    std::string ws_err;
    int ws_listen = make_listen_socket(ws_port, ws_err);
    ASSERT_TRUE(ws_listen >= 0);
    std::thread ws_server([ws_listen, &ws_running] {
        while (ws_running.load()) {
            struct pollfd pfd{ws_listen, POLLIN, 0};
            if (::poll(&pfd, 1, 50) <= 0) continue;
            int c = ::accept(ws_listen, nullptr, nullptr);
            if (c < 0) continue;
            std::string req;
            char buf[2048];
            while (req.find("\r\n\r\n") == std::string::npos) {
                ssize_t n = ::recv(c, buf, sizeof(buf), 0);
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
            }
            // extract Sec-WebSocket-Key
            std::string key;
            const std::string marker = "Sec-WebSocket-Key:";
            auto kpos = req.find(marker);
            if (kpos == std::string::npos) { ::close(c); continue; }
            kpos += marker.size();
            auto kend = req.find("\r\n", kpos);
            key = req.substr(kpos, kend - kpos);
            while (!key.empty() && key.front() == ' ') key.erase(key.begin());

            std::string resp =
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: " + stdnet::ws_accept_key(key) + "\r\n\r\n";
            (void)::send(c, resp.data(), resp.size(), 0);

            // Echo frames until close/timeout.
            stdnet::DynamicBuffer in;
            for (int i = 0; i < 20; ++i) {
                stdnet::WsFrame f;
                if (stdnet::ws_try_decode(in, f) != 1) {
                    ssize_t n = ::recv(c, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    in.append(buf, static_cast<size_t>(n));
                    if (stdnet::ws_try_decode(in, f) != 1) continue;
                }
                if (f.opcode == stdnet::WsOpcode::Close) break;
                stdnet::DynamicBuffer out;
                stdnet::ws_encode_frame(std::move(f), out, /*mask=*/false); // server -> client unmasked
                (void)::send(c, out.data(), out.size(), 0);
            }
            ::close(c);
        }
        ::close(ws_listen);
    });

    auto ws_open = invoke("stdnet.ws_connect", {
        Value("ws://127.0.0.1:" + std::to_string(ws_port) + "/echo"), Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(ws_open.is_ok());
    const int64_t ws_id = ws_open.value().as_int();
    ASSERT_TRUE(invoke("stdnet.ws_send", {Value(ws_id), Value("ws-roundtrip")}).is_ok());
    auto ws_recv = invoke("stdnet.ws_recv", {Value(ws_id), Value(static_cast<int64_t>(2000))});
    ASSERT_TRUE(ws_recv.is_ok());
    ASSERT_EQ(ws_recv.value().to_string(), "ws-roundtrip");
    ASSERT_TRUE(invoke("stdnet.ws_close", {Value(ws_id)}).is_ok());

    // 6. Rate limiting: an absurdly small bucket refuses large sends.
    ASSERT_TRUE(invoke("stdnet.rate_limit", {Value(0.001), Value(0.001)}).is_ok());
    int rl_sock_resp = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in rl_target{};
    rl_target.sin_family = AF_INET;
    rl_target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    rl_target.sin_port = htons(ws_port);
    (void)rl_sock_resp; // reuse ws listener only for connect; send is rate-limited before wire
    auto rl_open = invoke("stdnet.tcp_open", {Value("tcp://127.0.0.1:" + std::to_string(ws_port) + "/"), Value(static_cast<int64_t>(1000))});
    ASSERT_TRUE(rl_open.is_ok());
    std::string big(1024, 'x');
    auto rl_send = invoke("stdnet.tcp_send", {rl_open.value(), Value(big)});
    ASSERT_FALSE(rl_send.is_ok()); // burst 0.001KB << 1KB payload
    ASSERT_TRUE(invoke("stdnet.tcp_close", {rl_open.value()}).is_ok());
    ASSERT_TRUE(invoke("stdnet.rate_limit", {Value(0), Value(0)}).is_ok()); // disable

    // 7. Unload: everything closes (UDS thread + WS listener torn down first).
    ASSERT_TRUE(loader.unload_module("stdnet").is_ok());
    auto gone = invoke("stdnet.reactor_backend", {});
    ASSERT_FALSE(gone.is_ok());

    uds_running = false;
    ws_running = false;
    uds_server.join();
    ws_server.join();
    stdnet::UdsStream::remove_path(uds_path);
}
