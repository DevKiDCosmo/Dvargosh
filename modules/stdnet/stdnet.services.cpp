// stdnet — free binder-target service functions.
// Each looks up the module's NetServiceImpl and fails cleanly when the module
// is not loaded (e.g. after unload). No state capture, no marker boilerplate.
#include "stdnet_service.hpp"
#include "stdnet_services.hpp"
#include "stdnet_reactor.hpp"
#include "stdnet_coro.hpp"
#include "stdnet_framing.hpp"
#include "dvargosh/dvargosh.hpp"

namespace dvargosh {

namespace {

std::shared_ptr<stdnet::NetServiceImpl> svc() {
    return stdnet::instance();
}

Result<Value> fail(const std::string& msg) {
    return Result<Value>::failure(StatusCode::InternalError, msg);
}

} // namespace

// --- URI -------------------------------------------------------------------------

Result<Value> stdnet_uri_parse(const std::vector<Value>& args) {
    if (args.size() != 1) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.uri_parse requires (uri)");
    stdnet::Uri uri = stdnet::parse_uri(args[0].to_string());
    if (!uri.valid) return Result<Value>::failure(StatusCode::InvalidArg, uri.error);
    return Result<Value>::success(Value(uri.to_display()));
}

// --- DNS / IP ----------------------------------------------------------------------

Result<Value> stdnet_resolve(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.resolve requires (host, service)");
    auto ips = s->resolve(args[0].to_string(), args[1].to_string());
    if (ips.empty()) return Result<Value>::failure(StatusCode::NotFound, "no addresses resolved for '" + args[0].to_string() + "'");
    std::string joined;
    for (const auto& ip : ips) {
        if (!joined.empty()) joined += ", ";
        joined += ip;
    }
    return Result<Value>::success(Value(joined));
}

Result<Value> stdnet_dns_stats(const std::vector<Value>& /*args*/) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    return Result<Value>::success(Value(
        "{lookups=" + std::to_string(s->dns_lookups()) +
        ", cache_hits=" + std::to_string(s->dns_cache_hits()) + "}"));
}

// --- TCP -----------------------------------------------------------------------------

Result<Value> stdnet_tcp_open(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 1) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.tcp_open requires (uri[, timeout_ms])");
    const int timeout = args.size() > 1 ? static_cast<int>(args[1].as_int()) : stdnet::kDefaultTimeoutMs;

    stdnet::Uri uri = stdnet::parse_uri(args[0].to_string());
    if (!uri.valid) return Result<Value>::failure(StatusCode::InvalidArg, uri.error);
    if (uri.is_tls_scheme()) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet does not implement TLS");
    if (!uri.apply_scheme_defaults()) return Result<Value>::failure(StatusCode::InvalidArg, "URI missing usable port");

    std::string error;
    int64_t id = s->tcp_open(uri.host, uri.port, timeout, error);
    if (id < 0) return Result<Value>::failure(StatusCode::LoadFailed, error);
    return Result<Value>::success(Value(id));
}

Result<Value> stdnet_tcp_send(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.tcp_send requires (conn_id, data)");
    std::string error;
    std::string data = args[1].to_string();
    int64_t n = s->tcp_send(args[0].as_int(), data.data(), data.size(), error);
    if (n < 0) return Result<Value>::failure(StatusCode::LoadFailed, error);
    return Result<Value>::success(Value(n));
}

Result<Value> stdnet_tcp_recv(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 3) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.tcp_recv requires (conn_id, max_bytes, timeout_ms)");
    std::string error;
    std::string data = s->tcp_recv(args[0].as_int(),
                                   static_cast<size_t>(args[1].as_int()),
                                   static_cast<int>(args[2].as_int()), error);
    if (data.empty() && !error.empty()) return Result<Value>::failure(StatusCode::LoadFailed, error);
    return Result<Value>::success(Value(data));
}

Result<Value> stdnet_tcp_close(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 1) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.tcp_close requires (conn_id)");
    return Result<Value>::success(Value(s->tcp_close(args[0].as_int())));
}

// --- UDP -------------------------------------------------------------------------------

Result<Value> stdnet_udp_send(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 3) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.udp_send requires (host, port, payload)");
    const uint16_t port = static_cast<uint16_t>(args[1].as_int());
    std::string data = args[2].to_string();
    std::string error;
    if (!s->udp_send(args[0].to_string(), port, data.data(), data.size(), error)) {
        return Result<Value>::failure(StatusCode::LoadFailed, error);
    }
    return Result<Value>::success(Value(static_cast<int64_t>(data.size())));
}

Result<Value> stdnet_udp_roundtrip(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 4) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.udp_roundtrip requires (host, port, payload, timeout_ms)");
    const uint16_t port = static_cast<uint16_t>(args[1].as_int());
    std::string data = args[2].to_string();
    const int timeout = static_cast<int>(args[3].as_int());
    std::string out, error;
    if (!s->udp_roundtrip(args[0].to_string(), port, data.data(), data.size(), timeout, out, error)) {
        return Result<Value>::failure(StatusCode::LoadFailed, error);
    }
    return Result<Value>::success(Value(out));
}

// --- HTTP --------------------------------------------------------------------------------

Result<Value> stdnet_http_request(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 5) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.http_request requires (method, uri, headers, body, timeout_ms)");
    std::string out, error;
    if (!s->http_exchange(args[0].to_string(), args[1].to_string(), args[2].to_string(),
                          args[3].to_string(), static_cast<int>(args[4].as_int()),
                          /*body_only=*/false, out, error)) {
        return Result<Value>::failure(StatusCode::LoadFailed, error);
    }
    return Result<Value>::success(Value(out));
}

Result<Value> stdnet_http_get(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 1) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.http_get requires (uri[, timeout_ms])");
    const int timeout = args.size() > 1 ? static_cast<int>(args[1].as_int()) : stdnet::kDefaultTimeoutMs;
    std::string out, error;
    if (!s->http_exchange("GET", args[0].to_string(), "", "", timeout, /*body_only=*/true, out, error)) {
        return Result<Value>::failure(StatusCode::LoadFailed, error);
    }
    return Result<Value>::success(Value(out));
}

Result<Value> stdnet_http_post(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 4) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.http_post requires (uri, body, content_type, timeout_ms)");
    std::string headers = "Content-Type: " + args[2].to_string();
    std::string out, error;
    if (!s->http_exchange("POST", args[0].to_string(), headers, args[1].to_string(),
                          static_cast<int>(args[3].as_int()), /*body_only=*/true, out, error)) {
        return Result<Value>::failure(StatusCode::LoadFailed, error);
    }
    return Result<Value>::success(Value(out));
}

// ============================================================================
// v2 services: async runtime, UDS, TLS, WebSockets, server, flow control
// ============================================================================

Result<Value> stdnet_reactor_backend(const std::vector<Value>& /*args*/) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    return Result<Value>::success(Value(std::string(stdnet::Reactor::backend_name())));
}

Result<Value> stdnet_resolve_reverse(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.resolve_reverse requires (ip)");
    std::string name, error;
    if (!s->resolve_reverse(args[0].to_string(), name, error)) {
        return Result<Value>::failure(StatusCode::NotFound, error);
    }
    return Result<Value>::success(Value(name));
}

Result<Value> stdnet_resolve_async(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 3) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.resolve_async requires (host, service, tag)");
    s->resolve_async(args[0].to_string(), args[1].to_string(), args[2].to_string());
    return Result<Value>::success(Value(true));
}

Result<Value> stdnet_resolve_reverse_async(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.resolve_reverse_async requires (ip, tag)");
    s->resolve_reverse_async(args[0].to_string(), args[1].to_string());
    return Result<Value>::success(Value(true));
}

Result<Value> stdnet_timer_after(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.timer_after requires (ms)");
    const int ms = static_cast<int>(args[0].as_int());
    auto id = s->reactor().timer_after(ms, [s] {
        s->reactor().post([] {}); // keep reactor reference alive in the job
    });
    return Result<Value>::success(Value(static_cast<int64_t>(id)));
}

// Coroutine probe: co_awaits a steady timer then a posted job — proves the
// C++20 integration without blocking the calling thread's reactor.
Result<Value> stdnet_coro_delay_probe(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    const int ms = args.empty() ? 50 : static_cast<int>(args[0].as_int());
    stdnet::Reactor& r = s->reactor();

    auto probe = [&]() -> stdnet::task<int64_t> {
        co_await stdnet::async_delay(r, ms);
        co_await stdnet::async_post(r, [] {});
        co_return static_cast<int64_t>(ms);
    };
    stdnet::task<int64_t> t = probe();
    int64_t waited = stdnet::sync_wait(t, r);
    return Result<Value>::success(Value(waited));
}

Result<Value> stdnet_uds_open(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.uds_open requires (path)");
    std::string error;
    int64_t id = s->uds_open(args[0].to_string(), error);
    if (id < 0) return Result<Value>::failure(StatusCode::LoadFailed, error);
    return Result<Value>::success(Value(id));
}

Result<Value> stdnet_uds_send(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.uds_send requires (conn_id, data)");
    std::string data = args[1].to_string();
    std::string error;
    int64_t n = s->uds_send(args[0].as_int(), data.data(), data.size(), error);
    if (n < 0) return Result<Value>::failure(StatusCode::LoadFailed, error);
    return Result<Value>::success(Value(n));
}

Result<Value> stdnet_uds_recv(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 3) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.uds_recv requires (conn_id, max_bytes, timeout_ms)");
    std::string error;
    std::string data = s->uds_recv(args[0].as_int(), static_cast<size_t>(args[1].as_int()),
                                   static_cast<int>(args[2].as_int()), error);
    if (data.empty() && !error.empty()) return Result<Value>::failure(StatusCode::LoadFailed, error);
    return Result<Value>::success(Value(data));
}

Result<Value> stdnet_uds_close(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.uds_close requires (conn_id)");
    return Result<Value>::success(Value(s->uds_close(args[0].as_int())));
}

Result<Value> stdnet_ws_connect(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.ws_connect requires (uri[, timeout_ms])");
    const int timeout = args.size() > 1 ? static_cast<int>(args[1].as_int()) : stdnet::kDefaultTimeoutMs;
    std::string error;
    int64_t id = s->ws_connect(args[0].to_string(), timeout, error);
    if (id < 0) return Result<Value>::failure(StatusCode::LoadFailed, error);
    return Result<Value>::success(Value(id));
}

Result<Value> stdnet_ws_send(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.ws_send requires (conn_id, text)");
    std::string error;
    if (!s->ws_send(args[0].as_int(), args[1].to_string(), error)) {
        return Result<Value>::failure(StatusCode::LoadFailed, error);
    }
    return Result<Value>::success(Value(true));
}

Result<Value> stdnet_ws_recv(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.ws_recv requires (conn_id, timeout_ms)");
    std::string error;
    std::string text = s->ws_recv(args[0].as_int(), static_cast<int>(args[1].as_int()), error);
    if (text.empty() && !error.empty()) return Result<Value>::failure(StatusCode::LoadFailed, error);
    return Result<Value>::success(Value(text));
}

Result<Value> stdnet_ws_close(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.ws_close requires (conn_id)");
    return Result<Value>::success(Value(s->ws_close(args[0].as_int())));
}

Result<Value> stdnet_https_get(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.https_get requires (uri[, timeout_ms])");
    const int timeout = args.size() > 1 ? static_cast<int>(args[1].as_int()) : stdnet::kDefaultTimeoutMs;
    std::string out, error;
    if (!s->https_exchange("GET", args[0].to_string(), "", "", timeout, /*body_only=*/true, out, error)) {
        return Result<Value>::failure(StatusCode::LoadFailed, error);
    }
    return Result<Value>::success(Value(out));
}

Result<Value> stdnet_tls_status(const std::vector<Value>& /*args*/) {
    return Result<Value>::success(Value(stdnet::tls_available() ? std::string("openssl-enabled") : std::string("not-built")));
}

Result<Value> stdnet_http_server_listen(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    uint16_t port = args.empty() ? 0 : static_cast<uint16_t>(args[0].as_int());
    std::string error;
    if (!s->http_server_listen(port, error)) {
        return Result<Value>::failure(StatusCode::LoadFailed, error);
    }
    return Result<Value>::success(Value(static_cast<int64_t>(s->http_server_port())));
}

Result<Value> stdnet_http_server_stop(const std::vector<Value>& /*args*/) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    return Result<Value>::success(Value(s->http_server_stop()));
}

Result<Value> stdnet_rate_limit(const std::vector<Value>& args) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "stdnet.rate_limit requires (rate_kBps, burst_kb)");
    // Rebuild the limiter with the requested budget and enable byte-cost checks.
    const double rate = args[0].as_double();
    const double burst = args[1].as_double();
    if (rate <= 0 || burst <= 0) {
        s->set_rate_enabled(false);
        return Result<Value>::success(Value(false));
    }
    s->rate_limiter().reset_config(rate, burst);
    s->set_rate_enabled(true);
    return Result<Value>::success(Value(true));
}

Result<Value> stdnet_hooks_enable(const std::vector<Value>& /*args*/) {
    auto s = svc();
    if (!s) return fail("stdnet module service not available");
    // Logging hook: counts byte volume + writes an operation log line per error.
    static std::atomic<uint64_t> hook_bytes{0};
    s->hooks().on_bytes([](const std::string& direction, const std::string&, size_t bytes) {
        hook_bytes += bytes;
        (void)direction;
    });
    s->hooks().on_error([](const std::string& operation, const std::string& error) {
        log_warn("[stdnet-hook] ", operation, ": ", error);
    });
    return Result<Value>::success(Value(static_cast<int64_t>(hook_bytes.load())));
}

} // namespace dvargosh
