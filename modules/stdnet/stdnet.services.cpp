// stdnet — free binder-target service functions.
// Each looks up the module's NetServiceImpl and fails cleanly when the module
// is not loaded (e.g. after unload). No state capture, no marker boilerplate.
#include "stdnet_service.hpp"
#include "stdnet_services.hpp"
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

} // namespace dvargosh
