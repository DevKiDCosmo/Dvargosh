// netprobe — development module for testing connections (ping-style probes).
// Exercises stdnet over cross-module RPC: TCP connect timing, HTTP probes,
// UDP roundtrip probes, and DNS probes. All probes return a compact report
// string so the CLI/tests can assert on them.
#include "dvargosh/dvargosh.hpp"
#include <chrono>

namespace dvargosh {

namespace {

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

// tcp_ping: measures connect RTT against host:port.
Result<Value> netprobe_tcp_ping(const std::vector<Value>& args) {
    if (args.size() < 2) return Result<Value>::failure(StatusCode::InvalidArg, "netprobe.tcp_ping requires (host, port[, timeout_ms])");
    auto* ctx = Runtime::get_context();
    if (!ctx) return Result<Value>::failure(StatusCode::NullPointer, "no module context");

    std::string host = args[0].to_string();
    int64_t port = args[1].as_int();
    int64_t timeout = args.size() > 2 ? args[2].as_int() : 2000;

    auto t0 = std::chrono::steady_clock::now();
    auto open = ctx->call("stdnet.tcp_open", {Value("tcp://" + host + ":" + std::to_string(port) + "/"), Value(timeout)});
    double rtt = ms_since(t0);
    if (!open.is_ok()) {
        return Result<Value>::failure(open.status(), "tcp_ping failed: " + open.error_message());
    }
    (void)ctx->call("stdnet.tcp_close", {open.value()});
    return Result<Value>::success(Value("tcp_ping host=" + host + " port=" + std::to_string(port) +
                                        " rtt_ms=" + std::to_string(rtt)));
}

// http_ping: measures full HTTP GET exchange and reports the status line body.
Result<Value> netprobe_http_ping(const std::vector<Value>& args) {
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "netprobe.http_ping requires (uri[, timeout_ms])");
    auto* ctx = Runtime::get_context();
    if (!ctx) return Result<Value>::failure(StatusCode::NullPointer, "no module context");

    std::string uri = args[0].to_string();
    int64_t timeout = args.size() > 1 ? args[1].as_int() : 2000;

    auto t0 = std::chrono::steady_clock::now();
    auto res = ctx->call("stdnet.http_get", {Value(uri), Value(timeout)});
    double rtt = ms_since(t0);
    if (!res.is_ok()) {
        return Result<Value>::failure(res.status(), "http_ping failed: " + res.error_message());
    }
    std::string body = res.value().to_string();
    if (body.size() > 64) body = body.substr(0, 64) + "...";
    return Result<Value>::success(Value("http_ping uri=" + uri + " rtt_ms=" + std::to_string(rtt) +
                                        " body=" + body));
}

// udp_ping: expects an echo server; measures the roundtrip.
Result<Value> netprobe_udp_ping(const std::vector<Value>& args) {
    if (args.size() < 3) return Result<Value>::failure(StatusCode::InvalidArg, "netprobe.udp_ping requires (host, port, payload[, timeout_ms])");
    auto* ctx = Runtime::get_context();
    if (!ctx) return Result<Value>::failure(StatusCode::NullPointer, "no module context");

    std::string payload = args[2].to_string();
    int64_t timeout = args.size() > 3 ? args[3].as_int() : 2000;

    auto t0 = std::chrono::steady_clock::now();
    auto res = ctx->call("stdnet.udp_roundtrip", {args[0], args[1], Value(payload), Value(timeout)});
    double rtt = ms_since(t0);
    if (!res.is_ok()) {
        return Result<Value>::failure(res.status(), "udp_ping failed: " + res.error_message());
    }
    bool echoed = res.value().to_string() == payload;
    return Result<Value>::success(Value("udp_ping host=" + args[0].to_string() + " rtt_ms=" + std::to_string(rtt) +
                                        " echoed=" + (echoed ? "yes" : "no")));
}

// dns_probe: forward resolution report.
Result<Value> netprobe_dns_probe(const std::vector<Value>& args) {
    if (args.empty()) return Result<Value>::failure(StatusCode::InvalidArg, "netprobe.dns_probe requires (host[, service])");
    auto* ctx = Runtime::get_context();
    if (!ctx) return Result<Value>::failure(StatusCode::NullPointer, "no module context");

    std::string service = args.size() > 1 ? args[1].to_string() : "80";
    auto t0 = std::chrono::steady_clock::now();
    auto res = ctx->call("stdnet.resolve", {args[0], Value(service)});
    double ms = ms_since(t0);
    if (!res.is_ok()) {
        return Result<Value>::failure(res.status(), "dns_probe failed: " + res.error_message());
    }
    return Result<Value>::success(Value("dns_probe host=" + args[0].to_string() +
                                        " ips=" + res.value().to_string() +
                                        " ms=" + std::to_string(ms)));
}

} // namespace

class NetProbeModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest m = []() {
            ModuleManifest man;
            man.name = "netprobe";
            man.domain = "dev:netprobe";
            man.version = Version{1, 0, 0};
            man.description = "Development module: connection testing probes (tcp/http/udp/dns ping) via stdnet";
            man.author = "Dvargosh Team";
            man.requested_permissions = PermissionSet({
                Permission::ServiceRegister,
                Permission::DynamicInvoke
            });
            return man;
        }();
        return m;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        (void)ctx.record_metric("startup", 1.0);
        return ctx.binds()
            .fn<&netprobe_tcp_ping>("netprobe.tcp_ping", "TCP connect ping: rtt in ms (host, port[, timeout_ms])")
            .fn<&netprobe_http_ping>("netprobe.http_ping", "HTTP GET probe: rtt + body preview (uri[, timeout_ms])")
            .fn<&netprobe_udp_ping>("netprobe.udp_ping", "UDP echo probe: rtt + echo check (host, port, payload[, timeout_ms])")
            .fn<&netprobe_dns_probe>("netprobe.dns_probe", "DNS probe: resolved IPs + duration (host[, service])")
            .result();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::NetProbeModule)
