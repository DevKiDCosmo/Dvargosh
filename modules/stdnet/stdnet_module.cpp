// Dvargosh Standard Library — stdnet module.
// All networking services live in stdnet.services.cpp as plain functions bound
// through the ServiceBinder; this file owns the manifest, the permission
// contract, the service lifecycle, and the telemetry surface.
#include "dvargosh/dvargosh.hpp"
#include "stdnet_service.hpp"
#include "stdnet_services.hpp"

namespace dvargosh {

class StdNetModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest m = []() {
            ModuleManifest man;
            man.name = "stdnet";
            man.domain = "std:net";
            man.version = Version{1, 0, 0};
            man.description = "Dvargosh Standard Library: networking (URI, DNS, TCP, UDP, HTTP)";
            man.author = "Dvargosh Team";
            man.requested_permissions = PermissionSet({
                Permission::ServiceRegister,
                Permission::DynamicInvoke,
                Permission::NetworkAccess
            });
            return man;
        }();
        return m;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        // The module's own permission contract: without NetworkAccess in the
        // EFFECTIVE policy (host ceiling ∩ manifest request), provide nothing.
        if (!ctx.policy().permissions().has(Permission::NetworkAccess)) {
            return Result<void>::failure(
                StatusCode::PermissionDenied,
                "stdnet requires the NetworkAccess permission in its effective policy"
            );
        }

        stdnet::set_instance(std::make_shared<stdnet::NetServiceImpl>(ctx.telemetry()));
        (void)ctx.record_metric("startup", 1.0);

        return ctx.binds()
            // URI
            .fn<&stdnet_uri_parse>("stdnet.uri_parse", "Parses a URI: scheme/host/port/path/query/fragment")
            // DNS / IP
            .fn<&stdnet_resolve>("stdnet.resolve", "Resolves host+service to IP list (uses TTL cache)")
            .fn<&stdnet_dns_stats>("stdnet.dns_stats", "DNS cache statistics")
            // TCP (connection table owned by this module)
            .fn<&stdnet_tcp_open>("stdnet.tcp_open", "Opens a TCP connection (uri, timeout_ms) -> conn_id")
            .fn<&stdnet_tcp_send>("stdnet.tcp_send", "Sends bytes on a connection (conn_id, data)")
            .fn<&stdnet_tcp_recv>("stdnet.tcp_recv", "Receives up to max bytes (conn_id, max_bytes, timeout_ms)")
            .fn<&stdnet_tcp_close>("stdnet.tcp_close", "Closes a connection (conn_id)")
            // UDP
            .fn<&stdnet_udp_send>("stdnet.udp_send", "Sends one UDP datagram (host, port, payload)")
            .fn<&stdnet_udp_roundtrip>("stdnet.udp_roundtrip", "UDP send + wait for reply (host, port, payload, timeout_ms)")
            // HTTP
            .fn<&stdnet_http_request>("stdnet.http_request", "Raw HTTP/1.1 exchange (method, uri, headers, body, timeout_ms)")
            .fn<&stdnet_http_get>("stdnet.http_get", "HTTP GET, returns body (uri, timeout_ms)")
            .fn<&stdnet_http_post>("stdnet.http_post", "HTTP POST, returns body (uri, body, content_type, timeout_ms)")
            .result();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }

    Result<void> on_unload(ModuleContext& ctx) override {
        if (auto s = stdnet::instance()) {
            const size_t closed = s->close_all();
            if (closed > 0) {
                (void)ctx.record_metric("connections_closed_on_unload", static_cast<double>(closed));
            }
        }
        stdnet::set_instance(nullptr);
        return Result<void>::success();
    }
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::StdNetModule)
