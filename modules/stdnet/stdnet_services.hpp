#pragma once

// stdnet — binder-target service functions (defined in stdnet.services.cpp).
// Declared here so stdnet_module.cpp can register them via ctx.binds().fn<&...>.

#include "dvargosh/types.hpp"
#include <vector>

namespace dvargosh {

Result<Value> stdnet_uri_parse(const std::vector<Value>& args);
Result<Value> stdnet_resolve(const std::vector<Value>& args);
Result<Value> stdnet_dns_stats(const std::vector<Value>& args);

Result<Value> stdnet_tcp_open(const std::vector<Value>& args);
Result<Value> stdnet_tcp_send(const std::vector<Value>& args);
Result<Value> stdnet_tcp_recv(const std::vector<Value>& args);
Result<Value> stdnet_tcp_close(const std::vector<Value>& args);

Result<Value> stdnet_udp_send(const std::vector<Value>& args);
Result<Value> stdnet_udp_roundtrip(const std::vector<Value>& args);

Result<Value> stdnet_http_request(const std::vector<Value>& args);
Result<Value> stdnet_http_get(const std::vector<Value>& args);
Result<Value> stdnet_http_post(const std::vector<Value>& args);

// --- stdnet v2: async runtime, UDS, TLS, WebSockets, server, flow control ---

Result<Value> stdnet_reactor_backend(const std::vector<Value>& args);

Result<Value> stdnet_resolve_reverse(const std::vector<Value>& args);
Result<Value> stdnet_resolve_async(const std::vector<Value>& args);   // (host, service, tag)
Result<Value> stdnet_resolve_reverse_async(const std::vector<Value>& args); // (ip, tag)

Result<Value> stdnet_timer_after(const std::vector<Value>& args);     // (ms) -> fires event
Result<Value> stdnet_coro_delay_probe(const std::vector<Value>& args);// (ms) -> coroutine-driven probe

Result<Value> stdnet_uds_open(const std::vector<Value>& args);
Result<Value> stdnet_uds_send(const std::vector<Value>& args);
Result<Value> stdnet_uds_recv(const std::vector<Value>& args);
Result<Value> stdnet_uds_close(const std::vector<Value>& args);

Result<Value> stdnet_ws_connect(const std::vector<Value>& args);
Result<Value> stdnet_ws_send(const std::vector<Value>& args);
Result<Value> stdnet_ws_recv(const std::vector<Value>& args);
Result<Value> stdnet_ws_close(const std::vector<Value>& args);

Result<Value> stdnet_https_get(const std::vector<Value>& args);
Result<Value> stdnet_tls_status(const std::vector<Value>& args);

Result<Value> stdnet_http_server_listen(const std::vector<Value>& args);
Result<Value> stdnet_http_server_stop(const std::vector<Value>& args);

Result<Value> stdnet_rate_limit(const std::vector<Value>& args);       // (rate_kBps, burst_kb)
Result<Value> stdnet_hooks_enable(const std::vector<Value>& args);

} // namespace dvargosh
