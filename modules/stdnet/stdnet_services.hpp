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

} // namespace dvargosh
