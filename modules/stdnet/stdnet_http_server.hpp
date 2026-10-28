#pragma once

// stdnet — HTTP/1.1 server on the reactor: accept loop, per-connection buffers,
// handler invocation serialized on a strand (no user-side locking needed).
// Handlers return status + body; keep-alive is off (Connection: close), which
// keeps framing trivial and is sufficient for module-scale services.

#include "stdnet_http.hpp"
#include "stdnet_reactor.hpp"
#include "stdnet_strand.hpp"
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace dvargosh::stdnet {

struct HttpResponseSpec {
    int status = 200;
    std::string reason = "OK";
    std::string content_type = "text/plain";
    std::string body;
    std::vector<std::pair<std::string, std::string>> extra_headers;
};

using HttpHandler = std::function<HttpResponseSpec(const HttpRequest&)>;

class HttpServer {
public:
    HttpServer(Reactor& reactor, std::shared_ptr<Strand> strand = nullptr)
        : m_reactor(reactor),
          m_strand(strand ? std::move(strand) : Strand::make()) {}

    ~HttpServer() { stop(); }

    // Binds 127.0.0.1 (or any) and starts accepting on the reactor thread.
    bool listen(uint16_t port, HttpHandler handler, std::string& error);
    void stop();

    uint16_t port() const { return m_port; }
    bool running() const { return m_listen_fd >= 0; }

private:
    struct Conn {
        DynamicBuffer in;
        bool closing = false;
    };

    void on_listen_event(int fd, bool readable, bool /*writable*/, bool hungup);
    void on_conn_event(int fd, bool readable, bool /*writable*/, bool hungup);
    void write_response_and_close(int fd, const HttpResponseSpec& spec);

    Reactor& m_reactor;
    std::shared_ptr<Strand> m_strand;
    HttpHandler m_handler;
    int m_listen_fd = -1;
    uint16_t m_port = 0;
    std::map<int, std::unique_ptr<Conn>> m_conns;
};

} // namespace dvargosh::stdnet
