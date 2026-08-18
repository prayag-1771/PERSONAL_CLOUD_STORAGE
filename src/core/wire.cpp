#include "pcs/wire.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
static constexpr socket_t kBadSocket = INVALID_SOCKET;
#define pcs_close_socket closesocket
#else
#include <cerrno>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t kBadSocket = -1;
#define pcs_close_socket ::close
#endif

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pcs/config.hpp"
#include "pcs/tlsca.hpp"

using namespace std;

namespace pcs {
namespace {

once_flag g_startup_once;

string ssl_error_text() {
    unsigned long code = ERR_get_error();
    if (code == 0) return "unknown TLS error";
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    return string(buf);
}

// Splits "host:port". IPv6 literals may be bracketed, as in "[::1]:9000".
bool split_address(const string& address, string& host,
                   string& port) {
    if (address.empty()) return false;

    if (address.front() == '[') {
        const size_t close = address.find(']');
        if (close == string::npos || close + 2 > address.size()) return false;
        if (address[close + 1] != ':') return false;
        host = address.substr(1, close - 1);
        port = address.substr(close + 2);
    } else {
        const size_t colon = address.rfind(':');
        if (colon == string::npos) return false;
        host = address.substr(0, colon);
        port = address.substr(colon + 1);
    }
    return !host.empty() && !port.empty();
}

bool set_blocking(socket_t fd, bool blocking) {
#ifdef _WIN32
    u_long mode = blocking ? 0 : 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags) == 0;
#endif
}

// Connects with a bounded wait. A blocking connect to a machine that is off
// can hang for over a minute, which would make the "is the server up?" check
// useless as a fallback trigger.
bool connect_with_timeout(socket_t fd, const sockaddr* addr, socklen_t len,
                          int timeout_seconds) {
    if (!set_blocking(fd, false)) return false;

    const int rc = ::connect(fd, addr, len);
    if (rc == 0) return set_blocking(fd, true);

#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) return false;
#else
    if (errno != EINPROGRESS) return false;
#endif

    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(fd, &writable);

    timeval tv{};
    tv.tv_sec = timeout_seconds;
    tv.tv_usec = 0;

    const int ready = ::select(static_cast<int>(fd) + 1, nullptr, &writable,
                               nullptr, &tv);
    if (ready <= 0) return false;

    int err = 0;
    socklen_t err_len = sizeof(err);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err),
                     &err_len) != 0 || err != 0) {
        return false;
    }
    return set_blocking(fd, true);
}

}  // namespace

void net_startup() {
    call_once(g_startup_once, [] {
#ifdef _WIN32
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
#endif
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                             OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
                         nullptr);
    });
}

void net_shutdown() {
#ifdef _WIN32
    WSACleanup();
#endif
}

bool Channel::send_line(const string& line) {
    const string framed = line + "\n";
    return send(framed.data(), framed.size());
}

namespace {

// A TLS endpoint that owns its socket and, on the client side, its context.
class TlsChannel : public Channel {
public:
    TlsChannel(socket_t fd, SSL* ssl, SSL_CTX* owned_ctx)
        : fd_(fd), ssl_(ssl), owned_ctx_(owned_ctx) {}

    ~TlsChannel() override {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        if (fd_ != kBadSocket) pcs_close_socket(fd_);
        if (owned_ctx_) SSL_CTX_free(owned_ctx_);
    }

    bool send(const void* data, size_t len) override {
        const char* p = static_cast<const char*>(data);
        size_t sent = 0;
        while (sent < len) {
            const size_t want = len - sent;
            const int chunk = want > INT32_MAX ? INT32_MAX
                                               : static_cast<int>(want);
            const int n = SSL_write(ssl_, p + sent, chunk);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    bool recv(void* data, size_t len) override {
        char* p = static_cast<char*>(data);
        size_t got = 0;
        while (got < len) {
            const size_t want = len - got;
            const int chunk = want > INT32_MAX ? INT32_MAX
                                               : static_cast<int>(want);
            const int n = SSL_read(ssl_, p + got, chunk);
            if (n <= 0) return false;
            got += static_cast<size_t>(n);
        }
        return true;
    }

    bool read_line(string& out) override {
        out.clear();
        char c = 0;
        while (true) {
            const int n = SSL_read(ssl_, &c, 1);
            if (n <= 0) return false;
            if (c == '\n') return true;
            if (c == '\r') continue;
            // Refuse an unbounded "line" rather than growing without limit.
            if (out.size() >= config::kMaxLineLen) return false;
            out.push_back(c);
        }
    }

private:
    socket_t fd_ = kBadSocket;
    SSL* ssl_ = nullptr;
    SSL_CTX* owned_ctx_ = nullptr;
};

class TlsListener : public Listener {
public:
    TlsListener(socket_t fd, SSL_CTX* ctx) : fd_(fd), ctx_(ctx) {}

    ~TlsListener() override {
        if (fd_ != kBadSocket) pcs_close_socket(fd_);
        if (ctx_) SSL_CTX_free(ctx_);
    }

    ChannelPtr accept() override {
        socket_t client = ::accept(fd_, nullptr, nullptr);
        if (client == kBadSocket) return nullptr;

        SSL* ssl = SSL_new(ctx_);
        if (!ssl) {
            pcs_close_socket(client);
            return nullptr;
        }
        SSL_set_fd(ssl, static_cast<int>(client));

        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            pcs_close_socket(client);
            return nullptr;
        }
        // The listener keeps owning ctx_; the channel must not free it.
        return ChannelPtr(new TlsChannel(client, ssl, nullptr));
    }

private:
    socket_t fd_ = kBadSocket;
    SSL_CTX* ctx_ = nullptr;
};

}  // namespace

ChannelPtr dial(const string& address, const TlsTrust& trust, string& error) {
    net_startup();

    string host, port;
    if (!split_address(address, host, port)) {
        error = "malformed address (expected host:port): " + address;
        return nullptr;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* results = nullptr;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &results) != 0 ||
        results == nullptr) {
        error = "cannot resolve " + address;
        return nullptr;
    }

    socket_t fd = kBadSocket;
    for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
        fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == kBadSocket) continue;

        if (connect_with_timeout(fd, it->ai_addr,
                                 static_cast<socklen_t>(it->ai_addrlen),
                                 config::kConnectTimeoutS)) {
            break;
        }
        pcs_close_socket(fd);
        fd = kBadSocket;
    }
    ::freeaddrinfo(results);

    if (fd == kBadSocket) {
        error = "cannot connect to " + address;
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        pcs_close_socket(fd);
        error = "cannot create TLS context: " + ssl_error_text();
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (trust.verify) {
        if (trust.ca_file.empty()) {
            SSL_CTX_free(ctx);
            pcs_close_socket(fd);
            error = "no CA certificate given: pass --cacert, set PCS_CACERT, "
                    "or use --insecure to accept any certificate";
            return nullptr;
        }
        if (SSL_CTX_load_verify_locations(ctx, trust.ca_file.c_str(),
                                          nullptr) != 1) {
            SSL_CTX_free(ctx);
            pcs_close_socket(fd);
            error = "cannot read the CA certificate " + trust.ca_file;
            return nullptr;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        pcs_close_socket(fd);
        error = "cannot create TLS session: " + ssl_error_text();
        return nullptr;
    }
    SSL_set_fd(ssl, static_cast<int>(fd));
    SSL_set_tlsext_host_name(ssl, host.c_str());

    if (trust.verify) {
        // Verifying the chain is not enough on its own: without this, the
        // certificate of any machine in the group would be accepted for any
        // other. A literal address is matched against the IP entries and a
        // name against the DNS entries, which are checked separately.
        X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set_hostflags(param,
                                        X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        const int named =
            looks_like_ip(host)
                ? X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str())
                : X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0);
        if (named != 1) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            pcs_close_socket(fd);
            error = "cannot check the certificate against " + host;
            return nullptr;
        }
    }

    if (SSL_connect(ssl) <= 0) {
        const long result = SSL_get_verify_result(ssl);
        error = result != X509_V_OK
                    ? "certificate rejected for " + address + ": " +
                          X509_verify_cert_error_string(result)
                    : "TLS handshake failed with " + address;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        pcs_close_socket(fd);
        return nullptr;
    }

    return ChannelPtr(new TlsChannel(fd, ssl, ctx));
}

ListenerPtr listen_tls(int port, const string& cert_path,
                       const string& key_path, string& error) {
    net_startup();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        error = "cannot create TLS context: " + ssl_error_text();
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        error = "cannot load certificate or key: " + ssl_error_text();
        return nullptr;
    }

    socket_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd == kBadSocket) {
        SSL_CTX_free(ctx);
        error = "cannot create socket";
        return nullptr;
    }

    int reuse = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        pcs_close_socket(fd);
        SSL_CTX_free(ctx);
        error = "cannot bind port " + to_string(port) +
                " (is another server already running?)";
        return nullptr;
    }
    if (::listen(fd, 32) != 0) {
        pcs_close_socket(fd);
        SSL_CTX_free(ctx);
        error = "cannot listen on port " + to_string(port);
        return nullptr;
    }

    return ListenerPtr(new TlsListener(fd, ctx));
}

}  // namespace pcs
