#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Transport layer: a TLS-wrapped socket plus the framing helpers everything
// else is written against. The platform socket API is confined to wire.cpp,
// so the rest of the tree compiles unchanged on POSIX and on Windows.
namespace pcs {

// Must be called once before any socket work (initialises Winsock and the
// OpenSSL error strings). Safe to call more than once.
void net_startup();
void net_shutdown();

class Channel;
using ChannelPtr = std::unique_ptr<Channel>;

// A connected, TLS-established endpoint. Closing is handled by the destructor.
class Channel {
public:
    virtual ~Channel() = default;

    virtual bool send(const void* data, size_t len) = 0;
    virtual bool recv(void* data, size_t len) = 0;

    // Reads up to and including '\n' and returns the line without it.
    // Returns false on EOF, error, or a line longer than kMaxLineLen.
    virtual bool read_line(std::string& out) = 0;

    bool send_line(const std::string& line);
};

// Client side. `address` is "host:port"; the host may be a name or a literal
// IPv4/IPv6 address. Returns nullptr if the connection or handshake fails.
ChannelPtr dial(const std::string& address, std::string& error);

// Server side.
class Listener {
public:
    virtual ~Listener() = default;
    // Blocks until a client connects and completes the TLS handshake.
    // Returns nullptr for a connection that failed to handshake; the caller
    // should simply continue accepting.
    virtual ChannelPtr accept() = 0;
};

using ListenerPtr = std::unique_ptr<Listener>;

// Binds `port` and serves the given certificate. Returns nullptr on failure.
ListenerPtr listen_tls(int port, const std::string& cert_path,
                       const std::string& key_path, std::string& error);

// Writes a fresh self-signed certificate/key pair, used on first run.
bool write_self_signed_cert(const std::string& cert_path,
                            const std::string& key_path, std::string& error);

}  // namespace pcs
