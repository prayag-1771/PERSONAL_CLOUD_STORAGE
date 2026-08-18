#include <atomic>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#include "pcs/config.hpp"
#include "pcs/protocol.hpp"
#include "pcs/wire.hpp"
#include "session.hpp"
#include "store.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace {

void print_usage() {
    cout
        << "Usage: pcs-server <port> [--root <dir>]\n"
        << "\n"
        << "  <port>          TCP port to listen on\n"
        << "  --root <dir>    where to keep data (default: ./storage/server_<port>)\n"
        << "\n"
        << "The auth token is created on first run and printed at startup.\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const string port_text = argv[1];
    if (port_text == "-h" || port_text == "--help") {
        print_usage();
        return 0;
    }

    uint64_t port_value = 0;
    if (!pcs::proto::parse_size(port_text, 65535, port_value) || port_value == 0) {
        cerr << "Invalid port: " << port_text << "\n";
        return 1;
    }
    const int port = static_cast<int>(port_value);

    fs::path root = fs::current_path() / "storage" / ("server_" + port_text);
    for (int i = 2; i < argc; i++) {
        const string arg = argv[i];
        if (arg == "--root" && i + 1 < argc) {
            root = argv[++i];
        } else {
            cerr << "Unknown argument: " << arg << "\n";
            return 1;
        }
    }

    pcs::net_startup();

    pcs::server::Store store(root);
    string error;
    if (!store.init(error)) {
        cerr << "Cannot prepare storage: " << error << "\n";
        return 1;
    }

    const string token =
        pcs::server::load_or_create_token(root / "auth.token");

    const fs::path cert = root / "server.crt";
    const fs::path key  = root / "server.key";
    if (!fs::exists(cert) || !fs::exists(key)) {
        if (!pcs::write_self_signed_cert(cert.string(), key.string(), error)) {
            cerr << "Cannot create TLS certificate: " << error << "\n";
            return 1;
        }
        cout << "[server] generated a self-signed TLS certificate\n";
    }

    pcs::ListenerPtr listener =
        pcs::listen_tls(port, cert.string(), key.string(), error);
    if (!listener) {
        cerr << "Cannot listen: " << error << "\n";
        return 1;
    }

    cout << "[server] protocol " << pcs::config::kProtocol << " on port "
              << port << " (TLS)\n"
              << "[server] data root: " << root.string() << "\n"
              << "[server] auth token: " << token << "\n"
              << "[server] clients need that token; it is stored in "
              << (root / "auth.token").string() << "\n";

    while (true) {
        pcs::ChannelPtr channel = listener->accept();
        if (!channel) continue;  // handshake failed; keep serving others

        // Detached because each connection is independent and short-lived.
        thread([channel = move(channel), &store, token, port]() mutable {
            pcs::server::Session session(*channel, store, token, port);
            session.run();
        }).detach();
    }
}
