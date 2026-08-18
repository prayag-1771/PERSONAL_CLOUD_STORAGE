#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "pcs/config.hpp"
#include "pcs/keysource.hpp"
#include "pcs/protocol.hpp"
#include "pcs/tlsca.hpp"
#include "pcs/wire.hpp"
#include "session.hpp"
#include "store.hpp"
#include "users.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace {

void print_usage() {
    cout
        << "Usage: pcs-server <port> [command] [options]\n"
        << "\n"
        << "With no command, runs the server on <port>.\n"
        << "\n"
        << "Account commands:\n"
        << "  useradd <name>    create an account (prompts for a password)\n"
        << "  userdel <name>    remove an account and leave its files in place\n"
        << "  userlist          show the accounts on this server\n"
        << "  passwd <name>     change an account password\n"
        << "\n"
        << "Certificate commands:\n"
        << "  ca-export <path>  copy the CA certificate somewhere, ready to\n"
        << "                    install on a phone or laptop\n"
        << "\n"
        << "Options:\n"
        << "  --root <dir>      data directory\n"
        << "                    (default: ./storage/server_<port>)\n"
        << "  --token <token>   shared machine token, or set PCS_TOKEN\n"
        << "  --host <name>     an extra name or address this server is\n"
        << "                    reached by; repeatable\n"
        << "\n"
        << "Each account has its own storage and its own passphrase, so one\n"
        << "person cannot read another's files. Peers that hold shards for\n"
        << "each other must share one machine token.\n";
}

// Prompts twice, since a mistyped password would lock the account out.
bool ask_new_password(string& out) {
    string first, second;
    if (!pcs::read_hidden_line("New password: ", first) || first.empty()) {
        cout << "No password entered.\n";
        return false;
    }
    if (!pcs::read_hidden_line("Confirm password: ", second)) return false;
    if (first != second) {
        cout << "The two entries did not match.\n";
        return false;
    }
    out = first;
    return true;
}

int run_account_command(const string& command, const vector<string>& args,
                        pcs::server::UserStore& users) {
    string error;

    if (command == "userlist") {
        const vector<string> names = users.names();
        if (names.empty()) {
            cout << "No accounts yet. Create one with: pcs-server <port> "
                    "useradd <name>\n";
            return 0;
        }
        cout << names.size() << " account(s):\n";
        for (const string& name : names) cout << "  " << name << "\n";
        return 0;
    }

    if (args.empty()) {
        cout << "That command needs an account name.\n";
        return 1;
    }
    const string& name = args[0];

    if (command == "useradd") {
        string password;
        if (!ask_new_password(password)) return 1;
        if (!users.add(name, password, error)) {
            cout << error << "\n";
            return 1;
        }
        cout << "Created account '" << name << "'.\n";
        return 0;
    }

    if (command == "passwd") {
        string password;
        if (!ask_new_password(password)) return 1;
        if (!users.set_password(name, password, error)) {
            cout << error << "\n";
            return 1;
        }
        cout << "Password changed for '" << name << "'.\n";
        return 0;
    }

    if (command == "userdel") {
        if (!users.remove(name, error)) {
            cout << error << "\n";
            return 1;
        }
        cout << "Removed account '" << name << "'. Their files are still on "
                "disk; delete them by hand if you want them gone.\n";
        return 0;
    }

    cout << "Unknown command: " << command << "\n";
    return 1;
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
    string forced_token;
    vector<string> extra_hosts;
    string command;
    vector<string> command_args;

    for (int i = 2; i < argc; i++) {
        const string arg = argv[i];
        if (arg == "--root" && i + 1 < argc) {
            root = argv[++i];
        } else if (arg == "--token" && i + 1 < argc) {
            forced_token = argv[++i];
        } else if (arg == "--host" && i + 1 < argc) {
            extra_hosts.push_back(argv[++i]);
        } else if (arg.rfind("--", 0) == 0) {
            cerr << "Unknown option: " << arg << "\n";
            return 1;
        } else if (command.empty()) {
            command = arg;
        } else {
            command_args.push_back(arg);
        }
    }

    pcs::net_startup();

    pcs::server::Store store(root);
    string error;
    if (!store.init(error)) {
        cerr << "Cannot prepare storage: " << error << "\n";
        return 1;
    }

    pcs::server::UserStore users(root / "users.txt");
    if (!users.load(error)) {
        cerr << "Cannot read the account list: " << error << "\n";
        return 1;
    }

    if (command == "ca-export") {
        if (command_args.empty()) {
            cout << "Usage: pcs-server <port> ca-export <path>\n";
            return 1;
        }
        const fs::path source = root / "ca.crt";
        if (!fs::exists(source)) {
            cout << "No CA yet. Start the server once so it can create one.\n";
            return 1;
        }
        error_code ec;
        fs::copy_file(source, command_args[0],
                      fs::copy_options::overwrite_existing, ec);
        if (ec) {
            cout << "Cannot copy the CA certificate: " << ec.message() << "\n";
            return 1;
        }
        cout << "Wrote " << command_args[0] << "\n"
             << "Install it as a trusted root on each device, and point the\n"
             << "command-line client at it with --cacert.\n";
        return 0;
    }

    if (!command.empty())
        return run_account_command(command, command_args, users);

    if (forced_token.empty()) {
        if (const char* from_env = getenv("PCS_TOKEN")) forced_token = from_env;
    }
    const string token =
        forced_token.empty()
            ? pcs::server::load_or_create_token(root / "auth.token")
            : forced_token;

    const fs::path ca_cert = root / "ca.crt";
    const fs::path ca_key  = root / "ca.key";
    const fs::path cert    = root / "server.crt";
    const fs::path key     = root / "server.key";

    if (!pcs::ensure_ca(ca_cert.string(), ca_key.string(), error)) {
        cerr << "Cannot prepare the local CA: " << error << "\n";
        return 1;
    }

    vector<string> hosts = pcs::local_host_identities();
    hosts.insert(hosts.end(), extra_hosts.begin(), extra_hosts.end());
    sort(hosts.begin(), hosts.end());
    hosts.erase(unique(hosts.begin(), hosts.end()), hosts.end());

    // Reissued when it is missing, close to expiry, or does not cover a name
    // that has been added since it was written.
    if (!fs::exists(key) ||
        pcs::server_cert_needs_reissue(cert.string(), hosts, 30)) {
        if (!pcs::issue_server_cert(ca_cert.string(), ca_key.string(),
                                    cert.string(), key.string(), hosts,
                                    error)) {
            cerr << "Cannot issue the server certificate: " << error << "\n";
            return 1;
        }
        cout << "[server] issued a certificate for: ";
        for (size_t i = 0; i < hosts.size(); i++)
            cout << (i ? ", " : "") << hosts[i];
        cout << "\n";
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
         << "[server] machine token: " << token << "\n"
         << "[server] CA certificate: " << ca_cert.string() << "\n"
         << "[server] install that on each device, or export a copy with:\n"
         << "[server]   pcs-server " << port_text << " ca-export <path>\n";

    if (users.empty()) {
        cout << "[server] no accounts yet - nobody can store anything.\n"
             << "[server] create one with: pcs-server " << port_text
             << " useradd <name>\n";
    } else {
        cout << "[server] " << users.names().size() << " account(s) registered\n";
    }

    while (true) {
        pcs::ChannelPtr channel = listener->accept();
        if (!channel) continue;  // failed handshake; keep serving others

        thread([channel = move(channel), &store, &users, token, port]() mutable {
            pcs::server::Session session(*channel, store, users, token, port);
            session.run();
        }).detach();
    }
}
