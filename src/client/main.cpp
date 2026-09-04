#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "commands.hpp"
#include "pcs/config.hpp"
#include "pcs/keysource.hpp"
#include "pcs/protocol.hpp"
#include "pcs/daemon.hpp"
#include "pcs/settings.hpp"
#include "pcs/wire.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace {

void print_usage() {
    cout
        << "Usage: pcs-client [options] <command> [arguments]\n"
        << "\n"
        << "Commands:\n"
        << "  upload <file> [server] [peer1 peer2 peer3 peer4]\n"
        << "        Encrypt and store a file. Goes straight to the server\n"
        << "        when it is up; otherwise the four peers hold the pieces.\n"
        << "  download <name> [server]   (use --out for the path)\n"
        << "        Fetch and decrypt a file, from the server or from peers.\n"
        << "  seal <file> <output>\n"
        << "        Encrypt a file locally, without a server.\n"
        << "  open <file> <output>\n"
        << "        Decrypt a file that was sealed locally.\n"
        << "  delete <name> [server]\n"
        << "        Remove a stored file. This cannot be undone.\n"
        << "  list [server]\n"
        << "        Show what the server is holding.\n"
        << "  sync\n"
        << "        Forward pending files now that the server is reachable.\n"
        << "  watch [folder] [seconds]\n"
        << "        Upload anything that appears or changes in a folder,\n"
        << "        and forward pending files in the same loop.\n"
        << "  config\n"
        << "        Show which settings file is in use and what it sets.\n"
        << "  autosync [seconds]\n"
        << "        Keep watching and forward pending files automatically.\n"
        << "\n"
        << "Options:\n"
        << "  --user <name>     your account on the server (or set PCS_USER)\n"
        << "  --password <pw>   account password (or set PCS_PASSWORD; if"
        << "                    neither is given, it is prompted for)\n"
        << "  --token <token>   shared machine token, needed only to reach"
        << "                    peers (or set PCS_TOKEN)\n"
        << "  --keyfile <path>  read the passphrase from a file instead of\n"
        << "                    prompting (or set PCS_PASSPHRASE)\n"
        << "  --cacert <path>   CA certificate to verify the server against"
        << "                    (or set PCS_CACERT)\n"
        << "  --insecure        skip verification; only for bootstrapping\n"
        << "  --server <addr>   host:port of the server; also accepted as a\n"
        << "                    positional argument on most commands\n"
        << "  --out <path>      where a download is written\n"
        << "  --config <path>   settings file (default: ./pcs.conf, then\n"
        << "                    ~/.config/pcs/pcs.conf)\n"
        << "  --profile <name>  section of the settings file to use\n"
        << "  --dir <path>      where pending files are tracked (default: .)\n"
        << "  --quiet           no progress bars\n"
        << "  --daemon          detach and keep running after the terminal\n"
        << "                    closes (watch and autosync only)\n"
        << "  --log <path>      where a detached run writes its output\n"
        << "  --pidfile <path>  where to record the process id\n"
        << "  -h, --help        this message\n"
        << "  --version         print the version and exit\n"
        << "\n"
        << "Anything not given here is taken from the settings file, so a\n"
        << "server and peers usually need naming only once.\n"
        << "\n"
        << "Files are encrypted before they leave this machine. The server\n"
        << "never receives the passphrase or the key, and stores ciphertext\n"
        << "only. Keep the passphrase safe: without it the data is gone.\n";
}

// Pulls the known flags out of argv and leaves the positional arguments in
// order, so options may appear before or after the command.
bool parse_arguments(int argc, char* argv[], pcs::client::Options& options,
                     vector<string>& positional, bool& wants_help,
                     bool& wants_version,
                     string& output_path, string& config_path, string& profile,
                     bool& detach, string& log_path, string& pid_path) {
    for (int i = 1; i < argc; i++) {
        const string arg = argv[i];

        if (arg == "--version") {
            wants_version = true;
            return true;
        }
        if (arg == "-h" || arg == "--help") {
            wants_help = true;
            return true;
        }
        if (arg == "--quiet") {
            options.quiet = true;
        } else if (arg == "--token" && i + 1 < argc) {
            options.credentials.token = argv[++i];
        } else if (arg == "--user" && i + 1 < argc) {
            options.credentials.user = argv[++i];
        } else if (arg == "--password" && i + 1 < argc) {
            options.credentials.password = argv[++i];
        } else if (arg == "--keyfile" && i + 1 < argc) {
            options.key.keyfile = argv[++i];
        } else if (arg == "--server" && i + 1 < argc) {
            options.server = argv[++i];
        } else if (arg == "--dir" && i + 1 < argc) {
            options.work_dir = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            output_path = argv[++i];
        } else if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--profile" && i + 1 < argc) {
            profile = argv[++i];
        } else if (arg == "--daemon") {
            detach = true;
        } else if (arg == "--log" && i + 1 < argc) {
            log_path = argv[++i];
        } else if (arg == "--pidfile" && i + 1 < argc) {
            pid_path = argv[++i];
        } else if (arg == "--cacert" && i + 1 < argc) {
            options.trust.ca_file = argv[++i];
        } else if (arg == "--insecure") {
            options.trust.verify = false;
        } else if (arg.rfind("--", 0) == 0) {
            cout << "Unknown option: " << arg << "\n";
            return false;
        } else {
            positional.push_back(arg);
        }
    }
    return true;
}

// sync and autosync reach the server to deliver files, so they log in too;
// only the shard traffic underneath them runs on the machine token.
// Reports the missing setting once, in the same words everywhere.
// Command line first, then the positional argument, then the settings file.
string pick_server(const string& from_flag, const vector<string>& positional,
                   size_t index, const string& from_settings) {
    if (!from_flag.empty()) return from_flag;
    if (positional.size() > index) return positional[index];
    return from_settings;
}

bool require_server(const string& server) {
    if (!server.empty()) return true;
    cout << "No server given. Name one on the command line, or put\n"
         << "  server = host:port\n"
         << "in a pcs.conf settings file. See: pcs-client config\n";
    return false;
}

// Detaching is deferred until the command is about to start, so a bad
// argument is still reported to the terminal that typed it.
bool detach_now(const string& log_path, string& pid_path) {
    string error;
    const string target = log_path.empty() ? "pcs-client.log" : log_path;
    if (!pcs::daemonize(target, pid_path, error)) {
        cout << error << "\n";
        return false;
    }
    return true;
}

bool command_needs_account(const string& command) {
    return command == "upload" || command == "download" || command == "list" ||
           command == "delete" || command == "sync" || command == "autosync" ||
           command == "watch";
}

}  // namespace

int main(int argc, char* argv[]) {
    pcs::client::Options options;
    options.work_dir = fs::current_path();

    vector<string> positional;
    bool wants_help = false;
    bool wants_version = false;
    string output_path, config_path, profile, log_path, pid_path;
    bool detach = false;
    if (!parse_arguments(argc, argv, options, positional, wants_help,
                         wants_version, output_path, config_path, profile,
                         detach, log_path, pid_path))
        return 1;

    if (wants_version) {
        cout << "pcs-client " << pcs::config::kVersion << " (protocol "
             << pcs::config::kProtocol << ")\n";
        return 0;
    }

    if (wants_help || positional.empty()) {
        print_usage();
        return positional.empty() && !wants_help ? 1 : 0;
    }

    // seal and open touch no server, so they need neither an account nor a
    // certificate to verify.
    const string first = positional[0];
    const bool is_local = first == "seal" || first == "open";
    if (is_local) options.trust.verify = false;

    if (options.trust.ca_file.empty()) {
        if (const char* from_env = getenv("PCS_CACERT"))
            options.trust.ca_file = from_env;
    }

    pcs::Settings settings;
    {
        string settings_error;
        if (!pcs::Settings::load(config_path, profile, settings,
                                 settings_error)) {
            cout << settings_error << "\n";
            return 1;
        }
    }

    // The file fills gaps only; anything already set from the command line
    // or the environment stays as it is.
    auto fill = [](string& target, const string& value) {
        if (target.empty() && !value.empty()) target = value;
    };
    fill(options.credentials.user, settings.get("user"));
    fill(options.credentials.password, settings.get("password"));
    fill(options.credentials.token, settings.get("token"));
    fill(options.trust.ca_file, settings.get("cacert"));
    fill(options.key.keyfile, settings.get("keyfile"));

    const string settings_server = settings.get("server");
    const vector<string> settings_peers = settings.get_list("peers");

    if (const string dir = settings.get("dir"); !dir.empty() &&
        options.work_dir == fs::current_path()) {
        options.work_dir = dir;
    }

    if (first == "config") {
        if (!settings.loaded()) {
            cout << "No settings file found. Looked in:\n";
            for (const fs::path& candidate : pcs::Settings::search_paths())
                cout << "  " << candidate.string() << "\n";
            return 0;
        }
        cout << "Settings file: " << settings.path().string() << "\n"
             << "Profile:       " << settings.profile() << "\n"
             << "server         " << (settings_server.empty() ? "(unset)"
                                                              : settings_server)
             << "\n"
             << "user           " << (options.credentials.user.empty()
                                          ? "(unset)"
                                          : options.credentials.user)
             << "\n"
             << "cacert         " << (options.trust.ca_file.empty()
                                          ? "(unset)"
                                          : options.trust.ca_file)
             << "\n"
             << "peers          " << settings_peers.size() << " configured\n"
             << "token          " << (options.credentials.token.empty()
                                          ? "(unset)" : "(set)")
             << "\n"
             << "password       " << (options.credentials.password.empty()
                                          ? "(unset)" : "(set)")
             << "\n"
             << "watch          " << (settings.get("watch").empty()
                                          ? "(unset)" : settings.get("watch"))
             << "\n";
        return 0;
    }
    if (!is_local && options.trust.verify && options.trust.ca_file.empty()) {
        cout << "No CA certificate given, so the server cannot be verified.\n"
             << "Copy ca.crt from the server and pass --cacert <path>, or"
             << " set PCS_CACERT. Use --insecure only if you accept that"
             << " anyone on the network could impersonate the server.\n";
        return 1;
    }
    if (!is_local && !options.trust.verify) {
        cout << "Warning: --insecure, the server is not being verified." << endl;
    }

    if (options.credentials.token.empty()) {
        if (const char* from_env = getenv("PCS_TOKEN"))
            options.credentials.token = from_env;
    }
    if (options.credentials.user.empty()) {
        if (const char* from_env = getenv("PCS_USER"))
            options.credentials.user = from_env;
    }
    if (options.credentials.password.empty()) {
        if (const char* from_env = getenv("PCS_PASSWORD"))
            options.credentials.password = from_env;
    }

    // Only ask for a password when the command will actually log in, and
    // only when nothing else supplied one.
    const bool needs_account = command_needs_account(first);
    if (needs_account && !options.credentials.user.empty() &&
        options.credentials.password.empty()) {
        if (!pcs::read_hidden_line("Password for " + options.credentials.user +
                                       ": ",
                                   options.credentials.password)) {
            cout << "No password entered." << endl;
            return 1;
        }
    }

    pcs::net_startup();

    const string command = positional[0];
    if (command == "upload") {
        if (positional.size() < 2) {
            cout << "Usage: pcs-client upload <file> [server] "
                    "[peer1 peer2 peer3 peer4]\n";
            return 1;
        }
        options.server = pick_server(options.server, positional, 2,
                                    settings_server);
        if (positional.size() > 3)
            options.peers.assign(positional.begin() + 3, positional.end());
        else
            options.peers = settings_peers;
        if (!require_server(options.server)) return 1;
        return pcs::client::cmd_upload(options, positional[1]);
    }

    if (command == "download") {
        if (positional.size() < 2) {
            cout << "Usage: pcs-client download <name> [server] "
                    "[--out <path>]\n";
            return 1;
        }
        options.server = pick_server(options.server, positional, 2,
                                    settings_server);
        if (!require_server(options.server)) return 1;

        const fs::path destination = output_path.empty()
                                         ? fs::path(positional[1])
                                         : fs::path(output_path);
        return pcs::client::cmd_download(options, positional[1], destination);
    }

    if (command == "delete") {
        if (positional.size() < 2) {
            cout << "Usage: pcs-client delete <name> [server]\n";
            return 1;
        }
        options.server = pick_server(options.server, positional, 2,
                                    settings_server);
        if (!require_server(options.server)) return 1;
        return pcs::client::cmd_delete(options, positional[1]);
    }

    if (command == "list") {
        options.server = pick_server(options.server, positional, 1,
                                    settings_server);
        if (!require_server(options.server)) return 1;
        return pcs::client::cmd_list(options);
    }


    if (command == "seal" || command == "open") {
        if (positional.size() < 3) {
            cout << "Usage: pcs-client " << command
                 << " <file> <output>\n";
            return 1;
        }
        return command == "seal"
                   ? pcs::client::cmd_seal(options, positional[1], positional[2])
                   : pcs::client::cmd_open(options, positional[1], positional[2]);
    }

    if (command == "watch") {
        string folder = positional.size() > 1 ? positional[1]
                                              : settings.get("watch");
        uint64_t interval = 30;
        const size_t interval_at = positional.size() > 1 ? 2 : 1;
        if (positional.size() > interval_at &&
            !pcs::proto::parse_size(positional[interval_at], 86400, interval)) {
            cout << "Interval must be a number of seconds.\n";
            return 1;
        }
        if (interval == 0) interval = 1;
        if (options.server.empty()) options.server = settings_server;
        if (!require_server(options.server)) return 1;

        if (detach && !detach_now(log_path, pid_path)) return 1;
        return pcs::client::cmd_watch(options, folder,
                                      static_cast<int>(interval));
    }

    if (command == "sync") return pcs::client::cmd_sync(options);

    if (command == "autosync") {
        uint64_t interval = 30;
        if (positional.size() > 1 &&
            !pcs::proto::parse_size(positional[1], 86400, interval)) {
            cout << "Interval must be a number of seconds.\n";
            return 1;
        }
        if (interval == 0) interval = 1;
        if (detach && !detach_now(log_path, pid_path)) return 1;
        return pcs::client::cmd_autosync(options, static_cast<int>(interval));
    }

    cout << "Unknown command: " << command << "\n\n";
    print_usage();
    return 1;
}
