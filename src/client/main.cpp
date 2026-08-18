#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "commands.hpp"
#include "pcs/config.hpp"
#include "pcs/keysource.hpp"
#include "pcs/protocol.hpp"
#include "pcs/wire.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace {

void print_usage() {
    cout
        << "Usage: pcs-client [options] <command> [arguments]\n"
        << "\n"
        << "Commands:\n"
        << "  upload <file> <server> [peer1 peer2 peer3 peer4]\n"
        << "        Encrypt and store a file. Goes straight to the server\n"
        << "        when it is up; otherwise the four peers hold the pieces.\n"
        << "  download <name> <server> [output-path]\n"
        << "        Fetch and decrypt a file, from the server or from peers.\n"
        << "  seal <file> <output>\n"
        << "        Encrypt a file locally, without a server.\n"
        << "  open <file> <output>\n"
        << "        Decrypt a file that was sealed locally.\n"
        << "  list <server>\n"
        << "        Show what the server is holding.\n"
        << "  sync\n"
        << "        Forward pending files now that the server is reachable.\n"
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
        << "  --dir <path>      where pending files are tracked (default: .)\n"
        << "  --quiet           no progress bars\n"
        << "  -h, --help        this message\n"
        << "\n"
        << "Files are encrypted before they leave this machine. The server\n"
        << "never receives the passphrase or the key, and stores ciphertext\n"
        << "only. Keep the passphrase safe: without it the data is gone.\n";
}

// Pulls the known flags out of argv and leaves the positional arguments in
// order, so options may appear before or after the command.
bool parse_arguments(int argc, char* argv[], pcs::client::Options& options,
                     vector<string>& positional, bool& wants_help) {
    for (int i = 1; i < argc; i++) {
        const string arg = argv[i];

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
        } else if (arg == "--dir" && i + 1 < argc) {
            options.work_dir = argv[++i];
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
bool command_needs_account(const string& command) {
    return command == "upload" || command == "download" || command == "list" ||
           command == "sync" || command == "autosync";
}

}  // namespace

int main(int argc, char* argv[]) {
    pcs::client::Options options;
    options.work_dir = fs::current_path();

    vector<string> positional;
    bool wants_help = false;
    if (!parse_arguments(argc, argv, options, positional, wants_help)) return 1;

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
        if (positional.size() < 3) {
            cout << "Usage: pcs-client upload <file> <server> "
                    "[peer1 peer2 peer3 peer4]\n";
            return 1;
        }
        options.server = positional[2];
        options.peers.assign(positional.begin() + 3, positional.end());
        return pcs::client::cmd_upload(options, positional[1]);
    }

    if (command == "download") {
        if (positional.size() < 3) {
            cout << "Usage: pcs-client download <name> <server> "
                    "[output-path]\n";
            return 1;
        }
        options.server = positional[2];
        const fs::path destination =
            positional.size() > 3 ? fs::path(positional[3])
                                  : fs::path(positional[1]);
        return pcs::client::cmd_download(options, positional[1], destination);
    }

    if (command == "list") {
        if (positional.size() < 2) {
            cout << "Usage: pcs-client list <server>\n";
            return 1;
        }
        options.server = positional[1];
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

    if (command == "sync") return pcs::client::cmd_sync(options);

    if (command == "autosync") {
        uint64_t interval = 30;
        if (positional.size() > 1 &&
            !pcs::proto::parse_size(positional[1], 86400, interval)) {
            cout << "Interval must be a number of seconds.\n";
            return 1;
        }
        if (interval == 0) interval = 1;
        return pcs::client::cmd_autosync(options, static_cast<int>(interval));
    }

    cout << "Unknown command: " << command << "\n\n";
    print_usage();
    return 1;
}
