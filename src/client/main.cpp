#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "commands.hpp"
#include "pcs/config.hpp"
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
        << "  list <server>\n"
        << "        Show what the server is holding.\n"
        << "  sync\n"
        << "        Forward pending files now that the server is reachable.\n"
        << "  autosync [seconds]\n"
        << "        Keep watching and forward pending files automatically.\n"
        << "\n"
        << "Options:\n"
        << "  --token <token>   server token (or set PCS_TOKEN)\n"
        << "  --keyfile <path>  read the passphrase from a file instead of\n"
        << "                    prompting (or set PCS_PASSPHRASE)\n"
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
            options.token = argv[++i];
        } else if (arg == "--keyfile" && i + 1 < argc) {
            options.key.keyfile = argv[++i];
        } else if (arg == "--dir" && i + 1 < argc) {
            options.work_dir = argv[++i];
        } else if (arg.rfind("--", 0) == 0) {
            cout << "Unknown option: " << arg << "\n";
            return false;
        } else {
            positional.push_back(arg);
        }
    }
    return true;
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

    if (options.token.empty()) {
        if (const char* from_env = getenv("PCS_TOKEN")) options.token = from_env;
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
