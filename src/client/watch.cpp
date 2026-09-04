#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <map>
#include <thread>

#include "commands.hpp"
#include "internal.hpp"
#include "pcs/keysource.hpp"
#include "pcs/protocol.hpp"
#include "pcs/safename.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace client {
namespace {

atomic<bool> g_stop{false};

void request_stop(int) { g_stop = true; }

constexpr char kStateMagic[] = "pcs-watch";
constexpr int kStateVersion = 1;

// What was last uploaded for a given name. Size and modification time
// together are enough to notice an edit without re-reading the file, which
// matters when the folder holds thousands of photos.
struct Seen {
    uint64_t size = 0;
    int64_t modified = 0;
};

class WatchState {
public:
    bool load(const fs::path& path) {
        entries_.clear();

        ifstream in(path);
        if (!in) return true;  // no state yet is normal

        string line;
        if (!getline(in, line)) return true;
        const vector<string> head = proto::split(line);
        if (head.size() != 2 || head[0] != kStateMagic) return false;
        if (head[1] != to_string(kStateVersion)) return false;

        while (getline(in, line)) {
            // "file <size> <modified> <name>": the name comes last so a
            // space in it cannot be mistaken for a field separator.
            const vector<string> f = proto::split(line);
            if (f.size() < 4 || f[0] != "file") continue;

            uint64_t size = 0;
            if (!proto::parse_size(f[1], UINT64_MAX / 2, size)) continue;

            const size_t name_at = line.find(f[2]) + f[2].size() + 1;
            if (name_at >= line.size()) continue;

            Seen seen;
            seen.size = size;
            seen.modified = strtoll(f[2].c_str(), nullptr, 10);
            entries_[line.substr(name_at)] = seen;
        }
        return true;
    }

    bool save(const fs::path& path) const {
        ofstream out(path, ios::trunc);
        if (!out) return false;

        out << kStateMagic << " " << kStateVersion << "\n";
        for (const pair<const string, Seen>& entry : entries_) {
            out << "file " << entry.second.size << " " << entry.second.modified
                << " " << entry.first << "\n";
        }
        out.flush();
        return static_cast<bool>(out);
    }

    bool unchanged(const string& name, const Seen& now) const {
        const map<string, Seen>::const_iterator it = entries_.find(name);
        if (it == entries_.end()) return false;
        return it->second.size == now.size && it->second.modified == now.modified;
    }

    void record(const string& name, const Seen& now) { entries_[name] = now; }
    void forget(const string& name) { entries_.erase(name); }

private:
    map<string, Seen> entries_;
};

int64_t modified_time(const fs::directory_entry& entry) {
    error_code ec;
    const fs::file_time_type when = entry.last_write_time(ec);
    if (ec) return 0;
    return static_cast<int64_t>(when.time_since_epoch().count());
}

}  // namespace

int cmd_watch(const Options& opt, const string& folder, int interval_seconds) {
    if (folder.empty()) {
        cout << "No folder to watch. Give one on the command line, or put\n"
             << "  watch = /path/to/folder\n"
             << "in your settings file.\n";
        return 1;
    }

    error_code ec;
    if (!fs::is_directory(folder, ec)) {
        cout << "Not a folder: " << folder << "\n";
        return 1;
    }

    string passphrase, error;
    // Asked once, up front. A watcher that stopped to prompt would defeat
    // the point of it running unattended.
    if (!resolve_passphrase(opt.key, "Encryption passphrase: ", passphrase,
                            error)) {
        cout << error << "\n";
        return 1;
    }

    Workspace workspace(opt.work_dir);
    if (!workspace.init(error)) {
        cout << error << "\n";
        return 1;
    }

    const fs::path state_path = workspace.pending_dir() / ".watch-state";
    WatchState state;
    if (!state.load(state_path)) {
        cout << "Cannot read " << state_path.string()
             << ". Delete it to start again.\n";
        return 1;
    }

    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);

    cout << "Watching " << folder << " every " << interval_seconds
         << "s. Press Ctrl-C to stop.\n";

    int uploaded = 0;
    while (!g_stop) {
        bool state_changed = false;

        for (const fs::directory_entry& entry :
             fs::directory_iterator(folder, ec)) {
            if (g_stop) break;
            if (!entry.is_regular_file(ec)) continue;

            const string name = entry.path().filename().string();
            if (!is_safe_name(name)) continue;  // dotfiles and the like

            Seen now;
            now.size = static_cast<uint64_t>(entry.file_size(ec));
            now.modified = modified_time(entry);
            if (ec) continue;

            if (state.unchanged(name, now)) continue;

            cout << name << ": uploading\n";
            if (upload_with_passphrase(opt, workspace, entry.path().string(),
                                       passphrase, false) == 0) {
                state.record(name, now);
                state_changed = true;
                uploaded++;
                cout << name << ": stored\n";
            } else {
                // Left out of the state so the next pass tries again.
                cout << name << ": failed, will retry\n";
            }
        }

        if (state_changed && !state.save(state_path))
            cout << "Warning: cannot write " << state_path.string() << "\n";

        // Anything that went to peers while the server was down is forwarded
        // in the same loop, so one process covers both jobs.
        sync_pass(opt, workspace, false);

        for (int slept = 0; slept < interval_seconds && !g_stop; slept++)
            this_thread::sleep_for(chrono::seconds(1));
    }

    cout << "\nStopped. " << uploaded << " file(s) uploaded this run.\n";
    return 0;
}

}  // namespace client
}  // namespace pcs
