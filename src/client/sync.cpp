#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <thread>

#include "commands.hpp"
#include "pcs/manifest.hpp"
#include "pcs/progress.hpp"
#include "recover.hpp"
#include "remote.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace client {
namespace {

atomic<bool> g_stop_requested{false};

void request_stop(int) { g_stop_requested = true; }

struct SyncResult {
    int synced = 0;
    int waiting = 0;
    int failed = 0;
};

// Forwards one pending file to its server.
//
// This needs no passphrase. The shards already hold a sealed stream, and the
// server stores sealed streams, so syncing is a pure ciphertext relay: fetch
// the pieces, put them back together, hand the result over. Nothing along
// the way has to be decrypted, which is what lets the daemon run unattended.
bool sync_one(const Options& opt, const Workspace& workspace,
              const fs::path& manifest_path, bool verbose, string& error) {
    Manifest manifest;
    if (!Manifest::read(manifest_path, manifest, error)) return false;

    Options routed = opt;
    routed.server = manifest.server;

    TempFile stream = workspace.temp("stream");
    if (!rebuild_stream(routed, manifest, workspace, stream.path(), verbose,
                        error))
        return false;

    unique_ptr<Remote> remote =
        Remote::connect(manifest.server, opt.token, error);
    if (!remote) return false;

    uint64_t existing_size = 0;
    string existing_tag;
    bool exists = false;
    const bool already_there =
        remote->stat(manifest.name, existing_size, existing_tag, exists,
                     error) &&
        exists && !manifest.dedup_tag.empty() &&
        existing_tag == manifest.dedup_tag;

    if (already_there) {
        if (verbose)
            cout << "  the server already holds identical content\n";
    } else {
        ProgressBar bar("forwarding", !opt.quiet && verbose);
        const bool ok = remote->put_file(
            manifest.name, stream.path(), manifest.dedup_tag,
            [&bar](uint64_t done, uint64_t total) { bar.update(done, total); },
            error);
        bar.finish();
        if (!ok) return false;
    }
    remote->quit();

    release_shards(routed, manifest, verbose);

    error_code ec;
    fs::remove(manifest_path, ec);
    return true;
}

SyncResult sync_once(const Options& opt, const Workspace& workspace,
                     bool verbose) {
    SyncResult result;

    for (const fs::path& manifest_path : workspace.manifests()) {
        if (g_stop_requested) break;

        string server;
        if (!peek_manifest_server(manifest_path, server)) {
            if (verbose)
                cout << manifest_path.filename().string()
                     << ": unreadable, skipping\n";
            result.failed++;
            continue;
        }

        const string label =
            manifest_path.stem().string();  // the original file name

        // Cheap probe first: no point rebuilding a file we cannot deliver.
        if (!Remote::reachable(server)) {
            if (verbose)
                cout << label << ": " << server << " still offline\n";
            result.waiting++;
            continue;
        }

        if (verbose) cout << label << ": " << server << " is back, forwarding\n";

        string error;
        if (sync_one(opt, workspace, manifest_path, verbose, error)) {
            cout << label << ": synced to " << server << "\n";
            result.synced++;
        } else {
            cout << label << ": failed - " << error << "\n";
            result.failed++;
        }
    }

    return result;
}

}  // namespace

int cmd_sync(const Options& opt) {
    string error;
    Workspace workspace(opt.work_dir);
    if (!workspace.init(error)) {
        cout << error << "\n";
        return 1;
    }

    if (workspace.manifests().empty()) {
        cout << "Nothing is pending.\n";
        return 0;
    }

    const SyncResult result = sync_once(opt, workspace, true);

    cout << result.synced << " synced, " << result.waiting << " still waiting, "
         << result.failed << " failed.\n";
    return result.failed > 0 ? 1 : 0;
}

int cmd_autosync(const Options& opt, int interval_seconds) {
    string error;
    Workspace workspace(opt.work_dir);
    if (!workspace.init(error)) {
        cout << error << "\n";
        return 1;
    }

    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);

    cout << "Auto-sync running, checking every " << interval_seconds
         << "s. Press Ctrl-C to stop.\n"
         << "No passphrase is needed: pending files are relayed without being "
            "decrypted.\n";

    int total = 0;
    while (!g_stop_requested) {
        // Quiet on an ordinary pass; sync_once still reports what it moved.
        const SyncResult result = sync_once(opt, workspace, false);
        total += result.synced;

        if (g_stop_requested) break;

        // Wake often enough to notice the stop flag promptly rather than
        // sleeping through the whole interval.
        for (int slept = 0; slept < interval_seconds && !g_stop_requested;
             slept++) {
            this_thread::sleep_for(chrono::seconds(1));
        }
    }

    cout << "\nAuto-sync stopped. " << total << " file(s) synced.\n";
    return 0;
}

}  // namespace client
}  // namespace pcs
