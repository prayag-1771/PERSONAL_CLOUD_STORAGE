#include <iostream>
#include <memory>

#include "commands.hpp"
#include "pcs/keysource.hpp"
#include "pcs/manifest.hpp"
#include "pcs/progress.hpp"
#include "pcs/safename.hpp"
#include "pcs/stream.hpp"
#include "recover.hpp"
#include "remote.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace client {
namespace {

// Turns a sealed stream into the original file. Shared by both retrieval
// paths, because what comes back from the server and what is rebuilt from
// peers are byte-for-byte the same container.
int unseal_to(const Options& opt, const fs::path& stream_path,
              const fs::path& destination) {
    string passphrase, error;
    if (!resolve_passphrase(opt.key, "Passphrase: ", passphrase, error)) {
        cout << error << "\n";
        return 1;
    }

    ProgressBar bar("decrypting", !opt.quiet);
    const bool ok = open_file(
        stream_path, destination, passphrase,
        [&bar](uint64_t done, uint64_t total) { bar.update(done, total); },
        error);
    bar.finish();

    if (!ok) {
        cout << "Could not decrypt: " << error << "\n";
        return 1;
    }

    cout << "Wrote " << destination.string() << "\n";
    return 0;
}

int recover_from_peers(const Options& opt, const Workspace& workspace,
                       const string& name, const fs::path& destination) {
    const fs::path manifest_path = workspace.manifest_path(name);
    error_code ec;
    if (manifest_path.empty() || !fs::exists(manifest_path, ec)) {
        cout << "No pending record for '" << name
             << "', so there is nothing to rebuild from peers.\n";
        return 1;
    }

    Manifest manifest;
    string error;
    if (!Manifest::read(manifest_path, manifest, error)) {
        cout << "Cannot read the pending record: " << error << "\n";
        return 1;
    }

    cout << "Rebuilding '" << name << "' from peers...\n";
    TempFile stream = workspace.temp("stream");
    if (!rebuild_stream(opt, manifest, workspace, stream.path(), true, error)) {
        cout << "Rebuild failed: " << error << "\n";
        return 1;
    }

    return unseal_to(opt, stream.path(), destination);
}

}  // namespace

int cmd_download(const Options& opt, const string& name,
                 const fs::path& destination) {
    if (!is_safe_name(name)) {
        cout << "Not a valid stored name: " << name << "\n";
        return 1;
    }

    string error;
    Workspace workspace(opt.work_dir);
    if (!workspace.init(error)) {
        cout << error << "\n";
        return 1;
    }

    if (!Remote::reachable(opt.server)) {
        cout << "Server " << opt.server << " is offline. Trying peers.\n";
        return recover_from_peers(opt, workspace, name, destination);
    }

    unique_ptr<Remote> remote = Remote::connect(opt.server, opt.token, error);
    if (!remote) {
        cout << "Cannot reach the server: " << error << "\n";
        return 1;
    }

    TempFile stream = workspace.temp("stream");
    bool found = false;
    ProgressBar bar("downloading", !opt.quiet);
    const bool ok = remote->get_file(
        name, stream.path(), found,
        [&bar](uint64_t done, uint64_t total) { bar.update(done, total); },
        error);
    bar.finish();
    remote->quit();

    if (!ok) {
        cout << "Download failed: " << error << "\n";
        return 1;
    }
    if (!found) {
        // The server is up but does not have it; a pending record may still
        // hold the pieces from an earlier offline upload.
        cout << "The server does not have '" << name << "'.\n";
        return recover_from_peers(opt, workspace, name, destination);
    }

    return unseal_to(opt, stream.path(), destination);
}

}  // namespace client
}  // namespace pcs
