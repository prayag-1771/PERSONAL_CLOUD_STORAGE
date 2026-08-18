#include <array>
#include <iostream>

#include "commands.hpp"
#include "pcs/config.hpp"
#include "pcs/digest.hpp"
#include "pcs/erasure.hpp"
#include "pcs/keysource.hpp"
#include "pcs/manifest.hpp"
#include "pcs/progress.hpp"
#include "pcs/safename.hpp"
#include "pcs/shardfile.hpp"
#include "pcs/stream.hpp"
#include "remote.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace client {
namespace {

ProgressFn make_progress(ProgressBar& bar) {
    return [&bar](uint64_t done, uint64_t total) { bar.update(done, total); };
}

// Sends the sealed stream straight to the server, skipping the transfer when
// the server already holds identical content.
int upload_to_server(const Options& opt, const string& name,
                     const fs::path& stream_path, const string& dedup_tag) {
    string error;
    unique_ptr<Remote> remote = Remote::connect(opt.server, opt.credentials, Access::Files, error);
    if (!remote) {
        cout << "Cannot reach the server: " << error << "\n";
        return 1;
    }

    uint64_t existing_size = 0;
    string existing_tag;
    bool exists = false;
    if (remote->stat(name, existing_size, existing_tag, exists, error) &&
        exists && !dedup_tag.empty() && existing_tag == dedup_tag) {
        cout << "Server already holds identical content. Nothing to upload.\n";
        remote->quit();
        return 0;
    }

    ProgressBar bar("uploading", !opt.quiet);
    if (!remote->put_file(name, stream_path, dedup_tag, make_progress(bar),
                          error)) {
        bar.finish();
        cout << "Upload failed: " << error << "\n";
        return 1;
    }
    bar.finish();
    remote->quit();

    cout << "Stored '" << name << "' on the server (encrypted).\n";
    return 0;
}

// Splits the sealed stream across four peers and records where the pieces
// went, so the file can be rebuilt and forwarded once the server returns.
int distribute_to_peers(const Options& opt, const Workspace& workspace,
                        const string& name, const fs::path& stream_path,
                        const string& dedup_tag) {
    if (static_cast<int>(opt.peers.size()) != config::kTotalShards) {
        cout << "The server is offline, so the file has to go to peers.\n"
             << "Give exactly " << config::kTotalShards
             << " peer addresses to fall back on.\n";
        return 1;
    }

    array<TempFile, 4> shard_files = {
        workspace.temp("shard0"), workspace.temp("shard1"),
        workspace.temp("shard2"), workspace.temp("shard3")};

    array<fs::path, 4> shard_paths;
    for (int i = 0; i < config::kTotalShards; i++)
        shard_paths[i] = shard_files[i].path();

    uint64_t shard_size = 0;
    string error;
    if (!split_stream(stream_path, shard_paths, shard_size, error)) {
        cout << "Cannot split the file into shards: " << error << "\n";
        return 1;
    }

    error_code ec;
    Manifest manifest;
    manifest.server = opt.server;
    manifest.name = name;
    manifest.stream_size = static_cast<uint64_t>(fs::file_size(stream_path, ec));
    manifest.shard_size = shard_size;
    manifest.dedup_tag = dedup_tag;
    manifest.data_shards = config::kDataShards;
    manifest.parity_shards = config::kParityShards;

    int placed = 0;
    for (int i = 0; i < config::kTotalShards; i++) {
        const string chunk_id = sha256_file_hex(shard_paths[i]);
        if (chunk_id.empty()) {
            cout << "Cannot hash shard " << i << "\n";
            return 1;
        }

        unique_ptr<Remote> peer =
            Remote::connect(opt.peers[i], opt.credentials, Access::Chunks, error);
        if (!peer) {
            cout << "  " << shard_name(static_cast<Shard>(i)) << " -> "
                 << opt.peers[i] << " unavailable (" << error << ")\n";
            continue;
        }

        if (!peer->put_chunk(chunk_id, shard_paths[i], error)) {
            cout << "  " << shard_name(static_cast<Shard>(i)) << " -> "
                 << opt.peers[i] << " failed (" << error << ")\n";
            continue;
        }
        peer->quit();

        ShardRef ref;
        ref.index = i;
        ref.chunk_id = chunk_id;
        ref.peer = opt.peers[i];
        manifest.shards.push_back(ref);
        placed++;

        cout << "  " << shard_name(static_cast<Shard>(i)) << " -> "
             << opt.peers[i] << " ok\n";
    }

    // Two shards is the recovery threshold, so anything less means the file
    // is not actually safe and the manifest would be a false promise.
    if (placed < config::kDataShards) {
        cout << "Only " << placed << " shard(s) were accepted; at least "
             << config::kDataShards << " are needed to rebuild the file.\n"
             << "Nothing was recorded as pending.\n";
        return 1;
    }

    const fs::path manifest_path = workspace.manifest_path(name);
    if (manifest_path.empty() || !manifest.write(manifest_path, error)) {
        cout << "Cannot record the pending file: " << error << "\n";
        return 1;
    }

    cout << placed << " of " << config::kTotalShards
         << " shards distributed. Run 'sync' (or leave 'autosync' running) "
            "to forward the file once the server is back.\n";
    return 0;
}

}  // namespace

int cmd_upload(const Options& opt, const string& file) {
    const fs::path source = file;
    error_code ec;
    if (!fs::exists(source, ec) || !fs::is_regular_file(source, ec)) {
        cout << "Not a readable file: " << file << "\n";
        return 1;
    }

    const string name = source.filename().string();
    if (!is_safe_name(name)) {
        cout << "That file name cannot be stored: " << name << "\n"
             << "Names may not start with a dot or contain path separators.\n";
        return 1;
    }

    string passphrase, error;
    if (!confirm_passphrase(opt.key, passphrase, error)) {
        cout << error << "\n";
        return 1;
    }

    Workspace workspace(opt.work_dir);
    if (!workspace.init(error)) {
        cout << error << "\n";
        return 1;
    }

    // Sealing happens once, before we know which path the upload will take,
    // because both paths send the same ciphertext.
    TempFile stream = workspace.temp("stream");
    string dedup_tag;
    {
        ProgressBar bar("encrypting", !opt.quiet);
        if (!seal_file(source, stream.path(), passphrase, &dedup_tag,
                       make_progress(bar), error)) {
            bar.finish();
            cout << "Encryption failed: " << error << "\n";
            return 1;
        }
        bar.finish();
    }

    if (Remote::reachable(opt.server))
        return upload_to_server(opt, name, stream.path(), dedup_tag);

    cout << "Server " << opt.server << " is offline. Falling back to peers.\n";
    return distribute_to_peers(opt, workspace, name, stream.path(), dedup_tag);
}

}  // namespace client
}  // namespace pcs
