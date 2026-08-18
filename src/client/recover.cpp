#include "recover.hpp"

#include <array>
#include <iostream>
#include <memory>

#include "pcs/config.hpp"
#include "pcs/digest.hpp"
#include "pcs/erasure.hpp"
#include "pcs/shardfile.hpp"
#include "remote.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace client {

bool rebuild_stream(const Options& opt, const Manifest& manifest,
                    const Workspace& workspace, const fs::path& out_stream,
                    bool verbose, string& error) {
    array<TempFile, 4> holders = {
        workspace.temp("recover0"), workspace.temp("recover1"),
        workspace.temp("recover2"), workspace.temp("recover3")};

    // An empty path marks a shard as unavailable to the joiner.
    array<fs::path, 4> usable;
    int recovered = 0;

    for (const ShardRef& ref : manifest.shards) {
        if (ref.index < 0 || ref.index >= config::kTotalShards) continue;

        const char* label = shard_name(static_cast<Shard>(ref.index));
        string peer_error;

        unique_ptr<Remote> peer = Remote::connect(ref.peer, opt, Access::Chunks, peer_error);
        if (!peer) {
            if (verbose)
                cout << "  " << label << " from " << ref.peer
                     << ": unreachable\n";
            continue;
        }

        bool found = false;
        const fs::path destination = holders[ref.index].path();
        if (!peer->get_chunk(ref.chunk_id, destination, found, peer_error) ||
            !found) {
            if (verbose)
                cout << "  " << label << " from " << ref.peer
                     << ": missing\n";
            continue;
        }
        peer->quit();

        if (sha256_file_hex(destination) != ref.chunk_id) {
            if (verbose)
                cout << "  " << label << " from " << ref.peer
                     << ": integrity check failed, discarded\n";
            continue;
        }

        usable[ref.index] = destination;
        recovered++;
        if (verbose)
            cout << "  " << label << " from " << ref.peer << ": verified\n";
    }

    if (recovered < config::kDataShards) {
        error = "only " + to_string(recovered) + " verified shard(s); " +
                to_string(config::kDataShards) + " are needed";
        return false;
    }

    return join_shards(usable, manifest.shard_size, manifest.stream_size,
                       out_stream, error);
}

void release_shards(const Options& opt, const Manifest& manifest,
                    bool verbose) {
    for (const ShardRef& ref : manifest.shards) {
        string error;
        unique_ptr<Remote> peer = Remote::connect(ref.peer, opt, Access::Chunks, error);
        if (!peer) {
            if (verbose)
                cout << "  could not reach " << ref.peer
                     << " to clean up its shard\n";
            continue;
        }
        if (!peer->del_chunk(ref.chunk_id, error) && verbose)
            cout << "  " << ref.peer << " refused the cleanup: " << error << "\n";
        peer->quit();
    }
}

}  // namespace client
}  // namespace pcs
