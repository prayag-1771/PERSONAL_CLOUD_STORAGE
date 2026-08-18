#pragma once

#include <filesystem>
#include <string>

#include "pcs/manifest.hpp"
#include "workspace.hpp"

namespace pcs {
namespace client {

// Fetches the shards a manifest points at, checks each one against its
// recorded hash and rebuilds the sealed stream. A shard whose hash does not
// match is discarded rather than used, so a corrupted or tampered peer
// cannot poison the result while another good pair is still available.
bool rebuild_stream(const Options& options, const Manifest& manifest,
                    const Workspace& workspace,
                    const std::filesystem::path& out_stream, bool verbose,
                    std::string& error);

// Best-effort removal of the shards from the peers once the file is safely
// back on the server. Failures are reported but not fatal: a leftover chunk
// wastes space, it does not lose data.
void release_shards(const Options& options, const Manifest& manifest,
                    bool verbose);

}  // namespace client
}  // namespace pcs
