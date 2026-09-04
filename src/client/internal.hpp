#pragma once

#include <string>

#include "workspace.hpp"

// Helpers shared between the client commands. Not part of the command
// surface: these exist so the watcher can reuse the upload and sync work
// without going back through argument parsing or prompting for anything.
namespace pcs {
namespace client {

// Seals and stores one file with an already-resolved passphrase. Returns 0
// on success, matching the command exit codes.
int upload_with_passphrase(const Options& options, const Workspace& workspace,
                           const std::string& file,
                           const std::string& passphrase, bool verbose);

// One pass over the pending files. Returns how many were forwarded.
int sync_pass(const Options& options, const Workspace& workspace,
              bool verbose);

}  // namespace client
}  // namespace pcs
