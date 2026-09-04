#pragma once

#include <filesystem>
#include <string>

#include "workspace.hpp"

// The five things the client can be asked to do. Each returns a process exit
// code and prints its own diagnostics.
namespace pcs {
namespace client {

int cmd_upload(const Options& options, const std::string& file);
int cmd_download(const Options& options, const std::string& name,
                 const std::filesystem::path& destination);
int cmd_list(const Options& options);
int cmd_delete(const Options& options, const std::string& name);
int cmd_sync(const Options& options);
int cmd_autosync(const Options& options, int interval_seconds);

// Watches a folder and uploads whatever appears or changes, forwarding any
// pending files in the same loop.
int cmd_watch(const Options& options, const std::string& folder,
              int interval_seconds);

// Local sealing, with no server involved. Useful on its own for putting an
// encrypted copy on a USB stick, and it is what makes the container format
// testable against another implementation.
int cmd_seal(const Options& options, const std::string& input,
             const std::string& output);
int cmd_open(const Options& options, const std::string& input,
             const std::string& output);

}  // namespace client
}  // namespace pcs
