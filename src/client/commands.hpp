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
int cmd_sync(const Options& options);
int cmd_autosync(const Options& options, int interval_seconds);

}  // namespace client
}  // namespace pcs
