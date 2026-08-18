#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace pcs {
namespace server {

// Owns the on-disk layout and every path that is derived from a name coming
// off the network. Nothing outside this class turns a client-supplied string
// into a filesystem path.
//
//   <root>/files    sealed streams, one per stored file
//   <root>/meta     one sidecar per file holding its deduplication tag
//   <root>/chunks   erasure shards held on behalf of other clients
//   <root>/tmp      partial uploads, renamed into place once complete
class Store {
public:
    explicit Store(std::filesystem::path root);

    bool init(std::string& error);

    // Return an empty path when the name is not a safe single component.
    std::filesystem::path file_path(const std::string& name) const;
    std::filesystem::path chunk_path(const std::string& id) const;
    std::filesystem::path temp_path(const std::string& hint) const;

    // Size and dedup tag of a stored file. False when it does not exist.
    bool file_info(const std::string& name, uint64_t& size,
                   std::string& tag) const;

    bool write_tag(const std::string& name, const std::string& tag) const;

    std::vector<std::pair<std::string, uint64_t>> list_files() const;

    // Serialises the rename/delete steps between connection threads.
    std::mutex& mutex() const { return mutex_; }

    const std::filesystem::path& root() const { return root_; }

private:
    std::filesystem::path root_;
    std::filesystem::path files_;
    std::filesystem::path meta_;
    std::filesystem::path chunks_;
    std::filesystem::path tmp_;
    mutable std::mutex mutex_;
};

// Reads the server token, creating one on first run. The token is the only
// thing standing between the network and the stored data, so it is 32 random
// bytes rather than anything memorable.
std::string load_or_create_token(const std::filesystem::path& path);

}  // namespace server
}  // namespace pcs
