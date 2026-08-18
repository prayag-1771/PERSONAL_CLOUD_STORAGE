#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace pcs {
namespace server {

// Owns the on-disk layout and every path derived from a name off the network.
// Nothing outside this class turns a client-supplied string into a path.
//
//   <root>/users/<user>/files   sealed streams belonging to that account
//   <root>/users/<user>/meta    one sidecar per file, holding its dedup tag
//   <root>/chunks               erasure shards held for the peer group
//   <root>/tmp                  partial transfers, renamed once complete
//
// Files are namespaced per account so one user cannot name their way into
// another user's storage. Chunks are deliberately shared: they are opaque
// ciphertext addressed by their own hash, and peers hold them for each other.
class Store {
public:
    explicit Store(std::filesystem::path root);

    bool init(std::string& error);

    // Creates the per-account directories on first use.
    bool ensure_account(const std::string& user, std::string& error) const;

    // Return an empty path when the user or name is not a safe component.
    std::filesystem::path file_path(const std::string& user,
                                    const std::string& name) const;
    std::filesystem::path chunk_path(const std::string& id) const;
    std::filesystem::path temp_path() const;

    bool file_info(const std::string& user, const std::string& name,
                   uint64_t& size, std::string& tag) const;

    bool write_tag(const std::string& user, const std::string& name,
                   const std::string& tag) const;

    std::vector<std::pair<std::string, uint64_t>> list_files(
        const std::string& user) const;

    // Serialises the rename and delete steps between connection threads.
    std::mutex& mutex() const { return mutex_; }

    const std::filesystem::path& root() const { return root_; }

private:
    std::filesystem::path account_dir(const std::string& user) const;

    std::filesystem::path root_;
    std::filesystem::path users_;
    std::filesystem::path chunks_;
    std::filesystem::path tmp_;
    mutable std::mutex mutex_;
};

// Reads the shared machine token, creating one on first run. This is what
// lets peers store shards for each other; it is not a user credential.
std::string load_or_create_token(const std::filesystem::path& path);

}  // namespace server
}  // namespace pcs
