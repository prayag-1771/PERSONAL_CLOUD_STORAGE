#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "pcs/keysource.hpp"
#include "pcs/wire.hpp"

namespace pcs {
namespace client {

// Who the client is. The two halves are independent: the account identifies
// a person and scopes their files, while the machine token is what peers in
// the group present to each other in order to exchange shards.
struct Credentials {
    std::string user;
    std::string password;
    std::string token;
};

// Everything a command needs that came from the command line.
struct Options {
    Credentials credentials;
    TlsTrust trust;
    std::string server;
    std::vector<std::string> peers;
    KeyOptions key;
    std::filesystem::path work_dir;
    bool quiet = false;
};

// A scratch file that deletes itself unless it is explicitly kept. Sealing
// and shard splitting both produce large intermediates, and leaving those
// behind on an error would quietly fill the disk.
class TempFile {
public:
    TempFile() = default;
    explicit TempFile(std::filesystem::path path);
    ~TempFile();

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
    TempFile(TempFile&& other) noexcept;
    TempFile& operator=(TempFile&& other) noexcept;

    const std::filesystem::path& path() const { return path_; }
    void keep() { keep_ = true; }

private:
    std::filesystem::path path_;
    bool keep_ = false;
};

// Client-side layout, rooted at the working directory:
//
//   pending/            one manifest per file waiting to reach the server
//   pending/.work/      transient sealed streams and shards
class Workspace {
public:
    explicit Workspace(std::filesystem::path root);

    bool init(std::string& error);

    std::filesystem::path pending_dir() const { return pending_; }
    std::filesystem::path manifest_path(const std::string& name) const;
    std::vector<std::filesystem::path> manifests() const;

    TempFile temp(const std::string& suffix) const;

private:
    std::filesystem::path root_;
    std::filesystem::path pending_;
    std::filesystem::path work_;
};

// Extension used for manifests, kept in one place so the sync scan and the
// upload writer cannot disagree.
inline constexpr char kManifestExt[] = ".manifest";

}  // namespace client
}  // namespace pcs
