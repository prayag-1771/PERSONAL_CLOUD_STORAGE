#include "workspace.hpp"

#include <algorithm>
#include <utility>

#include "pcs/cipher.hpp"
#include "pcs/hex.hpp"
#include "pcs/safename.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace client {

TempFile::TempFile(fs::path path) : path_(move(path)) {}

TempFile::~TempFile() {
    if (!keep_ && !path_.empty()) {
        error_code ignored;
        fs::remove(path_, ignored);
    }
}

TempFile::TempFile(TempFile&& other) noexcept
    : path_(move(other.path_)), keep_(other.keep_) {
    other.path_.clear();
}

TempFile& TempFile::operator=(TempFile&& other) noexcept {
    if (this != &other) {
        if (!keep_ && !path_.empty()) {
            error_code ignored;
            fs::remove(path_, ignored);
        }
        path_ = move(other.path_);
        keep_ = other.keep_;
        other.path_.clear();
    }
    return *this;
}

Workspace::Workspace(fs::path root) : root_(move(root)) {
    pending_ = root_ / "pending";
    work_ = pending_ / ".work";
}

bool Workspace::init(string& error) {
    error_code ec;
    fs::create_directories(work_, ec);
    if (ec) {
        error = "cannot create " + work_.string() + ": " + ec.message();
        return false;
    }
    return true;
}

fs::path Workspace::manifest_path(const string& name) const {
    if (!is_safe_name(name)) return {};
    return pending_ / (name + kManifestExt);
}

vector<fs::path> Workspace::manifests() const {
    vector<fs::path> out;
    error_code ec;

    if (!fs::exists(pending_, ec)) return out;
    for (const fs::directory_entry& entry : fs::directory_iterator(pending_, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        if (entry.path().extension() == kManifestExt) out.push_back(entry.path());
    }

    sort(out.begin(), out.end());
    return out;
}

TempFile Workspace::temp(const string& suffix) const {
    return TempFile(work_ / (to_hex(random_bytes(12)) + "." + suffix));
}

}  // namespace client
}  // namespace pcs
