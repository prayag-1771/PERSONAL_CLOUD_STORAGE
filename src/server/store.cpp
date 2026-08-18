#include "store.hpp"

#include <algorithm>
#include <fstream>

#include "pcs/cipher.hpp"
#include "pcs/hex.hpp"
#include "pcs/safename.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace server {

Store::Store(fs::path root) : root_(move(root)) {
    files_  = root_ / "files";
    meta_   = root_ / "meta";
    chunks_ = root_ / "chunks";
    tmp_    = root_ / "tmp";
}

bool Store::init(string& error) {
    error_code ec;
    for (const fs::path& dir : {root_, files_, meta_, chunks_, tmp_}) {
        fs::create_directories(dir, ec);
        if (ec) {
            error = "cannot create " + dir.string() + ": " + ec.message();
            return false;
        }
    }

    // Anything left in tmp is a partial upload from a previous run.
    for (const fs::directory_entry& entry : fs::directory_iterator(tmp_, ec))
        fs::remove(entry.path(), ec);

    return true;
}

fs::path Store::file_path(const string& name) const {
    if (!is_safe_name(name)) return {};
    return files_ / name;
}

fs::path Store::chunk_path(const string& id) const {
    if (!is_safe_chunk_id(id)) return {};
    return chunks_ / id;
}

fs::path Store::temp_path(const string& hint) const {
    // The hint never reaches the filesystem; only random bytes do.
    (void)hint;
    return tmp_ / (to_hex(random_bytes(16)) + ".part");
}

bool Store::file_info(const string& name, uint64_t& size,
                      string& tag) const {
    const fs::path path = file_path(name);
    if (path.empty()) return false;

    error_code ec;
    if (!fs::exists(path, ec) || !fs::is_regular_file(path, ec)) return false;
    size = static_cast<uint64_t>(fs::file_size(path, ec));
    if (ec) return false;

    tag.clear();
    ifstream in(meta_ / (name + ".tag"));
    if (in) getline(in, tag);
    return true;
}

bool Store::write_tag(const string& name, const string& tag) const {
    if (!is_safe_name(name)) return false;
    ofstream out(meta_ / (name + ".tag"), ios::trunc);
    if (!out) return false;
    out << tag << "\n";
    out.flush();
    return static_cast<bool>(out);
}

vector<pair<string, uint64_t>> Store::list_files() const {
    vector<pair<string, uint64_t>> out;
    error_code ec;

    for (const fs::directory_entry& entry : fs::directory_iterator(files_, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        const string name = entry.path().filename().string();
        if (!is_safe_name(name)) continue;
        out.emplace_back(name, static_cast<uint64_t>(entry.file_size(ec)));
    }

    sort(out.begin(), out.end());
    return out;
}

string load_or_create_token(const fs::path& path) {
    {
        ifstream in(path);
        string existing;
        if (in && getline(in, existing) && existing.size() == 64)
            return existing;
    }

    const string token = to_hex(random_bytes(32));
    ofstream out(path, ios::trunc);
    if (out) {
        out << token << "\n";
        out.flush();
    }
    return token;
}

}  // namespace server
}  // namespace pcs
