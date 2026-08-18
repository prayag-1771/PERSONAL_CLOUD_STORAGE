#include "store.hpp"

#include <algorithm>
#include <fstream>

#include "pcs/cipher.hpp"
#include "pcs/hex.hpp"
#include "pcs/safename.hpp"
#include "users.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace server {

Store::Store(fs::path root) : root_(move(root)) {
    users_  = root_ / "users";
    chunks_ = root_ / "chunks";
    tmp_    = root_ / "tmp";
}

bool Store::init(string& error) {
    error_code ec;
    for (const fs::path& dir : {root_, users_, chunks_, tmp_}) {
        fs::create_directories(dir, ec);
        if (ec) {
            error = "cannot create " + dir.string() + ": " + ec.message();
            return false;
        }
    }

    // Anything left in tmp is a partial transfer from a previous run.
    for (const fs::directory_entry& entry : fs::directory_iterator(tmp_, ec))
        fs::remove(entry.path(), ec);

    return true;
}

fs::path Store::account_dir(const string& user) const {
    if (!UserStore::is_valid_username(user)) return {};
    return users_ / user;
}

bool Store::ensure_account(const string& user, string& error) const {
    const fs::path base = account_dir(user);
    if (base.empty()) {
        error = "invalid account name";
        return false;
    }

    error_code ec;
    fs::create_directories(base / "files", ec);
    fs::create_directories(base / "meta", ec);
    if (ec) {
        error = "cannot create storage for " + user + ": " + ec.message();
        return false;
    }
    return true;
}

fs::path Store::file_path(const string& user, const string& name) const {
    const fs::path base = account_dir(user);
    if (base.empty() || !is_safe_name(name)) return {};
    return base / "files" / name;
}

fs::path Store::chunk_path(const string& id) const {
    if (!is_safe_chunk_id(id)) return {};
    return chunks_ / id;
}

fs::path Store::temp_path() const {
    // Only random bytes ever reach the filesystem here.
    return tmp_ / (to_hex(random_bytes(16)) + ".part");
}

bool Store::file_info(const string& user, const string& name, uint64_t& size,
                      string& tag) const {
    const fs::path path = file_path(user, name);
    if (path.empty()) return false;

    error_code ec;
    if (!fs::exists(path, ec) || !fs::is_regular_file(path, ec)) return false;
    size = static_cast<uint64_t>(fs::file_size(path, ec));
    if (ec) return false;

    tag.clear();
    ifstream in(account_dir(user) / "meta" / (name + ".tag"));
    if (in) getline(in, tag);
    return true;
}

bool Store::write_tag(const string& user, const string& name,
                      const string& tag) const {
    const fs::path base = account_dir(user);
    if (base.empty() || !is_safe_name(name)) return false;

    ofstream out(base / "meta" / (name + ".tag"), ios::trunc);
    if (!out) return false;
    out << tag << "\n";
    out.flush();
    return static_cast<bool>(out);
}

vector<pair<string, uint64_t>> Store::list_files(const string& user) const {
    vector<pair<string, uint64_t>> out;
    const fs::path base = account_dir(user);
    if (base.empty()) return out;

    error_code ec;
    const fs::path files = base / "files";
    if (!fs::exists(files, ec)) return out;

    for (const fs::directory_entry& entry : fs::directory_iterator(files, ec)) {
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
