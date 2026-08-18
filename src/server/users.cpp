#include "users.hpp"

#include <ctime>
#include <fstream>
#include <utility>

#include "pcs/config.hpp"
#include "pcs/passwd.hpp"
#include "pcs/protocol.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace server {
namespace {

constexpr char kMagic[] = "pcs-users";
constexpr int kVersion = 1;

string today() {
    const time_t now = time(nullptr);
    tm parts{};
#ifdef _WIN32
    gmtime_s(&parts, &now);
#else
    gmtime_r(&now, &parts);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d", &parts);
    return string(buf);
}

// A verifier for a password that cannot be supplied, used to keep the cost of
// checking an unknown user the same as checking a real one.
const string& decoy_verifier() {
    static const string decoy = hash_password("", config::kPasswordIterations);
    return decoy;
}

}  // namespace

UserStore::UserStore(fs::path path) : path_(move(path)) {}

bool UserStore::is_valid_username(const string& name) {
    if (name.empty() || name.size() > 32) return false;
    if (name[0] < 'a' || name[0] > 'z') return false;

    for (char c : name) {
        const bool lower = c >= 'a' && c <= 'z';
        const bool digit = c >= '0' && c <= '9';
        if (!lower && !digit && c != '-' && c != '_') return false;
    }
    return true;
}

bool UserStore::load(string& error) {
    lock_guard<mutex> guard(mutex_);
    return load_locked(error);
}

void UserStore::reload_if_changed_locked() const {
    error_code ec;
    const fs::file_time_type stamp = fs::last_write_time(path_, ec);
    if (ec) return;                    // no file yet, nothing to pick up
    if (stamp == loaded_stamp_) return;

    string ignored;
    const_cast<UserStore*>(this)->load_locked(ignored);
}

bool UserStore::load_locked(string& error) {
    verifiers_.clear();

    error_code ec;
    loaded_stamp_ = fs::last_write_time(path_, ec);

    ifstream in(path_);
    if (!in) return true;  // no file yet is not an error, just no accounts

    string line;
    if (!getline(in, line)) return true;

    const vector<string> head = proto::split(line);
    if (head.size() != 2 || head[0] != kMagic) {
        error = "not a user file: " + path_.string();
        return false;
    }
    if (head[1] != to_string(kVersion)) {
        error = "unsupported user file version " + head[1];
        return false;
    }

    while (getline(in, line)) {
        const vector<string> f = proto::split(line);
        if (f.size() < 3 || f[0] != "user") continue;
        if (!is_valid_username(f[1])) continue;
        verifiers_[f[1]] = f[2];
    }
    return true;
}

bool UserStore::save_locked(string& error) const {
    // Written to a sibling file and renamed, so an interrupted save cannot
    // leave the account list truncated.
    const fs::path temp = path_.string() + ".new";

    {
        ofstream out(temp, ios::trunc);
        if (!out) {
            error = "cannot write " + temp.string();
            return false;
        }
        out << kMagic << " " << kVersion << "\n";
        for (const pair<const string, string>& entry : verifiers_)
            out << "user " << entry.first << " " << entry.second << " "
                << today() << "\n";
        out.flush();
        if (!out) {
            error = "write failed for " + temp.string();
            return false;
        }
    }

    error_code ec;
    fs::rename(temp, path_, ec);
    if (ec) {
        fs::remove(temp, ec);
        error = "cannot replace " + path_.string();
        return false;
    }

    // Remember the stamp we just wrote, so our own save is not mistaken for
    // an outside change on the next lookup.
    loaded_stamp_ = fs::last_write_time(path_, ec);
    return true;
}

bool UserStore::add(const string& name, const string& password, string& error) {
    if (!is_valid_username(name)) {
        error = "invalid username (lowercase letters, digits, - and _, "
                "starting with a letter)";
        return false;
    }
    if (password.size() < 8) {
        error = "password must be at least 8 characters";
        return false;
    }

    lock_guard<mutex> guard(mutex_);
    if (verifiers_.count(name) != 0) {
        error = "user already exists: " + name;
        return false;
    }

    const string verifier = hash_password(password, config::kPasswordIterations);
    if (verifier.empty()) {
        error = "could not hash the password";
        return false;
    }

    verifiers_[name] = verifier;
    if (!save_locked(error)) {
        verifiers_.erase(name);   // keep memory and disk consistent
        return false;
    }
    return true;
}

bool UserStore::set_password(const string& name, const string& password,
                             string& error) {
    if (password.size() < 8) {
        error = "password must be at least 8 characters";
        return false;
    }

    lock_guard<mutex> guard(mutex_);
    const map<string, string>::iterator it = verifiers_.find(name);
    if (it == verifiers_.end()) {
        error = "no such user: " + name;
        return false;
    }

    const string previous = it->second;
    it->second = hash_password(password, config::kPasswordIterations);
    if (it->second.empty() || !save_locked(error)) {
        it->second = previous;
        return false;
    }
    return true;
}

bool UserStore::remove(const string& name, string& error) {
    lock_guard<mutex> guard(mutex_);
    const map<string, string>::iterator it = verifiers_.find(name);
    if (it == verifiers_.end()) {
        error = "no such user: " + name;
        return false;
    }

    const string previous = it->second;
    verifiers_.erase(it);
    if (!save_locked(error)) {
        verifiers_[name] = previous;
        return false;
    }
    return true;
}

bool UserStore::verify(const string& name, const string& password) const {
    string verifier;
    {
        lock_guard<mutex> guard(mutex_);
        reload_if_changed_locked();
        const map<string, string>::const_iterator it = verifiers_.find(name);
        if (it != verifiers_.end()) verifier = it->second;
    }

    // Always run a full verification, even for a name that does not exist, so
    // the reply time does not reveal which usernames are real.
    if (verifier.empty()) {
        verify_password(password, decoy_verifier());
        return false;
    }
    return verify_password(password, verifier);
}

bool UserStore::exists(const string& name) const {
    lock_guard<mutex> guard(mutex_);
    reload_if_changed_locked();
    return verifiers_.count(name) != 0;
}

vector<string> UserStore::names() const {
    lock_guard<mutex> guard(mutex_);
    vector<string> out;
    out.reserve(verifiers_.size());
    for (const pair<const string, string>& entry : verifiers_)
        out.push_back(entry.first);
    return out;
}

bool UserStore::empty() const {
    lock_guard<mutex> guard(mutex_);
    return verifiers_.empty();
}

}  // namespace server
}  // namespace pcs
