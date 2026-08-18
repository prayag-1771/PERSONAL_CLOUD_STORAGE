#pragma once

#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace pcs {
namespace server {

// The account list, kept as a line-oriented text file next to the data:
//
//   pcs-users 1
//   user <name> <verifier> <created>
//
// Passwords are never stored, only verifiers. The file is rewritten whole on
// every change, which is fine for the handful of accounts a household has.
class UserStore {
public:
    explicit UserStore(std::filesystem::path path);

    bool load(std::string& error);

    bool add(const std::string& name, const std::string& password,
             std::string& error);
    bool remove(const std::string& name, std::string& error);
    bool set_password(const std::string& name, const std::string& password,
                      std::string& error);

    // An unknown user still pays the cost of a full hash comparison, so
    // probing for valid names is not free.
    bool verify(const std::string& name, const std::string& password) const;

    bool exists(const std::string& name) const;
    std::vector<std::string> names() const;
    bool empty() const;

    // A username also becomes a directory name, so it is restricted to
    // something that cannot escape or collide: lowercase letters, digits,
    // hyphen and underscore, starting with a letter.
    static bool is_valid_username(const std::string& name);

private:
    bool load_locked(std::string& error);
    bool save_locked(std::string& error) const;

    // Accounts are added by a separate `pcs-server useradd` run while the
    // server is up, so the in-memory copy has to notice the file changing.
    // Requiring a restart to add a family member would be the wrong
    // behaviour, and forgetting to restart would look like a broken password.
    void reload_if_changed_locked() const;

    std::filesystem::path path_;
    mutable std::map<std::string, std::string> verifiers_;
    mutable std::filesystem::file_time_type loaded_stamp_{};
    mutable std::mutex mutex_;
};

}  // namespace server
}  // namespace pcs
