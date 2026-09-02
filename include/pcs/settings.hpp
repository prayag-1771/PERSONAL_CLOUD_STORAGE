#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

// A small settings file, so a command is not six arguments long.
//
//   # pcs.conf
//   [default]
//   server  = 192.168.1.10:9000
//   user    = alice
//   token   = 1a2b3c...
//   cacert  = /home/alice/pcs-ca.crt
//   peers   = 192.168.1.11:9000, 192.168.1.12:9000
//   watch   = /home/alice/Pictures
//
//   [work]
//   server  = 10.0.0.5:9000
//
// Anything given on the command line or in the environment still wins; the
// file only fills in what was left out.
namespace pcs {

class Settings {
public:
    // Loads the first file found, selecting `profile` (default: "default").
    // A missing file is not an error: it just means nothing is preset.
    static bool load(const std::string& explicit_path,
                     const std::string& profile, Settings& out,
                     std::string& error);

    // Empty string when the key is not set.
    std::string get(const std::string& key) const;

    // Comma or whitespace separated, for peer lists.
    std::vector<std::string> get_list(const std::string& key) const;

    bool loaded() const { return loaded_; }
    const std::filesystem::path& path() const { return path_; }
    const std::string& profile() const { return profile_; }

    // Where a settings file is looked for, in order.
    static std::vector<std::filesystem::path> search_paths();

private:
    std::map<std::string, std::string> values_;
    std::filesystem::path path_;
    std::string profile_;
    bool loaded_ = false;
};

}  // namespace pcs
