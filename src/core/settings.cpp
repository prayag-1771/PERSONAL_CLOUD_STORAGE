#include "pcs/settings.hpp"

#include <cstdlib>
#include <fstream>

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace {

string trim(const string& text) {
    const size_t first = text.find_first_not_of(" \t\r\n");
    if (first == string::npos) return {};
    const size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

string lowercase(string text) {
    for (char& c : text)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return text;
}

fs::path home_directory() {
#ifdef _WIN32
    if (const char* appdata = getenv("APPDATA")) return fs::path(appdata);
    if (const char* profile = getenv("USERPROFILE")) return fs::path(profile);
#else
    if (const char* home = getenv("HOME")) return fs::path(home);
#endif
    return {};
}

}  // namespace

vector<fs::path> Settings::search_paths() {
    vector<fs::path> paths;

    if (const char* from_env = getenv("PCS_CONFIG")) paths.push_back(from_env);

    error_code ec;
    paths.push_back(fs::current_path(ec) / "pcs.conf");

    const fs::path home = home_directory();
    if (!home.empty()) {
#ifdef _WIN32
        paths.push_back(home / "pcs" / "pcs.conf");
#else
        if (const char* xdg = getenv("XDG_CONFIG_HOME"))
            paths.push_back(fs::path(xdg) / "pcs" / "pcs.conf");
        paths.push_back(home / ".config" / "pcs" / "pcs.conf");
        paths.push_back(home / ".pcs.conf");
#endif
    }
    return paths;
}

bool Settings::load(const string& explicit_path, const string& profile,
                    Settings& out, string& error) {
    out = Settings();
    out.profile_ = profile.empty() ? "default" : profile;

    fs::path chosen;
    error_code ec;

    if (!explicit_path.empty()) {
        chosen = explicit_path;
        if (!fs::exists(chosen, ec)) {
            // An explicitly named file that is not there is a mistake worth
            // reporting, unlike simply having no settings file at all.
            error = "no such settings file: " + explicit_path;
            return false;
        }
    } else {
        for (const fs::path& candidate : search_paths()) {
            if (fs::exists(candidate, ec)) {
                chosen = candidate;
                break;
            }
        }
        if (chosen.empty()) return true;  // nothing preset, which is fine
    }

    ifstream in(chosen);
    if (!in) {
        error = "cannot read " + chosen.string();
        return false;
    }

    string section = "default";
    string line;
    int number = 0;

    while (getline(in, line)) {
        number++;
        const string text = trim(line);
        if (text.empty() || text[0] == '#' || text[0] == ';') continue;

        if (text.front() == '[') {
            if (text.back() != ']') {
                error = chosen.string() + ":" + to_string(number) +
                        ": unclosed section header";
                return false;
            }
            section = lowercase(trim(text.substr(1, text.size() - 2)));
            continue;
        }

        const size_t equals = text.find('=');
        if (equals == string::npos) {
            error = chosen.string() + ":" + to_string(number) +
                    ": expected key = value";
            return false;
        }

        // Only the selected profile is kept, so an unrelated section cannot
        // leak a setting into this run.
        if (section != out.profile_) continue;

        const string key = lowercase(trim(text.substr(0, equals)));
        const string value = trim(text.substr(equals + 1));
        if (!key.empty()) out.values_[key] = value;
    }

    out.path_ = chosen;
    out.loaded_ = true;
    return true;
}

string Settings::get(const string& key) const {
    const map<string, string>::const_iterator it = values_.find(lowercase(key));
    return it == values_.end() ? string() : it->second;
}

vector<string> Settings::get_list(const string& key) const {
    vector<string> items;
    const string raw = get(key);

    string current;
    for (char c : raw) {
        if (c == ',' || c == ' ' || c == '\t') {
            if (!current.empty()) items.push_back(current);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) items.push_back(current);
    return items;
}

}  // namespace pcs
