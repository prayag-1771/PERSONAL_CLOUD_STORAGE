#include <iomanip>
#include <iostream>
#include <memory>

#include "commands.hpp"
#include "pcs/safename.hpp"
#include "pcs/progress.hpp"
#include "remote.hpp"

using namespace std;

namespace pcs {
namespace client {

int cmd_list(const Options& opt) {
    string error;
    unique_ptr<Remote> remote = Remote::connect(opt.server, opt, Access::Files, error);
    if (!remote) {
        cout << "Cannot reach the server: " << error << "\n";
        return 1;
    }

    vector<Remote::Listed> files;
    if (!remote->list(files, error)) {
        cout << "Listing failed: " << error << "\n";
        return 1;
    }
    remote->quit();

    if (files.empty()) {
        cout << "The server has no files yet.\n";
        return 0;
    }

    size_t widest = 0;
    for (const Remote::Listed& entry : files)
        widest = max(widest, entry.name.size());

    cout << "Files on " << opt.server << ":\n";
    for (const Remote::Listed& entry : files) {
        cout << "  " << left << setw(static_cast<int>(widest)) << entry.name
             << "  " << right << setw(10) << human_size(entry.size)
             << " sealed\n";
    }
    cout << files.size() << " file(s).\n";
    return 0;
}

int cmd_delete(const Options& opt, const string& name) {
    if (!is_safe_name(name)) {
        cout << "Not a valid stored name: " << name << "\n";
        return 1;
    }

    string error;
    unique_ptr<Remote> remote = Remote::connect(opt.server, opt, Access::Files, error);
    if (!remote) {
        cout << "Cannot reach the server: " << error << "\n";
        return 1;
    }

    bool found = false;
    if (!remote->del_file(name, found, error)) {
        cout << "Delete failed: " << error << "\n";
        return 1;
    }
    remote->quit();

    if (!found) {
        cout << "There is no '" << name << "' to delete.\n";
        return 1;
    }

    cout << "Deleted '" << name << "'.\n";
    return 0;
}

}  // namespace client
}  // namespace pcs
