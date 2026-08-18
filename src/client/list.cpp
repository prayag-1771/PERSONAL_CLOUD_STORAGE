#include <iomanip>
#include <iostream>
#include <memory>

#include "commands.hpp"
#include "pcs/progress.hpp"
#include "remote.hpp"

using namespace std;

namespace pcs {
namespace client {

int cmd_list(const Options& opt) {
    string error;
    unique_ptr<Remote> remote = Remote::connect(opt.server, opt.credentials, Access::Files, error);
    if (!remote) {
        cout << "Cannot reach the server: " << error << "\n";
        return 1;
    }

    vector<pair<string, uint64_t>> files;
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
    for (const pair<string, uint64_t>& entry : files)
        widest = max(widest, entry.first.size());

    cout << "Files on " << opt.server << ":\n";
    for (const pair<string, uint64_t>& entry : files) {
        cout << "  " << left << setw(static_cast<int>(widest)) << entry.first
             << "  " << human_size(entry.second) << " sealed\n";
    }
    cout << files.size() << " file(s).\n";
    return 0;
}

}  // namespace client
}  // namespace pcs
