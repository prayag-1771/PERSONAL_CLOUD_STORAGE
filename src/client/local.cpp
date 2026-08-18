#include <iostream>

#include "commands.hpp"
#include "pcs/keysource.hpp"
#include "pcs/progress.hpp"
#include "pcs/stream.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace client {

int cmd_seal(const Options& opt, const string& input, const string& output) {
    string passphrase, error;
    if (!confirm_passphrase(opt.key, passphrase, error)) {
        cout << error << "\n";
        return 1;
    }

    ProgressBar bar("encrypting", !opt.quiet);
    string tag;
    const bool ok = seal_file(
        input, output, passphrase, &tag,
        [&bar](uint64_t done, uint64_t total) { bar.update(done, total); },
        error);
    bar.finish();

    if (!ok) {
        cout << "Encryption failed: " << error << "\n";
        return 1;
    }
    cout << "Wrote " << output << "\n";
    return 0;
}

int cmd_open(const Options& opt, const string& input, const string& output) {
    string passphrase, error;
    if (!resolve_passphrase(opt.key, "Passphrase: ", passphrase, error)) {
        cout << error << "\n";
        return 1;
    }

    ProgressBar bar("decrypting", !opt.quiet);
    const bool ok = open_file(
        input, output, passphrase,
        [&bar](uint64_t done, uint64_t total) { bar.update(done, total); },
        error);
    bar.finish();

    if (!ok) {
        cout << "Could not decrypt: " << error << "\n";
        return 1;
    }
    cout << "Wrote " << output << "\n";
    return 0;
}

}  // namespace client
}  // namespace pcs
