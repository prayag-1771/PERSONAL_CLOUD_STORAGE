#include "pcs/passwd.hpp"

#include <vector>

#include "pcs/cipher.hpp"
#include "pcs/config.hpp"
#include "pcs/digest.hpp"
#include "pcs/hex.hpp"
#include "pcs/protocol.hpp"

using namespace std;

namespace pcs {
namespace {

constexpr char kScheme[] = "pbkdf2-sha256";
constexpr size_t kSaltLen = 16;
constexpr size_t kHashLen = 32;

// Splits on the field separator used by the verifier format.
vector<string> split_fields(const string& text) {
    vector<string> fields;
    size_t start = 0;
    while (true) {
        const size_t at = text.find('$', start);
        if (at == string::npos) {
            fields.push_back(text.substr(start));
            return fields;
        }
        fields.push_back(text.substr(start, at - start));
        start = at + 1;
    }
}

struct Parsed {
    uint32_t iterations = 0;
    vector<uint8_t> salt;
    vector<uint8_t> hash;
};

bool parse(const string& verifier, Parsed& out) {
    const vector<string> fields = split_fields(verifier);
    if (fields.size() != 4) return false;
    if (fields[0] != kScheme) return false;

    uint64_t iterations = 0;
    if (!proto::parse_size(fields[1], 100000000, iterations) || iterations == 0)
        return false;

    if (!from_hex(fields[2], out.salt) || out.salt.empty()) return false;
    if (!from_hex(fields[3], out.hash) || out.hash.size() != kHashLen)
        return false;

    out.iterations = static_cast<uint32_t>(iterations);
    return true;
}

vector<uint8_t> stretch(const string& password, const vector<uint8_t>& salt,
                        uint32_t iterations) {
    // Reuses the shared PBKDF2 wrapper, with its own label so a password
    // verifier can never collide with a file encryption key derived from the
    // same secret.
    return derive_key(password, salt, "pcs-password-v1", iterations);
}

}  // namespace

string hash_password(const string& password, uint32_t iterations) {
    if (iterations == 0) iterations = config::kPasswordIterations;

    const vector<uint8_t> salt = random_bytes(kSaltLen);
    if (salt.size() != kSaltLen) return {};

    const vector<uint8_t> hash = stretch(password, salt, iterations);
    if (hash.size() != kHashLen) return {};

    return string(kScheme) + "$" + to_string(iterations) + "$" + to_hex(salt) +
           "$" + to_hex(hash);
}

bool verify_password(const string& password, const string& verifier) {
    Parsed parsed;
    if (!parse(verifier, parsed)) return false;

    const vector<uint8_t> candidate =
        stretch(password, parsed.salt, parsed.iterations);
    if (candidate.size() != parsed.hash.size()) return false;

    // Compared in constant time: a timing signal here would leak how much of
    // a guessed password was right.
    return secure_equal(to_hex(candidate), to_hex(parsed.hash));
}

bool verifier_is_stale(const string& verifier, uint32_t wanted) {
    Parsed parsed;
    if (!parse(verifier, parsed)) return true;
    return parsed.iterations < wanted;
}

}  // namespace pcs
