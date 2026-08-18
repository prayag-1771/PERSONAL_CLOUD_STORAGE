#include "pcs/safename.hpp"

#include <cctype>

using namespace std;

namespace pcs {
namespace {

// Spelled numerically rather than as an escape so the value is unambiguous.
constexpr char kBackslash = 92;

}  // namespace

bool is_safe_name(const string& name) {
    if (name.empty() || name.size() > 255) return false;
    if (name == "." || name == "..") return false;
    if (name.front() == '.') return false;   // no dotfiles, no ".." prefixes

    for (unsigned char c : name) {
        if (c < 0x20 || c == 0x7F) return false;      // control characters
        if (c == '/' || c == kBackslash) return false;  // path separators
        if (c == ':' || c == '*' || c == '?') return false;
        if (c == '"' || c == '<' || c == '>' || c == '|') return false;
    }
    return true;
}

bool is_safe_chunk_id(const string& id) {
    if (id.size() != 64) return false;
    for (char c : id) {
        bool digit = c >= '0' && c <= '9';
        bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

}  // namespace pcs
