#include "pcs/protocol.hpp"

#include <cctype>

using namespace std;

namespace pcs {
namespace proto {

vector<string> split(const string& line) {
    vector<string> parts;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && line[i] == ' ') i++;
        size_t start = i;
        while (i < line.size() && line[i] != ' ') i++;
        if (i > start) parts.push_back(line.substr(start, i - start));
    }
    return parts;
}

bool parse_size(const string& text, uint64_t limit, uint64_t& out) {
    if (text.empty() || text.size() > 20) return false;

    uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        uint64_t digit = static_cast<uint64_t>(c - '0');
        // Reject before the multiply overflows rather than after.
        if (value > (limit - digit) / 10) return false;
        value = value * 10 + digit;
        if (value > limit) return false;
    }
    out = value;
    return true;
}

}  // namespace proto
}  // namespace pcs
