#include "pcs/hex.hpp"

namespace pcs {
namespace {

constexpr char kDigits[] = "0123456789abcdef";

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

}  // namespace

std::string to_hex(const uint8_t* data, size_t len) {
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = kDigits[data[i] >> 4];
        out[2 * i + 1] = kDigits[data[i] & 0x0F];
    }
    return out;
}

std::string to_hex(const std::vector<uint8_t>& data) {
    return to_hex(data.data(), data.size());
}

bool from_hex(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;

    std::vector<uint8_t> parsed(hex.size() / 2);
    for (size_t i = 0; i < parsed.size(); i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        parsed[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    out.swap(parsed);
    return true;
}

}  // namespace pcs
