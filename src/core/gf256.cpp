#include "pcs/gf256.hpp"

namespace pcs {

uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        bool carry = (a & 0x80) != 0;
        a = static_cast<uint8_t>(a << 1);
        if (carry) a ^= 0x1B;  // reduce by x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return result;
}

uint8_t gf_inv(uint8_t x) {
    if (x == 0) return 0;
    // The multiplicative group has 255 elements, so x^254 is the inverse.
    // Searching 255 candidates is just as correct and stays obvious.
    for (int candidate = 1; candidate < 256; candidate++) {
        if (gf_mul(x, static_cast<uint8_t>(candidate)) == 1)
            return static_cast<uint8_t>(candidate);
    }
    return 0;
}

void gf_scale_into(const uint8_t* src, size_t n, uint8_t coeff, uint8_t* dst) {
    for (size_t i = 0; i < n; i++) dst[i] = gf_mul(src[i], coeff);
}

void xor_into(const uint8_t* a, const uint8_t* b, size_t n, uint8_t* dst) {
    for (size_t i = 0; i < n; i++) dst[i] = static_cast<uint8_t>(a[i] ^ b[i]);
}

std::vector<uint8_t> gf_scale(const std::vector<uint8_t>& buf, uint8_t coeff) {
    std::vector<uint8_t> out(buf.size());
    gf_scale_into(buf.data(), buf.size(), coeff, out.data());
    return out;
}

std::vector<uint8_t> xor_buf(const std::vector<uint8_t>& a,
                             const std::vector<uint8_t>& b) {
    size_t n = a.size() < b.size() ? a.size() : b.size();
    std::vector<uint8_t> out(n);
    xor_into(a.data(), b.data(), n, out.data());
    return out;
}

}  // namespace pcs
