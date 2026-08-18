#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// Arithmetic in GF(2^8) with the AES reduction polynomial (0x11B). Used to
// build the second parity shard; the first one is a plain XOR.
namespace pcs {

uint8_t gf_mul(uint8_t a, uint8_t b);

// Multiplicative inverse, i.e. gf_mul(x, gf_inv(x)) == 1 for x != 0.
// gf_inv(0) is defined as 0 since zero has no inverse.
uint8_t gf_inv(uint8_t x);

void gf_scale_into(const uint8_t* src, size_t n, uint8_t coeff, uint8_t* dst);
void xor_into(const uint8_t* a, const uint8_t* b, size_t n, uint8_t* dst);

std::vector<uint8_t> gf_scale(const std::vector<uint8_t>& buf, uint8_t coeff);
std::vector<uint8_t> xor_buf(const std::vector<uint8_t>& a,
                             const std::vector<uint8_t>& b);

}  // namespace pcs
