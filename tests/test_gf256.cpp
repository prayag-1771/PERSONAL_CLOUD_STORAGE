#include "harness.hpp"

#include "pcs/gf256.hpp"

using namespace std;
using namespace pcs;

PCS_TEST(gf_multiplication_basics) {
    CHECK_EQ(gf_mul(0, 5), uint8_t{0});
    CHECK_EQ(gf_mul(1, 5), uint8_t{5});
    CHECK_EQ(gf_mul(5, 1), uint8_t{5});

    // 0x80 doubled overflows and is reduced by the AES polynomial.
    CHECK_EQ(gf_mul(0x80, 2), uint8_t{0x1B});
}

PCS_TEST(gf_multiplication_is_commutative_and_associative) {
    for (int a = 0; a < 256; a += 7) {
        for (int b = 0; b < 256; b += 11) {
            const uint8_t x = static_cast<uint8_t>(a);
            const uint8_t y = static_cast<uint8_t>(b);
            CHECK_EQ(gf_mul(x, y), gf_mul(y, x));

            const uint8_t z = static_cast<uint8_t>((a + b) & 0xFF);
            CHECK_EQ(gf_mul(gf_mul(x, y), z), gf_mul(x, gf_mul(y, z)));
        }
    }
}

PCS_TEST(every_nonzero_element_has_an_inverse) {
    for (int i = 1; i < 256; i++) {
        const uint8_t x = static_cast<uint8_t>(i);
        const uint8_t inverse = gf_inv(x);
        CHECK(inverse != 0);
        CHECK_EQ(gf_mul(x, inverse), uint8_t{1});
    }
    CHECK_EQ(gf_inv(0), uint8_t{0});
}

PCS_TEST(inverses_of_the_two_parity_coefficients) {
    // The recovery rules lean on these two constants; if the field
    // arithmetic ever changed, this is where it would show up first.
    CHECK_EQ(gf_inv(2), uint8_t{0x8D});
    CHECK_EQ(gf_inv(3), uint8_t{0xF6});
}

PCS_TEST(scaling_and_xor_operate_byte_wise) {
    const vector<uint8_t> a = {0x01, 0x02, 0x03, 0xFF};
    const vector<uint8_t> b = {0x10, 0x20, 0x30, 0x0F};

    const vector<uint8_t> mixed = xor_buf(a, b);
    CHECK_EQ(mixed.size(), size_t{4});
    CHECK_EQ(mixed[0], uint8_t{0x11});
    CHECK_EQ(mixed[3], uint8_t{0xF0});

    // XOR is its own inverse, so undoing it returns the original.
    const vector<uint8_t> restored = xor_buf(mixed, b);
    CHECK(restored == a);

    const vector<uint8_t> scaled = gf_scale(a, 3);
    for (size_t i = 0; i < a.size(); i++) CHECK_EQ(scaled[i], gf_mul(a[i], 3));

    // Scaling by the inverse coefficient undoes the scaling.
    const vector<uint8_t> unscaled = gf_scale(scaled, gf_inv(3));
    CHECK(unscaled == a);
}
