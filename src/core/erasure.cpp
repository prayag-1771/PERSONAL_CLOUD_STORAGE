#include "pcs/erasure.hpp"

#include "pcs/gf256.hpp"

namespace pcs {

const char* shard_name(Shard s) {
    switch (s) {
        case Shard::D0: return "d0";
        case Shard::D1: return "d1";
        case Shard::P0: return "p0";
        case Shard::P1: return "p1";
    }
    return "?";
}

void make_parity0(const uint8_t* d0, const uint8_t* d1, size_t n, uint8_t* out) {
    xor_into(d0, d1, n, out);
}

void make_parity1(const uint8_t* d0, const uint8_t* d1, size_t n, uint8_t* out) {
    for (size_t i = 0; i < n; i++)
        out[i] = static_cast<uint8_t>(gf_mul(d0[i], 2) ^ gf_mul(d1[i], 3));
}

bool choose_pair(const std::array<bool, 4>& present, ShardPair& out) {
    // Ordered cheapest first: the plain-copy case, then the XOR cases, then
    // the two that need a GF inverse.
    static const ShardPair kOrder[] = {
        {Shard::D0, Shard::D1},
        {Shard::D0, Shard::P0},
        {Shard::D1, Shard::P0},
        {Shard::D0, Shard::P1},
        {Shard::D1, Shard::P1},
        {Shard::P0, Shard::P1},
    };

    for (const ShardPair& candidate : kOrder) {
        if (present[static_cast<int>(candidate.a)] &&
            present[static_cast<int>(candidate.b)]) {
            out = candidate;
            return true;
        }
    }
    return false;
}

bool reconstruct(ShardPair pair, const uint8_t* a, const uint8_t* b, size_t n,
                 std::vector<uint8_t>& d0, std::vector<uint8_t>& d1) {
    d0.assign(n, 0);
    d1.assign(n, 0);

    const Shard x = pair.a;
    const Shard y = pair.b;

    if (x == Shard::D0 && y == Shard::D1) {
        d0.assign(a, a + n);
        d1.assign(b, b + n);
        return true;
    }
    if (x == Shard::D0 && y == Shard::P0) {
        // d1 = d0 XOR p0
        d0.assign(a, a + n);
        xor_into(a, b, n, d1.data());
        return true;
    }
    if (x == Shard::D1 && y == Shard::P0) {
        // d0 = d1 XOR p0
        d1.assign(a, a + n);
        xor_into(a, b, n, d0.data());
        return true;
    }
    if (x == Shard::D0 && y == Shard::P1) {
        // p1 = 2.d0 XOR 3.d1  =>  d1 = inv(3) . (p1 XOR 2.d0)
        d0.assign(a, a + n);
        const uint8_t inv3 = gf_inv(3);
        for (size_t i = 0; i < n; i++) {
            uint8_t t = static_cast<uint8_t>(b[i] ^ gf_mul(a[i], 2));
            d1[i] = gf_mul(t, inv3);
        }
        return true;
    }
    if (x == Shard::D1 && y == Shard::P1) {
        // d0 = inv(2) . (p1 XOR 3.d1)
        d1.assign(a, a + n);
        const uint8_t inv2 = gf_inv(2);
        for (size_t i = 0; i < n; i++) {
            uint8_t t = static_cast<uint8_t>(b[i] ^ gf_mul(a[i], 3));
            d0[i] = gf_mul(t, inv2);
        }
        return true;
    }
    if (x == Shard::P0 && y == Shard::P1) {
        // p1 XOR 2.p0 = (2.d0 XOR 3.d1) XOR (2.d0 XOR 2.d1) = d1
        // then d0 = p0 XOR d1
        for (size_t i = 0; i < n; i++) {
            d1[i] = static_cast<uint8_t>(b[i] ^ gf_mul(a[i], 2));
            d0[i] = static_cast<uint8_t>(a[i] ^ d1[i]);
        }
        return true;
    }
    return false;
}

}  // namespace pcs
