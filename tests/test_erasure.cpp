#include "harness.hpp"

#include <array>

#include "pcs/cipher.hpp"
#include "pcs/erasure.hpp"

using namespace std;
using namespace pcs;

namespace {

struct Shards {
    vector<uint8_t> d0, d1, p0, p1;
};

Shards build(const vector<uint8_t>& d0, const vector<uint8_t>& d1) {
    Shards s;
    s.d0 = d0;
    s.d1 = d1;
    s.p0.resize(d0.size());
    s.p1.resize(d0.size());
    make_parity0(d0.data(), d1.data(), d0.size(), s.p0.data());
    make_parity1(d0.data(), d1.data(), d0.size(), s.p1.data());
    return s;
}

const vector<uint8_t>& pick(const Shards& s, Shard which) {
    switch (which) {
        case Shard::D0: return s.d0;
        case Shard::D1: return s.d1;
        case Shard::P0: return s.p0;
        case Shard::P1: return s.p1;
    }
    return s.d0;
}

}  // namespace

PCS_TEST(any_two_shards_rebuild_the_data) {
    const size_t n = 512;
    const vector<uint8_t> original_d0 = random_bytes(n);
    const vector<uint8_t> original_d1 = random_bytes(n);
    const Shards shards = build(original_d0, original_d1);

    // All six ways of losing two of the four pieces.
    const ShardPair combinations[] = {
        {Shard::D0, Shard::D1}, {Shard::D0, Shard::P0}, {Shard::D1, Shard::P0},
        {Shard::D0, Shard::P1}, {Shard::D1, Shard::P1}, {Shard::P0, Shard::P1},
    };

    for (const ShardPair& pair : combinations) {
        vector<uint8_t> got_d0, got_d1;
        const bool ok = reconstruct(pair, pick(shards, pair.a).data(),
                                    pick(shards, pair.b).data(), n, got_d0,
                                    got_d1);
        CHECK(ok);
        CHECK(got_d0 == original_d0);
        CHECK(got_d1 == original_d1);
    }
}

PCS_TEST(recovery_works_on_edge_case_content) {
    // All-zero and all-ones content exercise the field arithmetic at its
    // boundaries, where a sloppy reduction would show up.
    const size_t n = 64;
    const vector<vector<uint8_t>> patterns = {
        vector<uint8_t>(n, 0x00),
        vector<uint8_t>(n, 0xFF),
        vector<uint8_t>(n, 0x80),
    };

    for (const vector<uint8_t>& left : patterns) {
        for (const vector<uint8_t>& right : patterns) {
            const Shards shards = build(left, right);
            vector<uint8_t> d0, d1;
            CHECK(reconstruct({Shard::P0, Shard::P1}, shards.p0.data(),
                              shards.p1.data(), n, d0, d1));
            CHECK(d0 == left);
            CHECK(d1 == right);
        }
    }
}

PCS_TEST(choose_pair_prefers_the_cheapest_available_combination) {
    ShardPair pair{};

    // Both data shards present: no arithmetic needed.
    CHECK(choose_pair({true, true, true, true}, pair));
    CHECK(pair.a == Shard::D0);
    CHECK(pair.b == Shard::D1);

    // One data shard gone: fall back to a parity that only needs XOR.
    CHECK(choose_pair({true, false, true, true}, pair));
    CHECK(pair.a == Shard::D0);
    CHECK(pair.b == Shard::P0);

    // Both data shards gone: the parity-only path.
    CHECK(choose_pair({false, false, true, true}, pair));
    CHECK(pair.a == Shard::P0);
    CHECK(pair.b == Shard::P1);
}

PCS_TEST(fewer_than_two_shards_cannot_recover) {
    ShardPair pair{};
    CHECK(!choose_pair({false, false, false, false}, pair));
    CHECK(!choose_pair({true, false, false, false}, pair));
    CHECK(!choose_pair({false, false, false, true}, pair));
}

PCS_TEST(shard_names_are_stable) {
    CHECK_EQ(string(shard_name(Shard::D0)), string("d0"));
    CHECK_EQ(string(shard_name(Shard::D1)), string("d1"));
    CHECK_EQ(string(shard_name(Shard::P0)), string("p0"));
    CHECK_EQ(string(shard_name(Shard::P1)), string("p1"));
}
