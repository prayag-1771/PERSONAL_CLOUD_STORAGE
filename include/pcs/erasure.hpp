#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

// Byte-wise 2-of-4 erasure coding. The data half is split into d0/d1 and two
// parity shards are derived:
//
//   p0 = d0 XOR d1
//   p1 = (2 . d0) XOR (3 . d1)      [. is GF(2^8) multiplication]
//
// Any two of the four shards reconstruct both data shards. Every function
// here is byte-wise, so callers may apply them to a whole buffer or to
// successive slices of a stream and get identical results.
namespace pcs {

enum class Shard : int { D0 = 0, D1 = 1, P0 = 2, P1 = 3 };

const char* shard_name(Shard s);

void make_parity0(const uint8_t* d0, const uint8_t* d1, size_t n, uint8_t* out);
void make_parity1(const uint8_t* d0, const uint8_t* d1, size_t n, uint8_t* out);

// The two shards a recovery will be driven from.
struct ShardPair {
    Shard a;
    Shard b;
};

// Picks a usable pair out of whatever survived. Prefers (d0,d1) because that
// path is a straight copy with no arithmetic. Returns false if fewer than two
// shards are present.
bool choose_pair(const std::array<bool, 4>& present, ShardPair& out);

// Rebuilds both data shards from the chosen pair. `a` and `b` are the buffers
// for pair.a and pair.b, each of length n. Returns false if the pair is not a
// recoverable combination.
bool reconstruct(ShardPair pair, const uint8_t* a, const uint8_t* b, size_t n,
                 std::vector<uint8_t>& d0, std::vector<uint8_t>& d1);

}  // namespace pcs
