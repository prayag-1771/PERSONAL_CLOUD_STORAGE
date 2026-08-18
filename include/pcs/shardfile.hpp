#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// File-level erasure coding. The sealed stream is halved into d0/d1 and two
// parity shards are derived from those halves. Everything is done in fixed
// size slices with a handful of open file descriptors, so shard splitting is
// bounded in memory just like sealing is.
namespace pcs {

// Splits `stream_path` into four equal shards. The final shard length is
// written to `shard_size`; the second data shard is zero-padded when the
// stream length is odd.
bool split_stream(const std::filesystem::path& stream_path,
                  const std::array<std::filesystem::path, 4>& shard_paths,
                  uint64_t& shard_size, std::string& error);

// Rebuilds the stream from any two available shards. Entries of
// `shard_paths` that are empty are treated as lost.
bool join_shards(const std::array<std::filesystem::path, 4>& shard_paths,
                 uint64_t shard_size, uint64_t stream_size,
                 const std::filesystem::path& stream_path,
                 std::string& error);

}  // namespace pcs
