#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// Bookkeeping for a file that went to peers because the server was down.
//
// The format is line-oriented text: it survives inspection with `cat`, and
// parsing cannot desynchronise the way the previous mixed text/binary layout
// could. One manifest is written per pending file.
namespace pcs {

struct ShardRef {
    int index = 0;          // 0=d0, 1=d1, 2=p0, 3=p1
    std::string chunk_id;   // SHA-256 of the shard, also its name on the peer
    std::string peer;       // host:port the shard was written to
};

struct Manifest {
    std::string server;       // server this file is waiting to reach
    std::string name;         // base filename
    uint64_t stream_size = 0; // bytes of sealed stream, before shard padding
    uint64_t shard_size = 0;  // bytes in each individual shard
    std::string dedup_tag;    // keyed tag, so sync needs no passphrase
    int data_shards = 0;
    int parity_shards = 0;
    std::vector<ShardRef> shards;

    bool write(const std::filesystem::path& path, std::string& error) const;
    static bool read(const std::filesystem::path& path, Manifest& out,
                     std::string& error);
};

// Reads only the server address, for a cheap "is it worth trying" check.
bool peek_manifest_server(const std::filesystem::path& path,
                          std::string& server);

}  // namespace pcs
