#include "pcs/shardfile.hpp"

#include <algorithm>
#include <fstream>

#include "pcs/config.hpp"
#include "pcs/erasure.hpp"

namespace fs = std::filesystem;

namespace pcs {
namespace {

// Reads exactly `want` bytes, zero-filling whatever lies past end of file.
// The second data shard is the short one whenever the stream length is odd,
// and zero padding is what makes all four shards the same length.
void read_padded(std::ifstream& in, uint8_t* dst, size_t want) {
    in.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(want));
    const size_t got = static_cast<size_t>(in.gcount());
    if (got < want) std::fill(dst + got, dst + want, uint8_t{0});
    if (!in && got < want) in.clear();  // padding is expected, not an error
}

}  // namespace

bool split_stream(const fs::path& stream_path,
                  const std::array<fs::path, 4>& shard_paths,
                  uint64_t& shard_size, std::string& error) {
    std::error_code ec;
    const uint64_t stream_size =
        static_cast<uint64_t>(fs::file_size(stream_path, ec));
    if (ec) {
        error = "cannot size " + stream_path.string();
        return false;
    }

    const uint64_t half = (stream_size + 1) / 2;
    shard_size = half;

    // Two readers over one file: one walking the first half, one the second.
    std::ifstream a(stream_path, std::ios::binary);
    std::ifstream b(stream_path, std::ios::binary);
    if (!a || !b) {
        error = "cannot read " + stream_path.string();
        return false;
    }
    b.seekg(static_cast<std::streamoff>(half), std::ios::beg);

    std::ofstream out[4];
    for (int i = 0; i < 4; i++) {
        out[i].open(shard_paths[i], std::ios::binary | std::ios::trunc);
        if (!out[i]) {
            error = "cannot write " + shard_paths[i].string();
            return false;
        }
    }

    const size_t slice = config::kIoBufferSize;
    std::vector<uint8_t> d0(slice), d1(slice), p0(slice), p1(slice);

    uint64_t done = 0;
    while (done < half) {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(slice, half - done));

        read_padded(a, d0.data(), n);
        read_padded(b, d1.data(), n);

        make_parity0(d0.data(), d1.data(), n, p0.data());
        make_parity1(d0.data(), d1.data(), n, p1.data());

        const uint8_t* src[4] = {d0.data(), d1.data(), p0.data(), p1.data()};
        for (int i = 0; i < 4; i++) {
            out[i].write(reinterpret_cast<const char*>(src[i]),
                         static_cast<std::streamsize>(n));
            if (!out[i]) {
                error = "write failed for " + shard_paths[i].string();
                return false;
            }
        }
        done += n;
    }

    for (int i = 0; i < 4; i++) {
        out[i].flush();
        if (!out[i]) {
            error = "flush failed for " + shard_paths[i].string();
            return false;
        }
    }
    return true;
}

bool join_shards(const std::array<fs::path, 4>& shard_paths,
                 uint64_t shard_size, uint64_t stream_size,
                 const fs::path& stream_path, std::string& error) {
    std::array<bool, 4> present{};
    for (int i = 0; i < 4; i++) {
        std::error_code ec;
        present[i] = !shard_paths[i].empty() && fs::exists(shard_paths[i], ec) &&
                     static_cast<uint64_t>(fs::file_size(shard_paths[i], ec)) ==
                         shard_size;
    }

    ShardPair pair{};
    if (!choose_pair(present, pair)) {
        error = "need at least 2 of the 4 shards to rebuild this file";
        return false;
    }

    std::ifstream in_a(shard_paths[static_cast<int>(pair.a)], std::ios::binary);
    std::ifstream in_b(shard_paths[static_cast<int>(pair.b)], std::ios::binary);
    if (!in_a || !in_b) {
        error = "cannot read the selected shards";
        return false;
    }

    std::ofstream out(stream_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot write " + stream_path.string();
        return false;
    }

    const size_t slice = config::kIoBufferSize;
    std::vector<uint8_t> buf_a(slice), buf_b(slice);
    std::vector<uint8_t> d0, d1;

    uint64_t done = 0;
    while (done < shard_size) {
        const size_t n =
            static_cast<size_t>(std::min<uint64_t>(slice, shard_size - done));

        in_a.read(reinterpret_cast<char*>(buf_a.data()),
                  static_cast<std::streamsize>(n));
        in_b.read(reinterpret_cast<char*>(buf_b.data()),
                  static_cast<std::streamsize>(n));
        if (static_cast<size_t>(in_a.gcount()) != n ||
            static_cast<size_t>(in_b.gcount()) != n) {
            error = "shard ended earlier than its recorded length";
            return false;
        }

        if (!reconstruct(pair, buf_a.data(), buf_b.data(), n, d0, d1)) {
            error = "no recovery rule for the available shard combination";
            return false;
        }

        // The first data shard lands at `done`, the second one shard_size
        // further along, so one output file is filled from both ends inward.
        out.seekp(static_cast<std::streamoff>(done), std::ios::beg);
        out.write(reinterpret_cast<const char*>(d0.data()),
                  static_cast<std::streamsize>(n));
        out.seekp(static_cast<std::streamoff>(shard_size + done), std::ios::beg);
        out.write(reinterpret_cast<const char*>(d1.data()),
                  static_cast<std::streamsize>(n));
        if (!out) {
            error = "write failed while rebuilding the stream";
            return false;
        }
        done += n;
    }

    out.close();

    // Drop the odd-length padding byte so the stream is byte-identical to the
    // one that was sealed.
    std::error_code ec;
    fs::resize_file(stream_path, static_cast<uintmax_t>(stream_size), ec);
    if (ec) {
        error = "cannot trim the rebuilt stream to its original length";
        return false;
    }
    return true;
}

}  // namespace pcs
