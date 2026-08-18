#include "harness.hpp"

#include <array>

#include "pcs/config.hpp"
#include "pcs/erasure.hpp"
#include "pcs/shardfile.hpp"
#include "pcs/stream.hpp"
#include "tempdir.hpp"

using namespace std;
using namespace pcs;
using pcstest::TempDir;

namespace {

const string kPass = "shard test passphrase";

array<filesystem::path, 4> shard_paths(const TempDir& dir) {
    return {dir.file("shard0"), dir.file("shard1"), dir.file("shard2"),
            dir.file("shard3")};
}

}  // namespace

PCS_TEST(splitting_produces_four_equal_shards) {
    TempDir dir;
    const auto source = dir.file("stream.bin");
    pcstest::write_pattern(source, 10001);   // deliberately odd

    const auto paths = shard_paths(dir);
    uint64_t shard_size = 0;
    string error;
    CHECK(split_stream(source, paths, shard_size, error));

    // An odd length rounds up, and every shard is padded to match.
    CHECK_EQ(shard_size, uint64_t{5001});
    error_code ec;
    for (const auto& path : paths)
        CHECK_EQ(static_cast<uint64_t>(filesystem::file_size(path, ec)),
                 shard_size);
}

PCS_TEST(any_two_shards_rebuild_the_original_stream) {
    TempDir dir;
    const auto source = dir.file("stream.bin");
    const uint64_t size = 40000;
    pcstest::write_pattern(source, size);

    const auto paths = shard_paths(dir);
    uint64_t shard_size = 0;
    string error;
    CHECK(split_stream(source, paths, shard_size, error));

    // Try every pair, keeping only those two and marking the rest as lost.
    for (int a = 0; a < 4; a++) {
        for (int b = a + 1; b < 4; b++) {
            array<filesystem::path, 4> available;
            available[a] = paths[a];
            available[b] = paths[b];

            const auto rebuilt = dir.file("rebuilt.bin");
            CHECK(join_shards(available, shard_size, size, rebuilt, error));
            CHECK(pcstest::files_identical(source, rebuilt));
        }
    }
}

PCS_TEST(rebuilding_needs_at_least_two_shards) {
    TempDir dir;
    const auto source = dir.file("stream.bin");
    pcstest::write_pattern(source, 2048);

    const auto paths = shard_paths(dir);
    uint64_t shard_size = 0;
    string error;
    CHECK(split_stream(source, paths, shard_size, error));

    array<filesystem::path, 4> only_one;
    only_one[2] = paths[2];

    const auto rebuilt = dir.file("rebuilt.bin");
    CHECK(!join_shards(only_one, shard_size, 2048, rebuilt, error));
    CHECK(!error.empty());
}

PCS_TEST(a_truncated_shard_is_not_treated_as_available) {
    TempDir dir;
    const auto source = dir.file("stream.bin");
    const uint64_t size = 4096;
    pcstest::write_pattern(source, size);

    const auto paths = shard_paths(dir);
    uint64_t shard_size = 0;
    string error;
    CHECK(split_stream(source, paths, shard_size, error));

    // Damage one shard by shortening it, then offer only that one and a
    // good one. The short shard must be rejected, leaving too few pieces.
    error_code ec;
    filesystem::resize_file(paths[1], shard_size - 10, ec);

    array<filesystem::path, 4> available;
    available[1] = paths[1];
    available[3] = paths[3];

    const auto rebuilt = dir.file("rebuilt.bin");
    CHECK(!join_shards(available, shard_size, size, rebuilt, error));
}

PCS_TEST(seal_split_join_open_returns_the_original_file) {
    // The whole offline path end to end, without any networking: encrypt,
    // scatter, lose two shards, rebuild, decrypt.
    TempDir dir;
    const auto plain = dir.file("holiday.bin");
    const auto sealed = dir.file("sealed.pcs");
    const auto rebuilt = dir.file("rebuilt.pcs");
    const auto restored = dir.file("restored.bin");

    pcstest::write_pattern(plain, config::kBlockSize + 7777);

    string error, tag;
    CHECK(seal_file(plain, sealed, kPass, &tag, nullptr, error));

    const auto paths = shard_paths(dir);
    uint64_t shard_size = 0;
    CHECK(split_stream(sealed, paths, shard_size, error));

    error_code ec;
    const uint64_t stream_size = filesystem::file_size(sealed, ec);

    // Keep only the two parity shards, the hardest recovery case.
    array<filesystem::path, 4> available;
    available[2] = paths[2];
    available[3] = paths[3];

    CHECK(join_shards(available, shard_size, stream_size, rebuilt, error));
    CHECK(pcstest::files_identical(sealed, rebuilt));

    CHECK(open_file(rebuilt, restored, kPass, nullptr, error));
    CHECK(pcstest::files_identical(plain, restored));
}
