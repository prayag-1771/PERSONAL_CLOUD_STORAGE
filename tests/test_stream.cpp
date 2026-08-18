#include "harness.hpp"

#include <algorithm>

#include "pcs/config.hpp"
#include "pcs/stream.hpp"
#include "tempdir.hpp"

using namespace std;
using namespace pcs;
using pcstest::TempDir;

namespace {

const string kPass = "a passphrase worth typing";

}  // namespace

PCS_TEST(stream_round_trips_across_block_boundaries) {
    TempDir dir;

    // Sizes chosen around the block boundary, which is where a streaming
    // container is most likely to lose or duplicate a chunk.
    const uint64_t block = config::kBlockSize;
    const vector<uint64_t> sizes = {0, 1, 1000, block - 1, block, block + 1,
                                    2 * block + 123};

    for (uint64_t size : sizes) {
        const auto plain = dir.file("plain.bin");
        const auto sealed = dir.file("sealed.pcs");
        const auto restored = dir.file("restored.bin");

        pcstest::write_pattern(plain, size);

        string error, tag;
        CHECK(seal_file(plain, sealed, kPass, &tag, nullptr, error));
        CHECK(!tag.empty());

        CHECK(open_file(sealed, restored, kPass, nullptr, error));
        CHECK(pcstest::files_identical(plain, restored));
    }
}

PCS_TEST(stream_header_is_readable_without_the_passphrase) {
    TempDir dir;
    const auto plain = dir.file("plain.bin");
    const auto sealed = dir.file("sealed.pcs");
    pcstest::write_pattern(plain, 4096);

    string error, tag;
    CHECK(seal_file(plain, sealed, kPass, &tag, nullptr, error));

    StreamHeader header;
    CHECK(read_header(sealed, header, error));
    CHECK_EQ(header.plain_size, uint64_t{4096});
    CHECK_EQ(header.block_size, config::kBlockSize);
    CHECK_EQ(header.salt.size(), config::kSaltLen);
    CHECK_EQ(header.iterations, config::kKdfIterations);
}

PCS_TEST(stream_refuses_the_wrong_passphrase) {
    TempDir dir;
    const auto plain = dir.file("plain.bin");
    const auto sealed = dir.file("sealed.pcs");
    const auto restored = dir.file("restored.bin");
    pcstest::write_pattern(plain, 5000);

    string error, tag;
    CHECK(seal_file(plain, sealed, kPass, &tag, nullptr, error));

    CHECK(!open_file(sealed, restored, "not the passphrase", nullptr, error));
    CHECK(!error.empty());
    // A failed decrypt must not leave a partial file that looks usable.
    CHECK(!filesystem::exists(restored));
}

PCS_TEST(stream_detects_a_flipped_bit) {
    TempDir dir;
    const auto plain = dir.file("plain.bin");
    const auto sealed = dir.file("sealed.pcs");
    const auto restored = dir.file("restored.bin");
    pcstest::write_pattern(plain, 9000);

    string error, tag;
    CHECK(seal_file(plain, sealed, kPass, &tag, nullptr, error));

    vector<uint8_t> bytes = pcstest::read_all(sealed);
    bytes[bytes.size() - 40] = static_cast<uint8_t>(bytes[bytes.size() - 40] ^ 0x01);
    {
        ofstream out(sealed, ios::binary | ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<streamsize>(bytes.size()));
    }

    CHECK(!open_file(sealed, restored, kPass, nullptr, error));
}

PCS_TEST(stream_detects_truncation) {
    TempDir dir;
    const auto plain = dir.file("plain.bin");
    const auto sealed = dir.file("sealed.pcs");
    const auto restored = dir.file("restored.bin");
    pcstest::write_pattern(plain, 8192);

    string error, tag;
    CHECK(seal_file(plain, sealed, kPass, &tag, nullptr, error));

    // Chop off the last few bytes: the header still promises more content
    // than the file can deliver, and that mismatch has to be caught.
    error_code ec;
    const uint64_t size = filesystem::file_size(sealed, ec);
    filesystem::resize_file(sealed, size - 20, ec);

    CHECK(!open_file(sealed, restored, kPass, nullptr, error));
    CHECK(!filesystem::exists(restored));
}

PCS_TEST(stream_rejects_a_file_that_is_not_a_stream) {
    TempDir dir;
    const auto bogus = dir.file("bogus.pcs");
    const auto restored = dir.file("restored.bin");
    pcstest::write_pattern(bogus, 500);

    string error;
    CHECK(!open_file(bogus, restored, kPass, nullptr, error));

    StreamHeader header;
    CHECK(!read_header(bogus, header, error));
}

PCS_TEST(dedup_tags_track_content_and_passphrase) {
    TempDir dir;
    const auto first = dir.file("first.bin");
    const auto second = dir.file("second.bin");
    const auto different = dir.file("different.bin");

    pcstest::write_pattern(first, 3000);
    pcstest::write_pattern(second, 3000);      // identical content
    pcstest::write_pattern(different, 3001);

    const string a = dedup_tag_for_file(first, kPass);
    const string b = dedup_tag_for_file(second, kPass);
    const string c = dedup_tag_for_file(different, kPass);
    const string d = dedup_tag_for_file(first, "another passphrase");

    CHECK(!a.empty());
    CHECK_EQ(a, b);      // same content and passphrase: the point of dedup
    CHECK(a != c);       // different content
    CHECK(a != d);       // same content, different passphrase

    // The tag produced while sealing must match the standalone computation,
    // otherwise an upload would never match what is already stored.
    const auto sealed = dir.file("sealed.pcs");
    string error, sealed_tag;
    CHECK(seal_file(first, sealed, kPass, &sealed_tag, nullptr, error));
    CHECK_EQ(sealed_tag, a);
}
