#include "harness.hpp"

#include "pcs/hex.hpp"
#include "pcs/protocol.hpp"
#include "pcs/safename.hpp"

using namespace std;
using namespace pcs;

PCS_TEST(hex_round_trips) {
    const vector<uint8_t> data = {0x00, 0x01, 0x7F, 0x80, 0xFF, 0xAB};
    const string encoded = to_hex(data);
    CHECK_EQ(encoded, string("00017f80ffab"));

    vector<uint8_t> decoded;
    CHECK(from_hex(encoded, decoded));
    CHECK(decoded == data);
}

PCS_TEST(hex_rejects_malformed_input) {
    vector<uint8_t> out;
    CHECK(!from_hex("abc", out));       // odd length
    CHECK(!from_hex("zz", out));        // not hex digits
    CHECK(!from_hex("00ff0g", out));    // trailing bad digit

    // A rejected parse must not disturb what the caller already had.
    vector<uint8_t> keep = {1, 2, 3};
    CHECK(!from_hex("xyz", keep));
    CHECK_EQ(keep.size(), size_t{3});
}

PCS_TEST(hex_accepts_uppercase) {
    vector<uint8_t> out;
    CHECK(from_hex("DEADBEEF", out));
    CHECK_EQ(to_hex(out), string("deadbeef"));
}

PCS_TEST(safe_names_accept_ordinary_files) {
    CHECK(is_safe_name("notes.txt"));
    CHECK(is_safe_name("holiday photo.jpg"));
    CHECK(is_safe_name("archive.tar.gz"));
}

PCS_TEST(safe_names_reject_traversal_and_separators) {
    CHECK(!is_safe_name(""));
    CHECK(!is_safe_name("."));
    CHECK(!is_safe_name(".."));
    CHECK(!is_safe_name("../etc/passwd"));
    CHECK(!is_safe_name("dir/file.txt"));
    CHECK(!is_safe_name(string("dir") + char(92) + "file.txt"));
    CHECK(!is_safe_name(".hidden"));
    CHECK(!is_safe_name(string("nul") + char(0) + "byte"));
    CHECK(!is_safe_name("bell" + string(1, char(7))));
    CHECK(!is_safe_name("c:evil"));
    CHECK(!is_safe_name("wild*card"));
}

PCS_TEST(chunk_ids_must_be_lowercase_hex_of_the_right_length) {
    const string good(64, 'a');
    CHECK(is_safe_chunk_id(good));
    CHECK(!is_safe_chunk_id(string(63, 'a')));
    CHECK(!is_safe_chunk_id(string(65, 'a')));
    CHECK(!is_safe_chunk_id(string(64, 'A')));   // uppercase not accepted
    CHECK(!is_safe_chunk_id(string(64, 'z')));
    CHECK(!is_safe_chunk_id("../" + string(61, 'a')));
}

PCS_TEST(protocol_split_handles_spacing) {
    vector<string> parts = proto::split("PUTFILE notes.txt 1024 abcd");
    CHECK_EQ(parts.size(), size_t{4});
    CHECK_EQ(parts[0], string("PUTFILE"));
    CHECK_EQ(parts[3], string("abcd"));

    CHECK_EQ(proto::split("").size(), size_t{0});
    CHECK_EQ(proto::split("     ").size(), size_t{0});
    CHECK_EQ(proto::split("  LIST  ").size(), size_t{1});
}

PCS_TEST(split_n_keeps_the_last_field_whole) {
    // File names may contain spaces, so every command carrying one puts it
    // last and parses the remainder verbatim.
    vector<string> f = proto::split_n("PUTFILE 1024 abcd holiday photo.jpg", 4);
    CHECK_EQ(f.size(), size_t{4});
    CHECK_EQ(f[0], string("PUTFILE"));
    CHECK_EQ(f[1], string("1024"));
    CHECK_EQ(f[2], string("abcd"));
    CHECK_EQ(f[3], string("holiday photo.jpg"));

    // Repeated spaces inside the name survive too, which a rebuild from
    // split fields would have quietly collapsed.
    f = proto::split_n("GETFILE two  spaces.txt", 2);
    CHECK_EQ(f.size(), size_t{2});
    CHECK_EQ(f[1], string("two  spaces.txt"));

    // Leading spaces before the final field are not part of it.
    f = proto::split_n("STAT    name.txt", 2);
    CHECK_EQ(f[1], string("name.txt"));

    // Fewer fields than the limit is not an error, it just yields fewer.
    f = proto::split_n("LIST", 3);
    CHECK_EQ(f.size(), size_t{1});

    CHECK_EQ(proto::split_n("", 2).size(), size_t{0});
    CHECK_EQ(proto::split_n("anything", 0).size(), size_t{0});
}

PCS_TEST(names_with_spaces_are_accepted) {
    // is_safe_name permits spaces, so the wire format has to as well.
    CHECK(is_safe_name("holiday photo.jpg"));
    CHECK(is_safe_name("two  spaces.txt"));
}

PCS_TEST(protocol_size_parsing_is_bounded) {
    uint64_t value = 0;

    CHECK(proto::parse_size("0", 100, value));
    CHECK_EQ(value, uint64_t{0});

    CHECK(proto::parse_size("100", 100, value));
    CHECK_EQ(value, uint64_t{100});

    CHECK(!proto::parse_size("101", 100, value));   // above the limit
    CHECK(!proto::parse_size("", 100, value));
    CHECK(!proto::parse_size("-1", 100, value));
    CHECK(!proto::parse_size("12x", 100, value));
    CHECK(!proto::parse_size(" 12", 100, value));

    // A value that would overflow a 64-bit accumulator must be rejected
    // rather than wrapping around into something small and plausible.
    CHECK(!proto::parse_size("99999999999999999999999", UINT64_MAX, value));
    CHECK(!proto::parse_size("18446744073709551616", UINT64_MAX, value));
}
