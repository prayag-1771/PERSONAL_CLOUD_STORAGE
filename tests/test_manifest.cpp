#include "harness.hpp"

#include <fstream>

#include "pcs/manifest.hpp"
#include "tempdir.hpp"

using namespace std;
using namespace pcs;
using pcstest::TempDir;

namespace {

Manifest sample() {
    Manifest m;
    m.server = "192.168.1.10:9000";
    m.name = "holiday.jpg";
    m.stream_size = 123456;
    m.shard_size = 61728;
    m.dedup_tag = string(64, 'b');
    m.data_shards = 2;
    m.parity_shards = 2;
    for (int i = 0; i < 4; i++) {
        ShardRef ref;
        ref.index = i;
        ref.chunk_id = string(64, static_cast<char>('a' + i));
        ref.peer = "10.0.0." + to_string(i + 1) + ":900" + to_string(i);
        m.shards.push_back(ref);
    }
    return m;
}

void write_raw(const filesystem::path& path, const string& text) {
    ofstream out(path, ios::trunc);
    out << text;
}

}  // namespace

PCS_TEST(manifest_round_trips) {
    TempDir dir;
    const auto path = dir.file("holiday.jpg.manifest");

    const Manifest original = sample();
    string error;
    CHECK(original.write(path, error));

    Manifest loaded;
    CHECK(Manifest::read(path, loaded, error));

    CHECK_EQ(loaded.server, original.server);
    CHECK_EQ(loaded.name, original.name);
    CHECK_EQ(loaded.stream_size, original.stream_size);
    CHECK_EQ(loaded.shard_size, original.shard_size);
    CHECK_EQ(loaded.dedup_tag, original.dedup_tag);
    CHECK_EQ(loaded.data_shards, original.data_shards);
    CHECK_EQ(loaded.parity_shards, original.parity_shards);
    CHECK_EQ(loaded.shards.size(), original.shards.size());

    for (size_t i = 0; i < loaded.shards.size(); i++) {
        CHECK_EQ(loaded.shards[i].index, original.shards[i].index);
        CHECK_EQ(loaded.shards[i].chunk_id, original.shards[i].chunk_id);
        CHECK_EQ(loaded.shards[i].peer, original.shards[i].peer);
    }
}

PCS_TEST(peeking_returns_the_server_without_a_full_parse) {
    TempDir dir;
    const auto path = dir.file("holiday.jpg.manifest");
    string error;
    CHECK(sample().write(path, error));

    string server;
    CHECK(peek_manifest_server(path, server));
    CHECK_EQ(server, string("192.168.1.10:9000"));
}

PCS_TEST(manifest_rejects_foreign_or_future_files) {
    TempDir dir;
    string error;

    const auto not_a_manifest = dir.file("random.manifest");
    write_raw(not_a_manifest, "hello there\n");
    Manifest loaded;
    CHECK(!Manifest::read(not_a_manifest, loaded, error));

    const auto empty = dir.file("empty.manifest");
    write_raw(empty, "");
    CHECK(!Manifest::read(empty, loaded, error));

    const auto newer = dir.file("newer.manifest");
    write_raw(newer, "pcs-manifest 99\nserver a:1\nname x\n");
    CHECK(!Manifest::read(newer, loaded, error));
}

PCS_TEST(manifest_rejects_dangerous_field_values) {
    TempDir dir;
    string error;
    Manifest loaded;

    // A chunk id is used to build a request, so a traversal attempt in one
    // has to be refused rather than passed along.
    const auto bad_chunk = dir.file("bad_chunk.manifest");
    write_raw(bad_chunk,
              "pcs-manifest 2\nserver a:1\nname x.txt\nstream-size 10\n"
              "shard-size 5\nlayout 2 2\nshard 0 ../../etc/passwd a:1\n");
    CHECK(!Manifest::read(bad_chunk, loaded, error));

    const auto bad_index = dir.file("bad_index.manifest");
    write_raw(bad_index,
              "pcs-manifest 2\nserver a:1\nname x.txt\nstream-size 10\n"
              "shard-size 5\nlayout 2 2\nshard 9 " + string(64, 'a') + " a:1\n");
    CHECK(!Manifest::read(bad_index, loaded, error));

    // The stored name becomes a path on retrieval, so it gets the same
    // treatment as anything arriving from the network.
    const auto bad_name = dir.file("bad_name.manifest");
    write_raw(bad_name,
              "pcs-manifest 2\nserver a:1\nname ../escape\nstream-size 10\n"
              "shard-size 5\nlayout 2 2\n");
    CHECK(!Manifest::read(bad_name, loaded, error));

    const auto no_server = dir.file("no_server.manifest");
    write_raw(no_server,
              "pcs-manifest 2\nname x.txt\nstream-size 10\nshard-size 5\n");
    CHECK(!Manifest::read(no_server, loaded, error));

    const auto bad_size = dir.file("bad_size.manifest");
    write_raw(bad_size,
              "pcs-manifest 2\nserver a:1\nname x.txt\nstream-size abc\n");
    CHECK(!Manifest::read(bad_size, loaded, error));
}

PCS_TEST(manifest_ignores_unknown_keys) {
    // A field written by a later version should not stop an older reader.
    TempDir dir;
    const auto path = dir.file("extra.manifest");
    write_raw(path,
              "pcs-manifest 2\nserver a:1\nname x.txt\nstream-size 10\n"
              "shard-size 5\nlayout 2 2\nsomething-new 42\n");

    Manifest loaded;
    string error;
    CHECK(Manifest::read(path, loaded, error));
    CHECK_EQ(loaded.name, string("x.txt"));
    CHECK_EQ(loaded.stream_size, uint64_t{10});
}
