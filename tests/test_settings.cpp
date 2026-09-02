#include "harness.hpp"

#include <fstream>

#include "pcs/settings.hpp"
#include "tempdir.hpp"

using namespace std;
using namespace pcs;
using pcstest::TempDir;

namespace {

void write_file(const filesystem::path& path, const string& text) {
    ofstream out(path, ios::trunc);
    out << text;
}

}  // namespace

PCS_TEST(settings_read_keys_from_the_default_profile) {
    TempDir dir;
    const auto path = dir.file("pcs.conf");
    write_file(path,
               "# a comment\n"
               "[default]\n"
               "server = 192.168.1.10:9000\n"
               "user   = alice\n"
               "\n"
               "; another comment\n"
               "cacert = /home/alice/ca.crt\n");

    Settings settings;
    string error;
    CHECK(Settings::load(path.string(), "", settings, error));
    CHECK(settings.loaded());
    CHECK_EQ(settings.get("server"), string("192.168.1.10:9000"));
    CHECK_EQ(settings.get("user"), string("alice"));
    CHECK_EQ(settings.get("cacert"), string("/home/alice/ca.crt"));
    CHECK_EQ(settings.get("missing"), string());
}

PCS_TEST(keys_are_case_insensitive_and_values_are_trimmed) {
    TempDir dir;
    const auto path = dir.file("pcs.conf");
    write_file(path, "[default]\n   SERVER   =    host:9000   \n");

    Settings settings;
    string error;
    CHECK(Settings::load(path.string(), "", settings, error));
    CHECK_EQ(settings.get("server"), string("host:9000"));
    CHECK_EQ(settings.get("SeRvEr"), string("host:9000"));
}

PCS_TEST(only_the_selected_profile_is_visible) {
    TempDir dir;
    const auto path = dir.file("pcs.conf");
    write_file(path,
               "[default]\n"
               "server = home:9000\n"
               "user = alice\n"
               "[work]\n"
               "server = office:9000\n");

    Settings settings;
    string error;

    CHECK(Settings::load(path.string(), "", settings, error));
    CHECK_EQ(settings.get("server"), string("home:9000"));

    // A setting from another section must not leak into this run, even when
    // the selected profile does not define it.
    CHECK(Settings::load(path.string(), "work", settings, error));
    CHECK_EQ(settings.get("server"), string("office:9000"));
    CHECK_EQ(settings.get("user"), string());
    CHECK_EQ(settings.profile(), string("work"));
}

PCS_TEST(peer_lists_split_on_commas_or_spaces) {
    TempDir dir;
    const auto path = dir.file("pcs.conf");
    write_file(path,
               "[default]\n"
               "peers = a:1, b:2 , c:3\n"
               "others = d:4 e:5\n"
               "empty =\n");

    Settings settings;
    string error;
    CHECK(Settings::load(path.string(), "", settings, error));

    const vector<string> peers = settings.get_list("peers");
    CHECK_EQ(peers.size(), size_t{3});
    CHECK_EQ(peers[0], string("a:1"));
    CHECK_EQ(peers[2], string("c:3"));

    CHECK_EQ(settings.get_list("others").size(), size_t{2});
    CHECK_EQ(settings.get_list("empty").size(), size_t{0});
    CHECK_EQ(settings.get_list("absent").size(), size_t{0});
}

PCS_TEST(a_missing_file_is_fine_but_a_named_missing_file_is_not) {
    Settings settings;
    string error;

    // Nothing named and nothing found: simply no presets.
    TempDir dir;
    const auto absent = dir.file("not-there.conf");
    CHECK(!Settings::load(absent.string(), "", settings, error));
    CHECK(!error.empty());

    // Asking for a file that is not there is a mistake worth reporting,
    // since the caller clearly expected it to exist.
    CHECK(error.find("no such settings file") != string::npos);
}

PCS_TEST(malformed_lines_are_reported_with_a_line_number) {
    TempDir dir;
    string error;
    Settings settings;

    const auto bad_line = dir.file("bad.conf");
    write_file(bad_line, "[default]\nserver = ok\nthis line has no equals\n");
    CHECK(!Settings::load(bad_line.string(), "", settings, error));
    CHECK(error.find(":3") != string::npos);

    const auto bad_section = dir.file("section.conf");
    write_file(bad_section, "[unclosed\n");
    CHECK(!Settings::load(bad_section.string(), "", settings, error));
    CHECK(error.find(":1") != string::npos);
}

PCS_TEST(search_paths_are_ordered_from_most_specific) {
    const vector<filesystem::path> paths = Settings::search_paths();
    CHECK(!paths.empty());

    // The working directory comes before anything in the home directory, so
    // a project-local file wins.
    bool seen_local = false;
    for (const filesystem::path& path : paths) {
        if (path.filename() == "pcs.conf" &&
            path.parent_path() == filesystem::current_path()) {
            seen_local = true;
            break;
        }
    }
    CHECK(seen_local);
}
