#include "pcs/manifest.hpp"

#include <fstream>
#include <sstream>

#include "pcs/protocol.hpp"
#include "pcs/safename.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace {

constexpr char kMagic[] = "pcs-manifest";
constexpr int kVersion = 2;

// stoi throws on malformed text; the parser should just reject the line.
bool parse_int(const string& text, int low, int high, int& out) {
    uint64_t value = 0;
    if (!proto::parse_size(text, static_cast<uint64_t>(high), value))
        return false;
    if (static_cast<int>(value) < low) return false;
    out = static_cast<int>(value);
    return true;
}

}  // namespace

bool Manifest::write(const fs::path& path, string& error) const {
    ofstream out(path, ios::trunc);
    if (!out) {
        error = "cannot write " + path.string();
        return false;
    }

    out << kMagic << " " << kVersion << "\n";
    out << "server " << server << "\n";
    out << "name " << name << "\n";
    out << "stream-size " << stream_size << "\n";
    out << "shard-size " << shard_size << "\n";
    out << "dedup-tag " << dedup_tag << "\n";
    out << "layout " << data_shards << " " << parity_shards << "\n";
    for (const ShardRef& s : shards)
        out << "shard " << s.index << " " << s.chunk_id << " " << s.peer << "\n";

    out.flush();
    if (!out) {
        error = "write failed for " + path.string();
        return false;
    }
    return true;
}

bool Manifest::read(const fs::path& path, Manifest& out, string& error) {
    ifstream in(path);
    if (!in) {
        error = "cannot read " + path.string();
        return false;
    }

    string line;
    if (!getline(in, line)) {
        error = "manifest is empty";
        return false;
    }
    {
        vector<string> head = proto::split(line);
        if (head.size() != 2 || head[0] != kMagic) {
            error = "not a manifest file";
            return false;
        }
        if (head[1] != to_string(kVersion)) {
            error = "unsupported manifest version " + head[1];
            return false;
        }
    }

    Manifest parsed;
    while (getline(in, line)) {
        if (line.empty()) continue;
        vector<string> f = proto::split(line);
        if (f.empty()) continue;

        const string& key = f[0];
        if (key == "server" && f.size() == 2) {
            parsed.server = f[1];
        } else if (key == "name" && f.size() == 2) {
            parsed.name = f[1];
        } else if (key == "stream-size" && f.size() == 2) {
            if (!proto::parse_size(f[1], UINT64_MAX / 2, parsed.stream_size)) {
                error = "bad stream-size";
                return false;
            }
        } else if (key == "shard-size" && f.size() == 2) {
            if (!proto::parse_size(f[1], UINT64_MAX / 2, parsed.shard_size)) {
                error = "bad shard-size";
                return false;
            }
        } else if (key == "dedup-tag" && f.size() == 2) {
            parsed.dedup_tag = f[1];
        } else if (key == "layout" && f.size() == 3) {
            if (!parse_int(f[1], 1, 16, parsed.data_shards) ||
                !parse_int(f[2], 0, 16, parsed.parity_shards)) {
                error = "bad layout line";
                return false;
            }
        } else if (key == "shard" && f.size() == 4) {
            ShardRef ref;
            if (!parse_int(f[1], 0, 3, ref.index)) {
                error = "shard index out of range";
                return false;
            }
            ref.chunk_id = f[2];
            ref.peer = f[3];
            if (!is_safe_chunk_id(ref.chunk_id)) {
                error = "malformed chunk id in manifest";
                return false;
            }
            parsed.shards.push_back(ref);
        }
        // Unknown keys are ignored so a newer writer stays readable here.
    }

    if (parsed.name.empty() || !is_safe_name(parsed.name)) {
        error = "manifest has no usable file name";
        return false;
    }
    if (parsed.server.empty()) {
        error = "manifest has no server address";
        return false;
    }

    out = move(parsed);
    return true;
}

bool peek_manifest_server(const fs::path& path, string& server) {
    ifstream in(path);
    if (!in) return false;

    string line;
    getline(in, line);  // magic + version
    while (getline(in, line)) {
        vector<string> f = proto::split(line);
        if (f.size() == 2 && f[0] == "server") {
            server = f[1];
            return true;
        }
    }
    return false;
}

}  // namespace pcs
