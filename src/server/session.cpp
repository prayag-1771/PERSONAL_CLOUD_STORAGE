#include "session.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <mutex>
#include <vector>

#include "pcs/config.hpp"
#include "pcs/digest.hpp"
#include "pcs/protocol.hpp"
#include "pcs/safename.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace server {
namespace {

mutex g_log_mutex;

// Streams `size` bytes off the wire into `path`, never holding more than one
// buffer in memory regardless of how large the upload is.
bool receive_to_file(Channel& channel, const fs::path& path, uint64_t size,
                     string& error) {
    ofstream out(path, ios::binary | ios::trunc);
    if (!out) {
        error = "cannot open temporary file";
        return false;
    }

    vector<char> buf(config::kIoBufferSize);
    uint64_t left = size;
    while (left > 0) {
        const size_t want =
            static_cast<size_t>(min<uint64_t>(buf.size(), left));
        if (!channel.recv(buf.data(), want)) {
            error = "connection dropped mid-upload";
            return false;
        }
        out.write(buf.data(), static_cast<streamsize>(want));
        if (!out) {
            error = "write failed (disk full?)";
            return false;
        }
        left -= want;
    }

    out.flush();
    if (!out) {
        error = "flush failed";
        return false;
    }
    return true;
}

bool send_from_file(Channel& channel, const fs::path& path, uint64_t size) {
    ifstream in(path, ios::binary);
    if (!in) return false;

    vector<char> buf(config::kIoBufferSize);
    uint64_t left = size;
    while (left > 0) {
        const size_t want =
            static_cast<size_t>(min<uint64_t>(buf.size(), left));
        in.read(buf.data(), static_cast<streamsize>(want));
        if (static_cast<size_t>(in.gcount()) != want) return false;
        if (!channel.send(buf.data(), want)) return false;
        left -= want;
    }
    return true;
}

}  // namespace

void log_line(const string& text) {
    lock_guard<mutex> guard(g_log_mutex);
    cout << text << endl;
}

Session::Session(Channel& channel, Store& store, const UserStore& users,
                 string token, int port)
    : channel_(channel),
      store_(store),
      users_(users),
      token_(move(token)),
      port_(port) {}

bool Session::fail(const string& reason) {
    channel_.send_line(string(proto::kErr) + " " + reason);
    return true;  // the error is reported, the connection may continue
}

void Session::run() {
    string line;
    while (channel_.read_line(line)) {
        if (!handle(line)) break;
    }
}

bool Session::handle(const string& line) {
    const vector<string> f = proto::split(line);
    if (f.empty()) return true;

    const string& cmd = f[0];

    // Reachable before authentication: a version handshake and a liveness
    // probe. The probe has to stay open, because deciding whether to fall
    // back to peers must not require a token round trip.
    if (cmd == proto::kHello) {
        channel_.send_line(string(proto::kOk) + " " + config::kProtocol);
        return true;
    }
    if (cmd == proto::kPing) {
        channel_.send_line(proto::kPong);
        return true;
    }
    if (cmd == proto::kQuit) {
        channel_.send_line(proto::kBye);
        return false;
    }
    if (cmd == proto::kLogin) return do_login(f);
    if (cmd == proto::kAuth)  return do_auth(f);

    // File commands act on one account, so they need an identity.
    const bool is_file_command =
        cmd == proto::kStat || cmd == proto::kPutFile ||
        cmd == proto::kGetFile || cmd == proto::kList;
    if (is_file_command && !logged_in_) return fail("login-required");

    // Chunk commands only move opaque ciphertext between machines, so the
    // shared machine token is the right level of proof for them.
    const bool is_chunk_command =
        cmd == proto::kPutChunk || cmd == proto::kGetChunk ||
        cmd == proto::kDelChunk;
    if (is_chunk_command && !machine_trusted_) return fail("token-required");

    if (cmd == proto::kStat)     return do_stat(f);
    if (cmd == proto::kPutFile)  return do_put_file(f);
    if (cmd == proto::kGetFile)  return do_get_file(f);
    if (cmd == proto::kPutChunk) return do_put_chunk(f);
    if (cmd == proto::kGetChunk) return do_get_chunk(f);
    if (cmd == proto::kDelChunk) return do_del_chunk(f);
    if (cmd == proto::kList)     return do_list();

    return fail("unknown-command");
}

bool Session::do_login(const vector<string>& f) {
    if (f.size() != 3) return fail("malformed-login");

    const string& name = f[1];
    if (!users_.verify(name, f[2])) {
        log_line("[server " + to_string(port_) + "] login rejected for " + name);
        channel_.send_line(string(proto::kErr) + " bad-credentials");
        return false;  // one attempt per connection
    }

    string error;
    if (!store_.ensure_account(name, error)) return fail("account-storage");

    user_ = name;
    logged_in_ = true;
    channel_.send_line(proto::kOk);
    log_line("[server " + to_string(port_) + "] " + name + " logged in");
    return true;
}

bool Session::do_auth(const vector<string>& f) {
    if (f.size() != 2) return fail("malformed-auth");

    // Compared in constant time so a wrong token cannot be recovered by
    // timing how far the comparison got.
    if (!secure_equal(f[1], token_)) {
        log_line("[server " + to_string(port_) + "] auth rejected");
        channel_.send_line(string(proto::kErr) + " bad-token");
        return false;  // one guess per connection
    }

    machine_trusted_ = true;
    channel_.send_line(proto::kOk);
    return true;
}

bool Session::do_stat(const vector<string>& f) {
    if (f.size() != 2) return fail("malformed-stat");

    uint64_t size = 0;
    string tag;
    lock_guard<mutex> guard(store_.mutex());

    if (!store_.file_info(user_, f[1], size, tag)) {
        channel_.send_line(proto::kNone);
        return true;
    }
    channel_.send_line(string(proto::kMeta) + " " + to_string(size) +
                       " " + (tag.empty() ? "-" : tag));
    return true;
}

bool Session::do_put_file(const vector<string>& f) {
    if (f.size() != 4) return fail("malformed-putfile");

    const string& name = f[1];
    uint64_t size = 0;
    if (!proto::parse_size(f[2], config::kMaxTransferSize, size))
        return fail("bad-size");

    const fs::path final_path = store_.file_path(user_, name);
    if (final_path.empty()) return fail("bad-name");

    const fs::path temp = store_.temp_path();
    string error;
    if (!receive_to_file(channel_, temp, size, error)) {
        error_code ignored;
        fs::remove(temp, ignored);
        log_line("[server " + to_string(port_) + "] upload failed: " + error);
        return false;
    }

    {
        lock_guard<mutex> guard(store_.mutex());
        error_code ec;
        // Rename last, so a reader never observes a half-written file.
        fs::rename(temp, final_path, ec);
        if (ec) {
            fs::remove(temp, ec);
            return fail("store-failed");
        }
        store_.write_tag(user_, name, f[3]);
    }

    channel_.send_line(proto::kOk);
    log_line("[server " + to_string(port_) + "] " + user_ + " stored " + name +
             " (" + to_string(size) + " bytes, encrypted)");
    return true;
}

bool Session::do_get_file(const vector<string>& f) {
    if (f.size() != 2) return fail("malformed-getfile");

    fs::path path;
    uint64_t size = 0;
    {
        lock_guard<mutex> guard(store_.mutex());
        path = store_.file_path(user_, f[1]);
        string tag;
        if (path.empty() || !store_.file_info(user_, f[1], size, tag)) {
            channel_.send_line(proto::kNone);
            return true;
        }
    }

    channel_.send_line(string(proto::kData) + " " + to_string(size));
    if (!send_from_file(channel_, path, size)) return false;

    log_line("[server " + to_string(port_) + "] served " + user_ + "/" + f[1] +
             " (" + to_string(size) + " bytes)");
    return true;
}

bool Session::do_put_chunk(const vector<string>& f) {
    if (f.size() != 3) return fail("malformed-putchunk");

    const fs::path final_path = store_.chunk_path(f[1]);
    if (final_path.empty()) return fail("bad-chunk-id");

    uint64_t size = 0;
    if (!proto::parse_size(f[2], config::kMaxTransferSize, size))
        return fail("bad-size");

    const fs::path temp = store_.temp_path();
    string error;
    if (!receive_to_file(channel_, temp, size, error)) {
        error_code ignored;
        fs::remove(temp, ignored);
        return false;
    }

    {
        lock_guard<mutex> guard(store_.mutex());
        error_code ec;
        fs::rename(temp, final_path, ec);
        if (ec) {
            fs::remove(temp, ec);
            return fail("store-failed");
        }
    }

    channel_.send_line(proto::kOk);
    log_line("[server " + to_string(port_) + "] stored chunk " +
             f[1].substr(0, 12) + " (" + to_string(size) + " bytes)");
    return true;
}

bool Session::do_get_chunk(const vector<string>& f) {
    if (f.size() != 2) return fail("malformed-getchunk");

    fs::path path;
    uint64_t size = 0;
    {
        lock_guard<mutex> guard(store_.mutex());
        path = store_.chunk_path(f[1]);
        error_code ec;
        if (path.empty() || !fs::exists(path, ec)) {
            channel_.send_line(proto::kNone);
            return true;
        }
        size = static_cast<uint64_t>(fs::file_size(path, ec));
        if (ec) {
            channel_.send_line(proto::kNone);
            return true;
        }
    }

    channel_.send_line(string(proto::kData) + " " + to_string(size));
    return send_from_file(channel_, path, size);
}

bool Session::do_del_chunk(const vector<string>& f) {
    if (f.size() != 2) return fail("malformed-delchunk");

    const fs::path path = store_.chunk_path(f[1]);
    if (path.empty()) return fail("bad-chunk-id");

    {
        lock_guard<mutex> guard(store_.mutex());
        error_code ec;
        fs::remove(path, ec);
    }

    // Deleting something already gone is success, so a retried cleanup after
    // a dropped connection does not look like a failure.
    channel_.send_line(proto::kOk);
    return true;
}

bool Session::do_list() {
    vector<pair<string, uint64_t>> files;
    {
        lock_guard<mutex> guard(store_.mutex());
        files = store_.list_files(user_);
    }

    channel_.send_line(string(proto::kCount) + " " +
                       to_string(files.size()));
    for (const pair<string, uint64_t>& entry : files) {
        if (!channel_.send_line(entry.first + " " +
                                to_string(entry.second)))
            return false;
    }
    return true;
}

}  // namespace server
}  // namespace pcs
