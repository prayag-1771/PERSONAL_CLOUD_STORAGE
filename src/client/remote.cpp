#include "remote.hpp"

#include <algorithm>
#include <fstream>

#include "pcs/config.hpp"
#include "pcs/protocol.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace client {

Remote::Remote(ChannelPtr channel) : channel_(move(channel)) {}

Remote::~Remote() = default;

unique_ptr<Remote> Remote::connect(const string& address,
                                        const Credentials& credentials,
                                        Access access, string& error) {
    ChannelPtr channel = dial(address, error);
    if (!channel) return nullptr;

    unique_ptr<Remote> remote(new Remote(move(channel)));

    string reply;
    if (!remote->channel_->send_line(string(proto::kHello) + " " +
                                     config::kProtocol) ||
        !remote->channel_->read_line(reply)) {
        error = "handshake failed with " + address;
        return nullptr;
    }

    const vector<string> hello = proto::split(reply);
    if (hello.size() != 2 || hello[0] != proto::kOk) {
        error = "unexpected handshake reply from " + address + ": " + reply;
        return nullptr;
    }
    if (hello[1] != config::kProtocol) {
        error = "server speaks " + hello[1] + ", this client speaks " +
                config::kProtocol;
        return nullptr;
    }

    if (access == Access::Files) {
        if (credentials.user.empty()) {
            error = "no account given: pass --user (and --password, or let it "
                    "prompt)";
            return nullptr;
        }
        if (!remote->channel_->send_line(string(proto::kLogin) + " " +
                                        credentials.user + " " +
                                        credentials.password) ||
            !remote->channel_->read_line(reply)) {
            error = "login request failed";
            return nullptr;
        }
        const vector<string> f = proto::split(reply);
        if (f.empty() || f[0] != proto::kOk) {
            error = "the server rejected that account or password";
            return nullptr;
        }
    } else {
        if (credentials.token.empty()) {
            error = "no machine token given: pass --token or set PCS_TOKEN";
            return nullptr;
        }
        if (!remote->channel_->send_line(string(proto::kAuth) + " " +
                                        credentials.token) ||
            !remote->channel_->read_line(reply)) {
            error = "token request failed";
            return nullptr;
        }
        const vector<string> f = proto::split(reply);
        if (f.empty() || f[0] != proto::kOk) {
            error = "the peer rejected the machine token";
            return nullptr;
        }
    }

    return remote;
}

bool Remote::reachable(const string& address) {
    string error;
    ChannelPtr channel = dial(address, error);
    if (!channel) return false;

    string reply;
    if (!channel->send_line(proto::kPing)) return false;
    if (!channel->read_line(reply)) return false;
    return reply == proto::kPong;
}

void Remote::quit() {
    if (!channel_) return;
    string reply;
    channel_->send_line(proto::kQuit);
    channel_->read_line(reply);
}

bool Remote::send_file_body(const fs::path& source, uint64_t size,
                            const ProgressFn& progress, string& error) {
    ifstream in(source, ios::binary);
    if (!in) {
        error = "cannot read " + source.string();
        return false;
    }

    vector<char> buf(config::kIoBufferSize);
    uint64_t sent = 0;
    while (sent < size) {
        const size_t want =
            static_cast<size_t>(min<uint64_t>(buf.size(), size - sent));
        in.read(buf.data(), static_cast<streamsize>(want));
        if (static_cast<size_t>(in.gcount()) != want) {
            error = "source file ended early";
            return false;
        }
        if (!channel_->send(buf.data(), want)) {
            error = "connection dropped during transfer";
            return false;
        }
        sent += want;
        if (progress) progress(sent, size);
    }
    return true;
}

bool Remote::read_body_to_file(const fs::path& destination, uint64_t size,
                               const ProgressFn& progress, string& error) {
    ofstream out(destination, ios::binary | ios::trunc);
    if (!out) {
        error = "cannot write " + destination.string();
        return false;
    }

    vector<char> buf(config::kIoBufferSize);
    uint64_t got = 0;
    while (got < size) {
        const size_t want =
            static_cast<size_t>(min<uint64_t>(buf.size(), size - got));
        if (!channel_->recv(buf.data(), want)) {
            error = "connection dropped during transfer";
            return false;
        }
        out.write(buf.data(), static_cast<streamsize>(want));
        if (!out) {
            error = "write failed (disk full?)";
            return false;
        }
        got += want;
        if (progress) progress(got, size);
    }

    out.flush();
    return true;
}

bool Remote::stat(const string& name, uint64_t& size, string& tag,
                  bool& exists, string& error) {
    exists = false;
    if (!channel_->send_line(string(proto::kStat) + " " + name)) {
        error = "request failed";
        return false;
    }

    string reply;
    if (!channel_->read_line(reply)) {
        error = "no reply to STAT";
        return false;
    }

    const vector<string> f = proto::split(reply);
    if (!f.empty() && f[0] == proto::kNone) return true;
    if (f.size() != 3 || f[0] != proto::kMeta) {
        error = "unexpected STAT reply: " + reply;
        return false;
    }
    if (!proto::parse_size(f[1], config::kMaxTransferSize, size)) {
        error = "bad size in STAT reply";
        return false;
    }
    tag = (f[2] == "-") ? string() : f[2];
    exists = true;
    return true;
}

bool Remote::put_file(const string& name, const fs::path& source,
                      const string& dedup_tag, const ProgressFn& progress,
                      string& error) {
    error_code ec;
    const uint64_t size = static_cast<uint64_t>(fs::file_size(source, ec));
    if (ec) {
        error = "cannot size " + source.string();
        return false;
    }

    if (!channel_->send_line(string(proto::kPutFile) + " " + name + " " +
                             to_string(size) + " " +
                             (dedup_tag.empty() ? "-" : dedup_tag))) {
        error = "request failed";
        return false;
    }
    if (!send_file_body(source, size, progress, error)) return false;

    string reply;
    if (!channel_->read_line(reply)) {
        error = "no reply after upload";
        return false;
    }
    const vector<string> f = proto::split(reply);
    if (f.empty() || f[0] != proto::kOk) {
        error = "server refused the upload: " + reply;
        return false;
    }
    return true;
}

bool Remote::get_file(const string& name, const fs::path& destination,
                      bool& found, const ProgressFn& progress,
                      string& error) {
    found = false;
    if (!channel_->send_line(string(proto::kGetFile) + " " + name)) {
        error = "request failed";
        return false;
    }

    string reply;
    if (!channel_->read_line(reply)) {
        error = "no reply to GETFILE";
        return false;
    }

    const vector<string> f = proto::split(reply);
    if (!f.empty() && f[0] == proto::kNone) return true;
    if (f.size() != 2 || f[0] != proto::kData) {
        error = "unexpected GETFILE reply: " + reply;
        return false;
    }

    uint64_t size = 0;
    if (!proto::parse_size(f[1], config::kMaxTransferSize, size)) {
        error = "bad size in GETFILE reply";
        return false;
    }
    if (!read_body_to_file(destination, size, progress, error)) return false;

    found = true;
    return true;
}

bool Remote::put_chunk(const string& id, const fs::path& source,
                       string& error) {
    error_code ec;
    const uint64_t size = static_cast<uint64_t>(fs::file_size(source, ec));
    if (ec) {
        error = "cannot size " + source.string();
        return false;
    }

    if (!channel_->send_line(string(proto::kPutChunk) + " " + id + " " +
                             to_string(size))) {
        error = "request failed";
        return false;
    }
    if (!send_file_body(source, size, nullptr, error)) return false;

    string reply;
    if (!channel_->read_line(reply)) {
        error = "no reply after chunk upload";
        return false;
    }
    const vector<string> f = proto::split(reply);
    if (f.empty() || f[0] != proto::kOk) {
        error = "peer refused the chunk: " + reply;
        return false;
    }
    return true;
}

bool Remote::get_chunk(const string& id, const fs::path& destination,
                       bool& found, string& error) {
    found = false;
    if (!channel_->send_line(string(proto::kGetChunk) + " " + id)) {
        error = "request failed";
        return false;
    }

    string reply;
    if (!channel_->read_line(reply)) {
        error = "no reply to GETCHUNK";
        return false;
    }

    const vector<string> f = proto::split(reply);
    if (!f.empty() && f[0] == proto::kNone) return true;
    if (f.size() != 2 || f[0] != proto::kData) {
        error = "unexpected GETCHUNK reply: " + reply;
        return false;
    }

    uint64_t size = 0;
    if (!proto::parse_size(f[1], config::kMaxTransferSize, size)) {
        error = "bad size in GETCHUNK reply";
        return false;
    }
    if (!read_body_to_file(destination, size, nullptr, error)) return false;

    found = true;
    return true;
}

bool Remote::del_chunk(const string& id, string& error) {
    if (!channel_->send_line(string(proto::kDelChunk) + " " + id)) {
        error = "request failed";
        return false;
    }
    string reply;
    if (!channel_->read_line(reply)) {
        error = "no reply to DELCHUNK";
        return false;
    }
    const vector<string> f = proto::split(reply);
    if (f.empty() || f[0] != proto::kOk) {
        error = "peer refused the delete: " + reply;
        return false;
    }
    return true;
}

bool Remote::list(vector<pair<string, uint64_t>>& out,
                  string& error) {
    if (!channel_->send_line(proto::kList)) {
        error = "request failed";
        return false;
    }

    string reply;
    if (!channel_->read_line(reply)) {
        error = "no reply to LIST";
        return false;
    }

    const vector<string> head = proto::split(reply);
    if (head.size() != 2 || head[0] != proto::kCount) {
        error = "unexpected LIST reply: " + reply;
        return false;
    }

    uint64_t count = 0;
    if (!proto::parse_size(head[1], 1000000, count)) {
        error = "implausible file count";
        return false;
    }

    out.clear();
    out.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; i++) {
        string line;
        if (!channel_->read_line(line)) {
            error = "listing ended early";
            return false;
        }
        const vector<string> f = proto::split(line);
        if (f.size() != 2) continue;
        uint64_t size = 0;
        proto::parse_size(f[1], config::kMaxTransferSize, size);
        out.emplace_back(f[0], size);
    }
    return true;
}

}  // namespace client
}  // namespace pcs
