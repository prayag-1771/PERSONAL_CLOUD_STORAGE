#include "webui.hpp"

#include <algorithm>
#include <fstream>
#include <vector>

#include "page.hpp"
#include "pcs/cipher.hpp"
#include "pcs/config.hpp"
#include "pcs/hex.hpp"
#include "pcs/safename.hpp"
#include "session.hpp"

using namespace std;

namespace fs = std::filesystem;

namespace pcs {
namespace server {
namespace {

// Long enough to be workable, short enough that a forgotten open tab does
// not stay usable indefinitely.
constexpr int kSessionMinutes = 120;

// Raw string literals throughout, so the JSON here contains no escape
// sequences to misread.
string json_error(const string& message) {
    return R"({"error":")" + json_escape(message) + R"("})";
}

}  // namespace

string BrowserSessions::create(const string& user) {
    const string token = to_hex(random_bytes(32));

    lock_guard<mutex> guard(mutex_);
    expire_locked();
    entries_[token] = Entry{user, chrono::steady_clock::now() +
                                      chrono::minutes(kSessionMinutes)};
    return token;
}

bool BrowserSessions::lookup(const string& token, string& user) {
    if (token.empty()) return false;

    lock_guard<mutex> guard(mutex_);
    expire_locked();

    const map<string, Entry>::const_iterator it = entries_.find(token);
    if (it == entries_.end()) return false;
    user = it->second.user;
    return true;
}

void BrowserSessions::destroy(const string& token) {
    lock_guard<mutex> guard(mutex_);
    entries_.erase(token);
}

void BrowserSessions::expire_locked() {
    const chrono::steady_clock::time_point now = chrono::steady_clock::now();
    for (map<string, Entry>::iterator it = entries_.begin();
         it != entries_.end();) {
        it = it->second.expires <= now ? entries_.erase(it) : next(it);
    }
}

WebUi::WebUi(Store& store, const UserStore& users)
    : store_(store), users_(users) {}

bool WebUi::authenticate(const HttpRequest& request, string& user) {
    const string header = request.header("authorization");
    const string prefix = "Bearer ";
    if (header.rfind(prefix, 0) != 0) return false;
    return sessions_.lookup(header.substr(prefix.size()), user);
}

bool WebUi::handle(Channel& channel, const HttpRequest& request) {
    const string& path = request.path;

    if (request.method == "GET" && (path == "/" || path == "/index.html"))
        return serve_page(channel);

    if (request.method == "POST" && path == "/api/login")
        return serve_login(channel, request);

    if (request.method == "POST" && path == "/api/logout")
        return serve_logout(channel, request);

    string user;
    if (path.rfind("/api/", 0) == 0 && !authenticate(request, user)) {
        drain_body(channel, request.content_length);
        send_response(channel, 401, "application/json",
                      json_error("not signed in"));
        return true;
    }

    if (request.method == "GET" && path == "/api/files")
        return serve_list(channel, user);

    const string files_prefix = "/api/files/";
    if (path.rfind(files_prefix, 0) == 0) {
        const string name = path.substr(files_prefix.size());
        if (request.method == "GET") return serve_get_file(channel, user, name);
        if (request.method == "PUT")
            return serve_put_file(channel, request, user, name);
        if (request.method == "DELETE")
            return serve_delete_file(channel, user, name);
    }

    drain_body(channel, request.content_length);
    send_response(channel, 404, "application/json", json_error("no such route"));
    return true;
}

bool WebUi::serve_page(Channel& channel) {
    return send_response(channel, 200, "text/html; charset=utf-8", web_page());
}

bool WebUi::serve_login(Channel& channel, const HttpRequest& request) {
    if (request.content_length > config::kMaxLineLen) {
        drain_body(channel, request.content_length);
        return send_response(channel, 400, "application/json",
                             json_error("request too large"));
    }

    string body(static_cast<size_t>(request.content_length), '\0');
    if (request.content_length > 0 && !channel.recv(&body[0], body.size()))
        return false;

    string user, password;
    if (!json_field(body, "user", user) ||
        !json_field(body, "password", password)) {
        return send_response(channel, 400, "application/json",
                             json_error("missing user or password"));
    }

    if (!users_.verify(user, password)) {
        log_line("[web] sign-in rejected for " + user);
        return send_response(channel, 401, "application/json",
                             json_error("wrong account or password"));
    }

    string error;
    if (!store_.ensure_account(user, error)) {
        return send_response(channel, 500, "application/json",
                             json_error("cannot prepare storage"));
    }

    const string token = sessions_.create(user);
    log_line("[web] " + user + " signed in");
    return send_response(channel, 200, "application/json",
                         R"({"token":")" + json_escape(token) +
                             R"(","user":")" + json_escape(user) + R"("})");
}

bool WebUi::serve_logout(Channel& channel, const HttpRequest& request) {
    const string header = request.header("authorization");
    const string prefix = "Bearer ";
    if (header.rfind(prefix, 0) == 0)
        sessions_.destroy(header.substr(prefix.size()));

    drain_body(channel, request.content_length);
    return send_response(channel, 200, "application/json", R"({"ok":true})");
}

bool WebUi::serve_list(Channel& channel, const string& user) {
    vector<pair<string, uint64_t>> files;
    {
        lock_guard<mutex> guard(store_.mutex());
        files = store_.list_files(user);
    }

    string body = R"({"files":[)";
    for (size_t i = 0; i < files.size(); i++) {
        if (i) body += ",";
        body += R"({"name":")" + json_escape(files[i].first) +
                R"(","size":)" + to_string(files[i].second) + "}";
    }
    body += "]}";

    return send_response(channel, 200, "application/json", body);
}

bool WebUi::serve_get_file(Channel& channel, const string& user,
                           const string& name) {
    fs::path path;
    uint64_t size = 0;
    {
        lock_guard<mutex> guard(store_.mutex());
        path = store_.file_path(user, name);
        string tag;
        if (path.empty() || !store_.file_info(user, name, size, tag)) {
            return send_response(channel, 404, "application/json",
                                 json_error("no such file"));
        }
    }

    // What goes out is the sealed stream. The browser opens it with the
    // passphrase; the server has no way to.
    if (!send_header(channel, 200, "application/octet-stream", size))
        return false;

    ifstream in(path, ios::binary);
    if (!in) return false;

    vector<char> buf(config::kIoBufferSize);
    uint64_t left = size;
    while (left > 0) {
        const size_t want = static_cast<size_t>(min<uint64_t>(buf.size(), left));
        in.read(buf.data(), static_cast<streamsize>(want));
        if (static_cast<size_t>(in.gcount()) != want) return false;
        if (!channel.send(buf.data(), want)) return false;
        left -= want;
    }
    return true;
}

bool WebUi::serve_delete_file(Channel& channel, const string& user,
                              const string& name) {
    bool removed = false;
    {
        lock_guard<mutex> guard(store_.mutex());
        removed = store_.remove_file(user, name);
    }

    if (!removed) {
        return send_response(channel, 404, "application/json",
                             json_error("no such file"));
    }

    log_line("[web] " + user + " deleted " + name);
    return send_response(channel, 200, "application/json", R"({"ok":true})");
}

bool WebUi::serve_put_file(Channel& channel, const HttpRequest& request,
                           const string& user, const string& name) {
    const fs::path final_path =
        is_safe_name(name) ? store_.file_path(user, name) : fs::path();
    if (final_path.empty()) {
        drain_body(channel, request.content_length);
        return send_response(channel, 400, "application/json",
                             json_error("that name cannot be stored"));
    }

    const fs::path temp = store_.temp_path();
    {
        ofstream out(temp, ios::binary | ios::trunc);
        if (!out) return false;

        vector<char> buf(config::kIoBufferSize);
        uint64_t left = request.content_length;
        while (left > 0) {
            const size_t want =
                static_cast<size_t>(min<uint64_t>(buf.size(), left));
            if (!channel.recv(buf.data(), want)) {
                error_code ec;
                fs::remove(temp, ec);
                return false;
            }
            out.write(buf.data(), static_cast<streamsize>(want));
            left -= want;
        }
        out.flush();
        if (!out) {
            error_code ec;
            fs::remove(temp, ec);
            return send_response(channel, 500, "application/json",
                                 json_error("write failed"));
        }
    }

    // The deduplication tag is computed in the browser and sent alongside,
    // for the same reason the command-line client sends one: the server can
    // match identical uploads without learning anything about the contents.
    string tag;
    const string marker = "tag=";
    const size_t at = request.query.find(marker);
    if (at != string::npos) tag = request.query.substr(at + marker.size());

    {
        lock_guard<mutex> guard(store_.mutex());
        error_code ec;
        fs::rename(temp, final_path, ec);
        if (ec) {
            fs::remove(temp, ec);
            return send_response(channel, 500, "application/json",
                                 json_error("cannot store the file"));
        }
        store_.write_tag(user, name, tag);
    }

    log_line("[web] " + user + " stored " + name + " (" +
             to_string(request.content_length) + " bytes, encrypted)");
    return send_response(channel, 201, "application/json", R"({"ok":true})");
}

}  // namespace server
}  // namespace pcs
