#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <string>

#include "http.hpp"
#include "pcs/wire.hpp"
#include "store.hpp"
#include "users.hpp"

namespace pcs {
namespace server {

// Browser sessions. A password is exchanged once for a random bearer token,
// so it is not resent with every request, and the token expires on its own.
//
// The encryption passphrase never appears here. It stays in the page, is used
// there to seal and open files, and is never sent to the server: what arrives
// over these endpoints is already ciphertext.
class BrowserSessions {
public:
    std::string create(const std::string& user);
    bool lookup(const std::string& token, std::string& user);
    void destroy(const std::string& token);

private:
    struct Entry {
        std::string user;
        std::chrono::steady_clock::time_point expires;
    };

    void expire_locked();

    std::map<std::string, Entry> entries_;
    std::mutex mutex_;
};

// Serves the web client and its endpoints over an established TLS channel.
// One instance is shared by every connection.
class WebUi {
public:
    WebUi(Store& store, const UserStore& users);

    // Handles one request. Returns false when the connection should close.
    bool handle(Channel& channel, const HttpRequest& request);

private:
    bool serve_page(Channel& channel);
    bool serve_login(Channel& channel, const HttpRequest& request);
    bool serve_logout(Channel& channel, const HttpRequest& request);
    bool serve_list(Channel& channel, const std::string& user);
    bool serve_get_file(Channel& channel, const std::string& user,
                        const std::string& name);
    bool serve_put_file(Channel& channel, const HttpRequest& request,
                        const std::string& user, const std::string& name);

    bool authenticate(const HttpRequest& request, std::string& user);

    Store& store_;
    const UserStore& users_;
    BrowserSessions sessions_;
};

}  // namespace server
}  // namespace pcs
