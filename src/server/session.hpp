#pragma once

#include <string>
#include <vector>

#include "pcs/wire.hpp"
#include "store.hpp"
#include "users.hpp"

namespace pcs {
namespace server {

// Serves one connection until the client quits or the link drops.
//
// A connection establishes up to two independent things. LOGIN identifies an
// account and scopes every file command to it. AUTH presents the shared
// machine token and unlocks only the chunk commands, which is all a peer
// needs in order to hold shards for somebody. Neither implies the other.
class Session {
public:
    Session(Channel& channel, Store& store, const UserStore& users,
            std::string token, int port);

    void run();

private:
    bool handle(const std::string& line);

    bool do_login(const std::vector<std::string>& fields);
    bool do_auth(const std::vector<std::string>& fields);
    bool do_stat(const std::vector<std::string>& fields);
    bool do_put_file(const std::vector<std::string>& fields);
    bool do_get_file(const std::vector<std::string>& fields);
    bool do_put_chunk(const std::vector<std::string>& fields);
    bool do_get_chunk(const std::vector<std::string>& fields);
    bool do_del_chunk(const std::vector<std::string>& fields);
    bool do_list();

    bool fail(const std::string& reason);

    Channel& channel_;
    Store& store_;
    const UserStore& users_;
    std::string token_;
    int port_;

    std::string user_;            // set by a successful LOGIN
    bool logged_in_ = false;      // may use the file commands
    bool machine_trusted_ = false;// may use the chunk commands
};

// Serialised so concurrent connections do not interleave their output.
void log_line(const std::string& text);

}  // namespace server
}  // namespace pcs
