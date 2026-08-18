#pragma once

#include <string>
#include <vector>

#include "pcs/wire.hpp"
#include "store.hpp"

namespace pcs {
namespace server {

// Serves one connection until the client quits or the link drops. A session
// carries as many commands as the client wants; authentication is checked
// once and then remembered for the life of the connection.
class Session {
public:
    Session(Channel& channel, Store& store, std::string token, int port);

    void run();

private:
    bool handle(const std::string& line);

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
    std::string token_;
    int port_;
    bool authenticated_ = false;
};

// Serialised so that concurrent connections do not interleave their output.
void log_line(const std::string& text);

}  // namespace server
}  // namespace pcs
