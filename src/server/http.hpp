#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "pcs/wire.hpp"

// Just enough HTTP/1.1 to serve one page and the handful of endpoints it
// calls. This is not a general purpose server: it answers the requests the
// bundled web client makes, and refuses everything else.
namespace pcs {
namespace server {

struct HttpRequest {
    std::string method;
    std::string path;   // percent-decoded, without the query string
    std::string query;
    std::map<std::string, std::string> headers;  // keys lowercased
    uint64_t content_length = 0;

    // The body is deliberately left on the socket: an upload can be
    // gigabytes, so a handler streams it rather than being handed a buffer.
    std::string header(const std::string& name) const;
};

// True when a line looks like the start of an HTTP request rather than the
// HELLO of our own protocol. That is how one port serves both.
bool looks_like_http(const std::string& first_line);

// Parses the request line and headers; `first_line` has already been read.
bool read_request(Channel& channel, const std::string& first_line,
                  HttpRequest& out, std::string& error);

// Reads and discards a body the handler does not want.
bool drain_body(Channel& channel, uint64_t length);

bool send_response(Channel& channel, int status,
                   const std::string& content_type, const std::string& body,
                   const std::vector<std::string>& extra_headers = {});

// Sends the status line and headers for a body the caller streams next.
bool send_header(Channel& channel, int status, const std::string& content_type,
                 uint64_t content_length,
                 const std::vector<std::string>& extra_headers = {});

std::string json_escape(const std::string& text);

// Pulls one string field out of a small flat JSON object. Written for the
// two or three fields the page actually sends, not as a general parser.
bool json_field(const std::string& body, const std::string& name,
                std::string& out);

}  // namespace server
}  // namespace pcs
