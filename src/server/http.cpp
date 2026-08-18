#include "http.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>

#include "pcs/config.hpp"
#include "pcs/protocol.hpp"

using namespace std;

namespace pcs {
namespace server {
namespace {

// Spelled numerically so no escape sequence can be misread.
constexpr char kBackslash = 92;
constexpr char kQuote = 34;

const char* status_text(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 500: return "Internal Server Error";
        default:  return "Error";
    }
}

string lowercase(string text) {
    transform(text.begin(), text.end(), text.begin(),
              [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return text;
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

// Percent-decoding, so a file name with a space or an accent survives the
// round trip through a URL.
string url_decode(const string& text) {
    string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); i++) {
        if (text[i] == '%' && i + 2 < text.size()) {
            const int hi = hex_digit(text[i + 1]);
            const int lo = hex_digit(text[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(text[i] == '+' ? ' ' : text[i]);
    }
    return out;
}

}  // namespace

string HttpRequest::header(const string& name) const {
    const map<string, string>::const_iterator it = headers.find(lowercase(name));
    return it == headers.end() ? string() : it->second;
}

bool looks_like_http(const string& first_line) {
    static const char* kMethods[] = {"GET ",    "POST ", "PUT ",
                                     "DELETE ", "HEAD ", "OPTIONS "};
    for (const char* method : kMethods)
        if (first_line.rfind(method, 0) == 0) return true;
    return false;
}

bool read_request(Channel& channel, const string& first_line, HttpRequest& out,
                  string& error) {
    const vector<string> parts = proto::split(first_line);
    if (parts.size() != 3) {
        error = "malformed request line";
        return false;
    }

    out.method = parts[0];

    string target = parts[1];
    const size_t question = target.find('?');
    if (question != string::npos) {
        out.query = target.substr(question + 1);
        target = target.substr(0, question);
    }
    out.path = url_decode(target);

    // Headers, until the blank line.
    size_t count = 0;
    while (true) {
        string line;
        if (!channel.read_line(line)) {
            error = "connection closed inside the headers";
            return false;
        }
        if (line.empty()) break;

        if (++count > 64) {
            error = "too many headers";
            return false;
        }

        const size_t colon = line.find(':');
        if (colon == string::npos) continue;

        const string name = lowercase(line.substr(0, colon));
        string value = line.substr(colon + 1);
        const size_t first = value.find_first_not_of(" \t");
        value = first == string::npos ? string() : value.substr(first);
        out.headers[name] = value;
    }

    const string length = out.header("content-length");
    if (!length.empty() &&
        !proto::parse_size(length, config::kMaxTransferSize,
                           out.content_length)) {
        error = "bad content-length";
        return false;
    }
    return true;
}

bool drain_body(Channel& channel, uint64_t length) {
    vector<char> buf(config::kIoBufferSize);
    while (length > 0) {
        const size_t want =
            static_cast<size_t>(min<uint64_t>(buf.size(), length));
        if (!channel.recv(buf.data(), want)) return false;
        length -= want;
    }
    return true;
}

bool send_header(Channel& channel, int status, const string& content_type,
                 uint64_t content_length,
                 const vector<string>& extra_headers) {
    string head = "HTTP/1.1 " + to_string(status) + " " + status_text(status);
    head += "\r\n";
    head += "Content-Type: " + content_type + "\r\n";
    head += "Content-Length: " + to_string(content_length) + "\r\n";

    // The page does its own encryption and is served on a local network;
    // these stop a browser doing anything clever with it in between.
    head += "Cache-Control: no-store\r\n";
    head += "X-Content-Type-Options: nosniff\r\n";
    head += "Referrer-Policy: no-referrer\r\n";

    for (const string& extra : extra_headers) head += extra + "\r\n";
    head += "\r\n";

    return channel.send(head.data(), head.size());
}

bool send_response(Channel& channel, int status, const string& content_type,
                   const string& body, const vector<string>& extra_headers) {
    if (!send_header(channel, status, content_type, body.size(), extra_headers))
        return false;
    if (body.empty()) return true;
    return channel.send(body.data(), body.size());
}

string json_escape(const string& text) {
    string out;
    out.reserve(text.size() + 8);
    for (unsigned char c : text) {
        if (c == kQuote || c == static_cast<unsigned char>(kBackslash)) {
            out.push_back(kBackslash);
            out.push_back(static_cast<char>(c));
        } else if (c == 10) {
            out.push_back(kBackslash);
            out.push_back('n');
        } else if (c == 13) {
            out.push_back(kBackslash);
            out.push_back('r');
        } else if (c == 9) {
            out.push_back(kBackslash);
            out.push_back('t');
        } else if (c < 0x20) {
            char buf[8];
            snprintf(buf, sizeof(buf), "%c%c%04x", kBackslash, 'u', c);
            out += buf;
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

bool json_field(const string& body, const string& name, string& out) {
    const string key = string(1, kQuote) + name + string(1, kQuote);
    size_t at = body.find(key);
    if (at == string::npos) return false;

    at = body.find(':', at + key.size());
    if (at == string::npos) return false;

    at = body.find(kQuote, at + 1);
    if (at == string::npos) return false;
    at++;

    string value;
    while (at < body.size() && body[at] != kQuote) {
        if (body[at] == kBackslash && at + 1 < body.size()) {
            at++;
            switch (body[at]) {
                case 'n': value.push_back(10); break;
                case 'r': value.push_back(13); break;
                case 't': value.push_back(9); break;
                default:  value.push_back(body[at]);
            }
        } else {
            value.push_back(body[at]);
        }
        at++;
        if (value.size() > config::kMaxLineLen) return false;
    }
    if (at >= body.size()) return false;

    out = value;
    return true;
}

}  // namespace server
}  // namespace pcs
