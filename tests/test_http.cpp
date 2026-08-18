#include "harness.hpp"

#include "http.hpp"

using namespace std;
using namespace pcs;
using namespace pcs::server;

PCS_TEST(http_requests_are_told_apart_from_our_own_protocol) {
    // This is what lets one port serve the browser and the client.
    CHECK(looks_like_http("GET / HTTP/1.1"));
    CHECK(looks_like_http("POST /api/login HTTP/1.1"));
    CHECK(looks_like_http("PUT /api/files/x HTTP/1.1"));
    CHECK(looks_like_http("DELETE /x HTTP/1.1"));

    CHECK(!looks_like_http("HELLO pcs/3"));
    CHECK(!looks_like_http("PING"));
    CHECK(!looks_like_http("AUTH abc"));
    CHECK(!looks_like_http("GETFILE holiday.jpg"));  // ours, not HTTP GET
    CHECK(!looks_like_http(""));
    CHECK(!looks_like_http("GET"));                  // no space, not a request
}

PCS_TEST(json_escaping_covers_the_awkward_characters) {
    CHECK_EQ(json_escape("plain"), string("plain"));
    CHECK_EQ(json_escape("say " + string(1, char(34)) + "hi"),
             string("say ") + char(92) + char(34) + "hi");
    CHECK_EQ(json_escape(string(1, char(92))), string() + char(92) + char(92));
    CHECK_EQ(json_escape("a\nb"), string("a") + char(92) + "nb");
    CHECK_EQ(json_escape("a\tb"), string("a") + char(92) + "tb");

    // A control character has to become an escape, not travel through raw.
    const string escaped = json_escape(string(1, char(1)));
    CHECK_EQ(escaped, string() + char(92) + "u0001");
}

PCS_TEST(json_fields_are_read_from_the_page_requests) {
    const char q = 34;
    const string body = string() + "{" + q + "user" + q + ":" + q + "alice" +
                        q + "," + q + "password" + q + ":" + q + "secret" + q +
                        "}";

    string value;
    CHECK(json_field(body, "user", value));
    CHECK_EQ(value, string("alice"));
    CHECK(json_field(body, "password", value));
    CHECK_EQ(value, string("secret"));

    CHECK(!json_field(body, "missing", value));
    CHECK(!json_field("not json at all", "user", value));
    CHECK(!json_field("", "user", value));
}

PCS_TEST(json_field_reading_handles_escapes_and_bad_input) {
    const char q = 34;
    const char b = 92;

    // A quote inside the value must not end it early.
    const string body = string() + "{" + q + "name" + q + ":" + q + "he said " +
                        b + q + "hi" + b + q + q + "}";
    string value;
    CHECK(json_field(body, "name", value));
    CHECK_EQ(value, string("he said ") + q + "hi" + q);

    // An unterminated value is rejected rather than returning a partial one.
    const string truncated = string() + "{" + q + "name" + q + ":" + q + "abc";
    CHECK(!json_field(truncated, "name", value));
}

PCS_TEST(header_lookup_is_case_insensitive) {
    HttpRequest request;
    request.headers["content-length"] = "42";
    request.headers["authorization"] = "Bearer abc";

    CHECK_EQ(request.header("Content-Length"), string("42"));
    CHECK_EQ(request.header("CONTENT-LENGTH"), string("42"));
    CHECK_EQ(request.header("authorization"), string("Bearer abc"));
    CHECK_EQ(request.header("missing"), string());
}
