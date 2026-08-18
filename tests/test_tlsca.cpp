#include "harness.hpp"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>

#include "pcs/tlsca.hpp"
#include "tempdir.hpp"

using namespace std;
using namespace pcs;
using pcstest::TempDir;

namespace {

X509* read_cert(const filesystem::path& path) {
    FILE* file = fopen(path.string().c_str(), "rb");
    if (!file) return nullptr;
    X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    return cert;
}

// Verifies a leaf against a CA exactly the way a client does.
bool chains_to(const filesystem::path& leaf_path,
               const filesystem::path& ca_path) {
    X509* leaf = read_cert(leaf_path);
    X509* ca = read_cert(ca_path);
    if (!leaf || !ca) {
        if (leaf) X509_free(leaf);
        if (ca) X509_free(ca);
        return false;
    }

    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, ca);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, leaf, nullptr);

    const bool ok = X509_verify_cert(ctx) == 1;

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(leaf);
    X509_free(ca);
    return ok;
}

bool covers_host(const filesystem::path& leaf_path, const string& host) {
    X509* leaf = read_cert(leaf_path);
    if (!leaf) return false;
    const bool ok =
        looks_like_ip(host)
            ? X509_check_ip_asc(leaf, host.c_str(), 0) == 1
            : X509_check_host(leaf, host.c_str(), host.size(), 0, nullptr) == 1;
    X509_free(leaf);
    return ok;
}

}  // namespace

PCS_TEST(ip_literals_are_told_apart_from_names) {
    CHECK(looks_like_ip("127.0.0.1"));
    CHECK(looks_like_ip("192.168.1.10"));
    CHECK(looks_like_ip("::1"));
    CHECK(!looks_like_ip("localhost"));
    CHECK(!looks_like_ip("my-laptop.local"));
    CHECK(!looks_like_ip("999.1.1.1"));
    CHECK(!looks_like_ip(""));
}

PCS_TEST(the_ca_is_created_once_and_then_reused) {
    TempDir dir;
    const auto cert = dir.file("ca.crt");
    const auto key = dir.file("ca.key");

    string error;
    CHECK(ensure_ca(cert.string(), key.string(), error));
    CHECK(filesystem::exists(cert));
    CHECK(filesystem::exists(key));

    const auto original = pcstest::read_all(cert);

    // Reissuing would invalidate every copy already installed on a device,
    // so a second call has to leave the existing authority alone.
    CHECK(ensure_ca(cert.string(), key.string(), error));
    CHECK(pcstest::read_all(cert) == original);
}

PCS_TEST(an_issued_certificate_chains_to_the_ca) {
    TempDir dir;
    const auto ca_cert = dir.file("ca.crt");
    const auto ca_key = dir.file("ca.key");
    const auto cert = dir.file("server.crt");
    const auto key = dir.file("server.key");

    string error;
    CHECK(ensure_ca(ca_cert.string(), ca_key.string(), error));
    CHECK(issue_server_cert(ca_cert.string(), ca_key.string(), cert.string(),
                            key.string(),
                            {"localhost", "127.0.0.1", "my-laptop.local"},
                            error));

    CHECK(chains_to(cert, ca_cert));
}

PCS_TEST(a_certificate_covers_every_name_it_was_issued_for) {
    TempDir dir;
    const auto ca_cert = dir.file("ca.crt");
    const auto ca_key = dir.file("ca.key");
    const auto cert = dir.file("server.crt");
    const auto key = dir.file("server.key");

    string error;
    CHECK(ensure_ca(ca_cert.string(), ca_key.string(), error));
    CHECK(issue_server_cert(ca_cert.string(), ca_key.string(), cert.string(),
                            key.string(),
                            {"localhost", "127.0.0.1", "192.168.1.10"}, error));

    // Names and addresses live in different parts of the certificate, so
    // both kinds have to be checked.
    CHECK(covers_host(cert, "localhost"));
    CHECK(covers_host(cert, "127.0.0.1"));
    CHECK(covers_host(cert, "192.168.1.10"));

    // Anything it was not issued for must not be accepted.
    CHECK(!covers_host(cert, "someone-else.local"));
    CHECK(!covers_host(cert, "10.0.0.5"));
}

PCS_TEST(a_certificate_from_another_ca_does_not_chain) {
    TempDir mine, theirs;

    string error;
    CHECK(ensure_ca(mine.file("ca.crt").string(), mine.file("ca.key").string(),
                    error));
    CHECK(ensure_ca(theirs.file("ca.crt").string(),
                    theirs.file("ca.key").string(), error));

    CHECK(issue_server_cert(theirs.file("ca.crt").string(),
                            theirs.file("ca.key").string(),
                            theirs.file("server.crt").string(),
                            theirs.file("server.key").string(), {"localhost"},
                            error));

    // This is the impersonation case: a certificate for the right name, from
    // the wrong authority, must be refused.
    CHECK(covers_host(theirs.file("server.crt"), "localhost"));
    CHECK(!chains_to(theirs.file("server.crt"), mine.file("ca.crt")));
}

PCS_TEST(reissue_is_requested_when_a_host_is_missing) {
    TempDir dir;
    const auto ca_cert = dir.file("ca.crt");
    const auto ca_key = dir.file("ca.key");
    const auto cert = dir.file("server.crt");
    const auto key = dir.file("server.key");

    string error;
    CHECK(ensure_ca(ca_cert.string(), ca_key.string(), error));
    CHECK(issue_server_cert(ca_cert.string(), ca_key.string(), cert.string(),
                            key.string(), {"localhost", "127.0.0.1"}, error));

    CHECK(!server_cert_needs_reissue(cert.string(), {"localhost"}, 30));
    CHECK(!server_cert_needs_reissue(cert.string(), {"localhost", "127.0.0.1"}, 30));

    // A newly added address is not covered yet, so it has to be reissued.
    CHECK(server_cert_needs_reissue(cert.string(), {"192.168.1.50"}, 30));

    // A missing certificate always needs issuing.
    CHECK(server_cert_needs_reissue(dir.file("absent.crt").string(),
                                    {"localhost"}, 30));

    // And one that would expire inside the window.
    CHECK(server_cert_needs_reissue(cert.string(), {"localhost"}, 100000));
}
