#include "pcs/tlsca.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "pcs/wire.hpp"

using namespace std;

namespace pcs {
namespace {

// Ten years for the authority, so installing it on a phone is a one-off.
constexpr long kCaLifetimeSeconds = 10L * 365 * 24 * 3600;

// Apple enforces an 825-day ceiling on TLS certificates even when the root
// was installed by hand, so anything longer would simply be rejected on an
// iPhone. Staying under it keeps one certificate valid on every device.
constexpr long kLeafLifetimeSeconds = 820L * 24 * 3600;

string ssl_error_text() {
    const unsigned long code = ERR_get_error();
    if (code == 0) return "unknown TLS error";
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    return string(buf);
}

// Frees an OpenSSL object on the way out of any return path.
template <typename T, void (*Free)(T*)>
struct Owned {
    T* ptr = nullptr;
    explicit Owned(T* p = nullptr) : ptr(p) {}
    ~Owned() { if (ptr) Free(ptr); }
    Owned(const Owned&) = delete;
    Owned& operator=(const Owned&) = delete;
    T* release() { T* p = ptr; ptr = nullptr; return p; }
    explicit operator bool() const { return ptr != nullptr; }
};

using OwnedKey  = Owned<EVP_PKEY, EVP_PKEY_free>;
using OwnedCert = Owned<X509, X509_free>;

EVP_PKEY* generate_key() {
    EVP_PKEY* key = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

// A random serial, which is what a certificate authority is expected to use.
bool set_random_serial(X509* cert) {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) return false;
    bytes[0] &= 0x7F;  // keep it positive

    Owned<BIGNUM, BN_free> value(BN_bin2bn(bytes, sizeof(bytes), nullptr));
    if (!value) return false;
    return BN_to_ASN1_INTEGER(value.ptr, X509_get_serialNumber(cert)) != nullptr;
}

void set_name_entry(X509_NAME* name, const char* field, const string& value) {
    X509_NAME_add_entry_by_txt(
        name, field, MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(value.c_str()), -1, -1, 0);
}

bool add_extension(X509* cert, X509V3_CTX* ctx, int nid, const string& value) {
    X509_EXTENSION* ext =
        X509V3_EXT_conf_nid(nullptr, ctx, nid, value.c_str());
    if (!ext) return false;
    const bool ok = X509_add_ext(cert, ext, -1) == 1;
    X509_EXTENSION_free(ext);
    return ok;
}

bool write_key(const string& path, EVP_PKEY* key) {
    FILE* file = fopen(path.c_str(), "wb");
    if (!file) return false;
    const bool ok = PEM_write_PrivateKey(file, key, nullptr, nullptr, 0,
                                         nullptr, nullptr) == 1;
    fclose(file);
    return ok;
}

bool write_cert(const string& path, X509* cert) {
    FILE* file = fopen(path.c_str(), "wb");
    if (!file) return false;
    const bool ok = PEM_write_X509(file, cert) == 1;
    fclose(file);
    return ok;
}

EVP_PKEY* read_key(const string& path) {
    FILE* file = fopen(path.c_str(), "rb");
    if (!file) return nullptr;
    EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return key;
}

X509* read_cert(const string& path) {
    FILE* file = fopen(path.c_str(), "rb");
    if (!file) return nullptr;
    X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    return cert;
}

}  // namespace

bool looks_like_ip(const string& host) {
    unsigned char scratch[16];
    if (inet_pton(AF_INET, host.c_str(), scratch) == 1) return true;
    return inet_pton(AF_INET6, host.c_str(), scratch) == 1;
}

vector<string> local_host_identities() {
    vector<string> hosts = {"localhost", "127.0.0.1", "::1"};

    char name[256];
    if (gethostname(name, sizeof(name)) == 0) {
        name[sizeof(name) - 1] = '\0';
        hosts.push_back(name);

        // Whatever the hostname resolves to is how other machines on the
        // network will most likely address this one.
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* results = nullptr;
        if (getaddrinfo(name, nullptr, &hints, &results) == 0) {
            for (addrinfo* it = results; it != nullptr; it = it->ai_next) {
                char text[INET6_ADDRSTRLEN] = {0};
                if (it->ai_family == AF_INET) {
                    sockaddr_in* v4 = reinterpret_cast<sockaddr_in*>(it->ai_addr);
                    inet_ntop(AF_INET, &v4->sin_addr, text, sizeof(text));
                } else if (it->ai_family == AF_INET6) {
                    sockaddr_in6* v6 =
                        reinterpret_cast<sockaddr_in6*>(it->ai_addr);
                    inet_ntop(AF_INET6, &v6->sin6_addr, text, sizeof(text));
                }
                if (text[0] != '\0') hosts.push_back(text);
            }
            freeaddrinfo(results);
        }
    }

    sort(hosts.begin(), hosts.end());
    hosts.erase(unique(hosts.begin(), hosts.end()), hosts.end());
    return hosts;
}

bool ensure_ca(const string& ca_cert_path, const string& ca_key_path,
               string& error) {
    net_startup();

    {
        // Reusing an existing authority matters: reissuing it would
        // invalidate every copy already installed on somebody's device.
        OwnedCert existing(read_cert(ca_cert_path));
        OwnedKey existing_key(read_key(ca_key_path));
        if (existing && existing_key) return true;
    }

    OwnedKey key(generate_key());
    if (!key) {
        error = "cannot generate a CA key: " + ssl_error_text();
        return false;
    }

    OwnedCert cert(X509_new());
    if (!cert) {
        error = "cannot allocate the CA certificate";
        return false;
    }

    X509_set_version(cert.ptr, 2);  // v3
    if (!set_random_serial(cert.ptr)) {
        error = "cannot set a serial number";
        return false;
    }
    X509_gmtime_adj(X509_getm_notBefore(cert.ptr), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.ptr), kCaLifetimeSeconds);
    X509_set_pubkey(cert.ptr, key.ptr);

    X509_NAME* subject = X509_get_subject_name(cert.ptr);
    set_name_entry(subject, "CN", "Personal Cloud Storage local CA");
    set_name_entry(subject, "O", "Personal Cloud Storage");
    X509_set_issuer_name(cert.ptr, subject);  // self-signed

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.ptr, cert.ptr, nullptr, nullptr, 0);

    if (!add_extension(cert.ptr, &ctx, NID_basic_constraints,
                       "critical,CA:TRUE,pathlen:0") ||
        !add_extension(cert.ptr, &ctx, NID_key_usage,
                       "critical,keyCertSign,cRLSign") ||
        !add_extension(cert.ptr, &ctx, NID_subject_key_identifier, "hash")) {
        error = "cannot add the CA extensions: " + ssl_error_text();
        return false;
    }

    if (X509_sign(cert.ptr, key.ptr, EVP_sha256()) <= 0) {
        error = "cannot sign the CA certificate: " + ssl_error_text();
        return false;
    }

    if (!write_cert(ca_cert_path, cert.ptr) || !write_key(ca_key_path, key.ptr)) {
        error = "cannot write the CA files";
        return false;
    }
    return true;
}

bool issue_server_cert(const string& ca_cert_path, const string& ca_key_path,
                       const string& cert_path, const string& key_path,
                       const vector<string>& hosts, string& error) {
    net_startup();

    OwnedCert ca_cert(read_cert(ca_cert_path));
    OwnedKey ca_key(read_key(ca_key_path));
    if (!ca_cert || !ca_key) {
        error = "cannot read the CA files";
        return false;
    }

    if (hosts.empty()) {
        error = "no host names to issue a certificate for";
        return false;
    }

    OwnedKey key(generate_key());
    if (!key) {
        error = "cannot generate a server key: " + ssl_error_text();
        return false;
    }

    OwnedCert cert(X509_new());
    if (!cert) {
        error = "cannot allocate the server certificate";
        return false;
    }

    X509_set_version(cert.ptr, 2);
    if (!set_random_serial(cert.ptr)) {
        error = "cannot set a serial number";
        return false;
    }
    X509_gmtime_adj(X509_getm_notBefore(cert.ptr), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.ptr), kLeafLifetimeSeconds);
    X509_set_pubkey(cert.ptr, key.ptr);

    X509_NAME* subject = X509_get_subject_name(cert.ptr);
    set_name_entry(subject, "CN", hosts.front());
    set_name_entry(subject, "O", "Personal Cloud Storage");
    X509_set_issuer_name(cert.ptr, X509_get_subject_name(ca_cert.ptr));

    // Browsers ignore the common name entirely, so the subject alternative
    // names are the only thing that decides which addresses this is valid for.
    string san;
    for (const string& host : hosts) {
        if (!san.empty()) san += ",";
        san += (looks_like_ip(host) ? "IP:" : "DNS:") + host;
    }

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert.ptr, cert.ptr, nullptr, nullptr, 0);

    if (!add_extension(cert.ptr, &ctx, NID_basic_constraints,
                       "critical,CA:FALSE") ||
        !add_extension(cert.ptr, &ctx, NID_key_usage,
                       "critical,digitalSignature,keyEncipherment") ||
        !add_extension(cert.ptr, &ctx, NID_ext_key_usage, "serverAuth") ||
        !add_extension(cert.ptr, &ctx, NID_subject_alt_name, san) ||
        !add_extension(cert.ptr, &ctx, NID_subject_key_identifier, "hash") ||
        !add_extension(cert.ptr, &ctx, NID_authority_key_identifier,
                       "keyid:always")) {
        error = "cannot add the certificate extensions: " + ssl_error_text();
        return false;
    }

    if (X509_sign(cert.ptr, ca_key.ptr, EVP_sha256()) <= 0) {
        error = "cannot sign the server certificate: " + ssl_error_text();
        return false;
    }

    if (!write_cert(cert_path, cert.ptr) || !write_key(key_path, key.ptr)) {
        error = "cannot write the server certificate or key";
        return false;
    }
    return true;
}

bool server_cert_needs_reissue(const string& cert_path,
                               const vector<string>& hosts, int days_left) {
    net_startup();

    OwnedCert cert(read_cert(cert_path));
    if (!cert) return true;

    // Reissue before it lapses rather than after, so the server never comes
    // up serving something already expired.
    const ASN1_TIME* expiry = X509_get0_notAfter(cert.ptr);
    int days = 0;
    int seconds = 0;
    if (ASN1_TIME_diff(&days, &seconds, nullptr, expiry) != 1) return true;
    if (days < days_left) return true;

    // A host added since the certificate was issued would not be covered.
    for (const string& host : hosts) {
        const bool covered =
            looks_like_ip(host)
                ? X509_check_ip_asc(cert.ptr, host.c_str(), 0) == 1
                : X509_check_host(cert.ptr, host.c_str(), host.size(), 0,
                                  nullptr) == 1;
        if (!covered) return true;
    }
    return false;
}

}  // namespace pcs
