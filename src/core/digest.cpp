#include "pcs/digest.hpp"

#include <fstream>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#else
#include <openssl/hmac.h>
#endif

#include "pcs/config.hpp"
#include "pcs/hex.hpp"

namespace pcs {

// --- SHA-256 ---------------------------------------------------------------

struct Sha256::Impl {
    EVP_MD_CTX* ctx = nullptr;
};

Sha256::Sha256() : impl_(new Impl) {
    impl_->ctx = EVP_MD_CTX_new();
    if (impl_->ctx) EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr);
}

Sha256::~Sha256() {
    if (impl_->ctx) EVP_MD_CTX_free(impl_->ctx);
}

void Sha256::update(const void* data, size_t len) {
    if (impl_->ctx && len > 0) EVP_DigestUpdate(impl_->ctx, data, len);
}

std::vector<uint8_t> Sha256::finish() {
    std::vector<uint8_t> out(32);
    if (!impl_->ctx) return out;
    unsigned int len = 0;
    EVP_DigestFinal_ex(impl_->ctx, out.data(), &len);
    out.resize(len);
    return out;
}

// --- HMAC-SHA256 -----------------------------------------------------------

struct HmacSha256::Impl {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC* mac = nullptr;
    EVP_MAC_CTX* ctx = nullptr;
#else
    HMAC_CTX* ctx = nullptr;
#endif
};

HmacSha256::HmacSha256(const std::vector<uint8_t>& key) : impl_(new Impl) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    impl_->mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!impl_->mac) return;
    impl_->ctx = EVP_MAC_CTX_new(impl_->mac);
    if (!impl_->ctx) return;

    char digest[] = "SHA256";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC_init(impl_->ctx, key.data(), key.size(), params);
#else
    impl_->ctx = HMAC_CTX_new();
    if (impl_->ctx)
        HMAC_Init_ex(impl_->ctx, key.data(), static_cast<int>(key.size()),
                     EVP_sha256(), nullptr);
#endif
}

HmacSha256::~HmacSha256() {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (impl_->ctx) EVP_MAC_CTX_free(impl_->ctx);
    if (impl_->mac) EVP_MAC_free(impl_->mac);
#else
    if (impl_->ctx) HMAC_CTX_free(impl_->ctx);
#endif
}

void HmacSha256::update(const void* data, size_t len) {
    if (!impl_->ctx || len == 0) return;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC_update(impl_->ctx, static_cast<const unsigned char*>(data), len);
#else
    HMAC_Update(impl_->ctx, static_cast<const unsigned char*>(data), len);
#endif
}

std::vector<uint8_t> HmacSha256::finish() {
    std::vector<uint8_t> out(32);
    if (!impl_->ctx) return out;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    size_t len = 0;
    EVP_MAC_final(impl_->ctx, out.data(), &len, out.size());
    out.resize(len);
#else
    unsigned int len = 0;
    HMAC_Final(impl_->ctx, out.data(), &len);
    out.resize(len);
#endif
    return out;
}

// --- convenience -----------------------------------------------------------

std::vector<uint8_t> sha256(const void* data, size_t len) {
    Sha256 h;
    h.update(data, len);
    return h.finish();
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    return sha256(data.data(), data.size());
}

std::string sha256_hex(const std::vector<uint8_t>& data) {
    return to_hex(sha256(data));
}

std::string sha256_file_hex(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};

    Sha256 h;
    std::vector<char> buf(config::kIoBufferSize);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize got = in.gcount();
        if (got > 0) h.update(buf.data(), static_cast<size_t>(got));
    }
    return to_hex(h.finish());
}

bool secure_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace pcs
