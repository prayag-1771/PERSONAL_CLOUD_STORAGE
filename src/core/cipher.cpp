#include "pcs/cipher.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "pcs/config.hpp"

using namespace std;

namespace pcs {
namespace {

// Wraps EVP_CIPHER_CTX so that every early return still frees it.
struct CipherCtx {
    CipherCtx() = default;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    ~CipherCtx() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
    CipherCtx(const CipherCtx&) = delete;
    CipherCtx& operator=(const CipherCtx&) = delete;
    explicit operator bool() const { return ctx != nullptr; }
};

}  // namespace

vector<uint8_t> derive_key(const string& passphrase,
                                const vector<uint8_t>& salt,
                                const string& label,
                                uint32_t iterations) {
    // The label is prefixed to the salt so that two different purposes never
    // share a key, even when passphrase and salt are identical.
    vector<uint8_t> full;
    full.reserve(label.size() + salt.size());
    full.insert(full.end(), label.begin(), label.end());
    full.insert(full.end(), salt.begin(), salt.end());

    vector<uint8_t> key(config::kKeyLen);
    if (PKCS5_PBKDF2_HMAC(passphrase.data(),
                          static_cast<int>(passphrase.size()),
                          full.data(), static_cast<int>(full.size()),
                          static_cast<int>(iterations), EVP_sha256(),
                          static_cast<int>(key.size()), key.data()) != 1) {
        return {};
    }
    return key;
}

vector<uint8_t> derive_dedup_key(const string& passphrase) {
    // A fixed salt, deliberately: the tag has to be reproducible across files
    // and across runs, otherwise deduplication could never match anything.
    const string label = config::kDedupKeyLabel;
    vector<uint8_t> salt(label.begin(), label.end());
    return derive_key(passphrase, salt, label, config::kKdfIterations);
}

vector<uint8_t> random_bytes(size_t n) {
    vector<uint8_t> out(n);
    if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1) return {};
    return out;
}

bool aes_gcm_seal(const vector<uint8_t>& key,
                  const vector<uint8_t>& iv,
                  const vector<uint8_t>& aad,
                  const uint8_t* plain, size_t plain_len,
                  vector<uint8_t>& out,
                  vector<uint8_t>& tag) {
    if (key.size() != config::kKeyLen || iv.size() != config::kIvLen) return false;

    CipherCtx c;
    if (!c) return false;

    if (EVP_EncryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return false;
    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1)
        return false;
    if (EVP_EncryptInit_ex(c.ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        return false;

    int len = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(c.ctx, nullptr, &len, aad.data(),
                          static_cast<int>(aad.size())) != 1)
        return false;

    out.resize(plain_len);
    int written = 0;
    if (plain_len > 0 &&
        EVP_EncryptUpdate(c.ctx, out.data(), &written, plain,
                          static_cast<int>(plain_len)) != 1)
        return false;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(c.ctx, out.data() + written, &final_len) != 1)
        return false;
    out.resize(static_cast<size_t>(written) + static_cast<size_t>(final_len));

    tag.resize(config::kTagLen);
    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1)
        return false;
    return true;
}

bool aes_gcm_open(const vector<uint8_t>& key,
                  const vector<uint8_t>& iv,
                  const vector<uint8_t>& aad,
                  const uint8_t* cipher, size_t cipher_len,
                  const vector<uint8_t>& tag,
                  vector<uint8_t>& out) {
    if (key.size() != config::kKeyLen || iv.size() != config::kIvLen) return false;
    if (tag.size() != config::kTagLen) return false;

    CipherCtx c;
    if (!c) return false;

    if (EVP_DecryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return false;
    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1)
        return false;
    if (EVP_DecryptInit_ex(c.ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        return false;

    int len = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(c.ctx, nullptr, &len, aad.data(),
                          static_cast<int>(aad.size())) != 1)
        return false;

    out.resize(cipher_len);
    int written = 0;
    if (cipher_len > 0 &&
        EVP_DecryptUpdate(c.ctx, out.data(), &written, cipher,
                          static_cast<int>(cipher_len)) != 1)
        return false;

    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<uint8_t*>(tag.data())) != 1)
        return false;

    int final_len = 0;
    // A non-positive result here is the authentication failure: wrong key,
    // wrong AAD, or modified ciphertext. Never return partial plaintext.
    if (EVP_DecryptFinal_ex(c.ctx, out.data() + written, &final_len) <= 0) {
        out.clear();
        return false;
    }
    out.resize(static_cast<size_t>(written) + static_cast<size_t>(final_len));
    return true;
}

}  // namespace pcs
