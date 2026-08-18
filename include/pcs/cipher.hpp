#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pcs {

// PBKDF2-HMAC-SHA256. `label` is mixed into the salt so that one passphrase
// yields independent keys for different purposes.
std::vector<uint8_t> derive_key(const std::string& passphrase,
                                const std::vector<uint8_t>& salt,
                                const std::string& label,
                                uint32_t iterations);

// Deterministic key for the deduplication tag: same passphrase and content
// always produce the same tag, while a server without the passphrase cannot
// test a guess against stored content.
std::vector<uint8_t> derive_dedup_key(const std::string& passphrase);

std::vector<uint8_t> random_bytes(size_t n);

// AES-256-GCM. `aad` is authenticated but not encrypted. On success `out`
// holds the ciphertext and `tag` the 16-byte authentication tag.
bool aes_gcm_seal(const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  const std::vector<uint8_t>& aad,
                  const uint8_t* plain, size_t plain_len,
                  std::vector<uint8_t>& out,
                  std::vector<uint8_t>& tag);

// Returns false when the tag does not verify, which is the signal that the
// key is wrong or the data was tampered with.
bool aes_gcm_open(const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& iv,
                  const std::vector<uint8_t>& aad,
                  const uint8_t* cipher, size_t cipher_len,
                  const std::vector<uint8_t>& tag,
                  std::vector<uint8_t>& out);

}  // namespace pcs
