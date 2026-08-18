#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace pcs {

// Incremental SHA-256. The OpenSSL context is hidden behind a pimpl so that
// no other translation unit has to see <openssl/...>.
class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    void update(const void* data, size_t len);
    std::vector<uint8_t> finish();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Incremental HMAC-SHA256, used for the keyed deduplication tag.
class HmacSha256 {
public:
    explicit HmacSha256(const std::vector<uint8_t>& key);
    ~HmacSha256();
    HmacSha256(const HmacSha256&) = delete;
    HmacSha256& operator=(const HmacSha256&) = delete;

    void update(const void* data, size_t len);
    std::vector<uint8_t> finish();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::vector<uint8_t> sha256(const void* data, size_t len);
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
std::string sha256_hex(const std::vector<uint8_t>& data);

// Streams the file so arbitrarily large files hash in constant memory.
// Returns an empty string if the file cannot be read.
std::string sha256_file_hex(const std::filesystem::path& path);

// Constant-time comparison, for auth tokens and dedup tags.
bool secure_equal(const std::string& a, const std::string& b);

}  // namespace pcs
