#include "pcs/stream.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>

#include "pcs/cipher.hpp"
#include "pcs/config.hpp"
#include "pcs/digest.hpp"
#include "pcs/hex.hpp"

namespace fs = std::filesystem;

namespace pcs {
namespace {

// Fixed header: magic[4] version[1] iterations[4] salt[16] block[4] plain[8].
constexpr size_t kHeaderLen = 4 + 1 + 4 + config::kSaltLen + 4 + 8;

void put_u32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 0; i < 4; i++)
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
}

void put_u64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; i++)
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
}

uint32_t get_u32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= static_cast<uint32_t>(p[i]) << (8 * i);
    return v;
}

uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

std::vector<uint8_t> build_header(const StreamHeader& h) {
    std::vector<uint8_t> out;
    out.reserve(kHeaderLen);
    out.insert(out.end(), config::kStreamMagic, config::kStreamMagic + 4);
    out.push_back(config::kStreamVersion);
    put_u32(out, h.iterations);
    out.insert(out.end(), h.salt.begin(), h.salt.end());
    put_u32(out, h.block_size);
    put_u64(out, h.plain_size);
    return out;
}

bool parse_header(const std::vector<uint8_t>& raw, StreamHeader& out,
                  std::string& error) {
    if (raw.size() != kHeaderLen) {
        error = "truncated stream header";
        return false;
    }
    if (std::memcmp(raw.data(), config::kStreamMagic, 4) != 0) {
        error = "not a PCS stream (bad magic)";
        return false;
    }
    if (raw[4] != config::kStreamVersion) {
        error = "unsupported stream version";
        return false;
    }

    out.iterations = get_u32(raw.data() + 5);
    out.salt.assign(raw.begin() + 9, raw.begin() + 9 + config::kSaltLen);
    out.block_size = get_u32(raw.data() + 9 + config::kSaltLen);
    out.plain_size = get_u64(raw.data() + 13 + config::kSaltLen);

    if (out.block_size == 0 || out.block_size > 64u * 1024 * 1024) {
        error = "implausible block size in header";
        return false;
    }
    if (out.iterations == 0) {
        error = "invalid iteration count in header";
        return false;
    }
    return true;
}

// Each block is authenticated against the whole header plus its own index, so
// blocks cannot be reordered, duplicated or dropped without detection.
std::vector<uint8_t> block_aad(const std::vector<uint8_t>& header,
                               uint64_t index) {
    std::vector<uint8_t> aad = header;
    put_u64(aad, index);
    return aad;
}

uint64_t block_count(uint64_t plain_size, uint32_t block_size) {
    if (plain_size == 0) return 0;
    return (plain_size + block_size - 1) / block_size;
}

}  // namespace

bool seal_file(const fs::path& plain_path, const fs::path& stream_path,
               const std::string& passphrase, std::string* dedup_tag,
               const ProgressFn& progress, std::string& error) {
    std::error_code ec;
    if (!fs::exists(plain_path, ec) || !fs::is_regular_file(plain_path, ec)) {
        error = "not a readable file: " + plain_path.string();
        return false;
    }
    const uint64_t plain_size =
        static_cast<uint64_t>(fs::file_size(plain_path, ec));
    if (ec) {
        error = "cannot determine file size";
        return false;
    }

    std::ifstream in(plain_path, std::ios::binary);
    if (!in) {
        error = "cannot open " + plain_path.string();
        return false;
    }

    StreamHeader header;
    header.iterations = config::kKdfIterations;
    header.salt = random_bytes(config::kSaltLen);
    header.block_size = config::kBlockSize;
    header.plain_size = plain_size;
    if (header.salt.size() != config::kSaltLen) {
        error = "no entropy available for salt";
        return false;
    }

    const std::vector<uint8_t> key =
        derive_key(passphrase, header.salt, config::kContentKeyLabel,
                   header.iterations);
    if (key.size() != config::kKeyLen) {
        error = "key derivation failed";
        return false;
    }

    std::ofstream out(stream_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot write " + stream_path.string();
        return false;
    }

    const std::vector<uint8_t> raw_header = build_header(header);
    out.write(reinterpret_cast<const char*>(raw_header.data()),
              static_cast<std::streamsize>(raw_header.size()));

    HmacSha256 tagger(derive_dedup_key(passphrase));

    std::vector<uint8_t> block(header.block_size);
    uint64_t done = 0;
    uint64_t index = 0;

    while (done < plain_size) {
        const uint64_t want =
            std::min<uint64_t>(header.block_size, plain_size - done);
        in.read(reinterpret_cast<char*>(block.data()),
                static_cast<std::streamsize>(want));
        if (static_cast<uint64_t>(in.gcount()) != want) {
            error = "short read (did the file change while it was sealed?)";
            return false;
        }

        tagger.update(block.data(), static_cast<size_t>(want));

        const std::vector<uint8_t> iv = random_bytes(config::kIvLen);
        std::vector<uint8_t> cipher, tag;
        if (!aes_gcm_seal(key, iv, block_aad(raw_header, index), block.data(),
                          static_cast<size_t>(want), cipher, tag)) {
            error = "encryption failed";
            return false;
        }

        std::vector<uint8_t> length_le;
        put_u32(length_le, static_cast<uint32_t>(cipher.size()));

        out.write(reinterpret_cast<const char*>(iv.data()),
                  static_cast<std::streamsize>(iv.size()));
        out.write(reinterpret_cast<const char*>(length_le.data()), 4);
        out.write(reinterpret_cast<const char*>(cipher.data()),
                  static_cast<std::streamsize>(cipher.size()));
        out.write(reinterpret_cast<const char*>(tag.data()),
                  static_cast<std::streamsize>(tag.size()));
        if (!out) {
            error = "write failed (disk full?)";
            return false;
        }

        done += want;
        index++;
        if (progress) progress(done, plain_size);
    }

    out.flush();
    if (!out) {
        error = "write failed while flushing";
        return false;
    }
    if (progress && plain_size == 0) progress(0, 0);

    if (dedup_tag) *dedup_tag = to_hex(tagger.finish());
    return true;
}

bool open_file(const fs::path& stream_path, const fs::path& plain_path,
               const std::string& passphrase, const ProgressFn& progress,
               std::string& error) {
    std::ifstream in(stream_path, std::ios::binary);
    if (!in) {
        error = "cannot open " + stream_path.string();
        return false;
    }

    std::vector<uint8_t> raw_header(kHeaderLen);
    in.read(reinterpret_cast<char*>(raw_header.data()),
            static_cast<std::streamsize>(kHeaderLen));
    if (static_cast<size_t>(in.gcount()) != kHeaderLen) {
        error = "stream is too short to contain a header";
        return false;
    }

    StreamHeader header;
    if (!parse_header(raw_header, header, error)) return false;

    const std::vector<uint8_t> key =
        derive_key(passphrase, header.salt, config::kContentKeyLabel,
                   header.iterations);
    if (key.size() != config::kKeyLen) {
        error = "key derivation failed";
        return false;
    }

    std::ofstream out(plain_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        error = "cannot write " + plain_path.string();
        return false;
    }

    const uint64_t blocks = block_count(header.plain_size, header.block_size);
    uint64_t done = 0;
    bool ok = true;

    for (uint64_t index = 0; index < blocks && ok; index++) {
        std::vector<uint8_t> iv(config::kIvLen);
        uint8_t length_le[4];

        in.read(reinterpret_cast<char*>(iv.data()),
                static_cast<std::streamsize>(iv.size()));
        in.read(reinterpret_cast<char*>(length_le), 4);
        if (!in) {
            error = "stream ends in the middle of a block";
            ok = false;
            break;
        }

        const uint32_t cipher_len = get_u32(length_le);
        if (cipher_len > header.block_size) {
            error = "block claims to be larger than the header allows";
            ok = false;
            break;
        }

        std::vector<uint8_t> cipher(cipher_len);
        std::vector<uint8_t> tag(config::kTagLen);
        in.read(reinterpret_cast<char*>(cipher.data()),
                static_cast<std::streamsize>(cipher_len));
        in.read(reinterpret_cast<char*>(tag.data()),
                static_cast<std::streamsize>(tag.size()));
        if (!in) {
            error = "stream ends in the middle of a block";
            ok = false;
            break;
        }

        std::vector<uint8_t> plain;
        if (!aes_gcm_open(key, iv, block_aad(raw_header, index), cipher.data(),
                          cipher.size(), tag, plain)) {
            error = "authentication failed (wrong passphrase or altered data)";
            ok = false;
            break;
        }

        out.write(reinterpret_cast<const char*>(plain.data()),
                  static_cast<std::streamsize>(plain.size()));
        if (!out) {
            error = "write failed (disk full?)";
            ok = false;
            break;
        }

        done += plain.size();
        if (progress) progress(done, header.plain_size);
    }

    if (ok && done != header.plain_size) {
        error = "recovered size does not match the header";
        ok = false;
    }

    out.close();
    if (!ok) {
        // Never leave a half-decrypted file behind to be mistaken for a good
        // one.
        std::error_code ignored;
        fs::remove(plain_path, ignored);
        return false;
    }
    return true;
}

bool read_header(const fs::path& stream_path, StreamHeader& out,
                 std::string& error) {
    std::ifstream in(stream_path, std::ios::binary);
    if (!in) {
        error = "cannot open " + stream_path.string();
        return false;
    }
    std::vector<uint8_t> raw(kHeaderLen);
    in.read(reinterpret_cast<char*>(raw.data()),
            static_cast<std::streamsize>(kHeaderLen));
    if (static_cast<size_t>(in.gcount()) != kHeaderLen) {
        error = "stream is too short to contain a header";
        return false;
    }
    return parse_header(raw, out, error);
}

std::string dedup_tag_for_file(const fs::path& plain_path,
                               const std::string& passphrase) {
    std::ifstream in(plain_path, std::ios::binary);
    if (!in) return {};

    HmacSha256 tagger(derive_dedup_key(passphrase));
    std::vector<char> buf(config::kIoBufferSize);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize got = in.gcount();
        if (got > 0) tagger.update(buf.data(), static_cast<size_t>(got));
    }
    return to_hex(tagger.finish());
}

}  // namespace pcs
