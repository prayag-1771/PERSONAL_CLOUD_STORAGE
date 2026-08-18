#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

// The on-disk / on-wire encrypted container. A file is sealed one block at a
// time, so encrypting a 4 GB video costs the same memory as a 4 KB note.
//
//   header : magic[4] version[1] iterations[4] salt[16]
//            block_size[4] plain_size[8]
//   block  : iv[12] length[4] ciphertext[length] tag[16]
//
// Every block is sealed with the full header plus its own block index as
// additional authenticated data. That binds each block to its position and to
// the declared plaintext size, so a reordered, duplicated or truncated stream
// fails to open rather than decrypting to something plausible.
namespace pcs {

struct StreamHeader {
    uint32_t iterations = 0;
    std::vector<uint8_t> salt;
    uint32_t block_size = 0;
    uint64_t plain_size = 0;
};

// Reports bytes processed out of the total, for the progress bar.
using ProgressFn = std::function<void(uint64_t done, uint64_t total)>;

// Seals `plain_path` into `stream_path`. When `dedup_tag` is non-null it
// receives the keyed tag of the plaintext, computed during the same pass.
bool seal_file(const std::filesystem::path& plain_path,
               const std::filesystem::path& stream_path,
               const std::string& passphrase,
               std::string* dedup_tag,
               const ProgressFn& progress,
               std::string& error);

// Opens `stream_path` into `plain_path`. Fails if any block's tag does not
// verify, and removes the partial output so a failed decrypt never leaves a
// half-written file behind.
bool open_file(const std::filesystem::path& stream_path,
               const std::filesystem::path& plain_path,
               const std::string& passphrase,
               const ProgressFn& progress,
               std::string& error);

// Reads just the header, without needing the passphrase.
bool read_header(const std::filesystem::path& stream_path,
                 StreamHeader& out, std::string& error);

// Computes the keyed dedup tag of a plaintext file in one streaming pass.
std::string dedup_tag_for_file(const std::filesystem::path& plain_path,
                               const std::string& passphrase);

}  // namespace pcs
