#pragma once

#include <cstddef>
#include <cstdint>

// Compile-time layout constants shared by the client, the server and the
// tests. Nothing here allocates or depends on OpenSSL, so every other header
// is free to include it.
namespace pcs {
namespace config {

// Wire protocol identifier exchanged in the HELLO handshake.
inline constexpr char kProtocol[] = "pcs/2";

// --- Encrypted stream container -------------------------------------------
inline constexpr uint8_t  kStreamVersion = 1;
inline constexpr char     kStreamMagic[4] = {'P', 'C', 'S', '1'};

// Plaintext bytes sealed per AEAD block. Files are processed one block at a
// time so memory use stays flat no matter how large the file is.
inline constexpr uint32_t kBlockSize = 1u << 20;  // 1 MiB

inline constexpr size_t kIvLen   = 12;
inline constexpr size_t kTagLen  = 16;
inline constexpr size_t kKeyLen  = 32;
inline constexpr size_t kSaltLen = 16;

inline constexpr uint32_t kKdfIterations = 100000;

// Fixed context strings so the two derived keys never collide.
inline constexpr char kContentKeyLabel[] = "pcs-content-v1";
inline constexpr char kDedupKeyLabel[]   = "pcs-dedup-v1";

// --- Erasure layout --------------------------------------------------------
inline constexpr int kDataShards   = 2;
inline constexpr int kParityShards = 2;
inline constexpr int kTotalShards  = kDataShards + kParityShards;

// --- I/O -------------------------------------------------------------------
inline constexpr size_t kIoBufferSize    = 64 * 1024;
inline constexpr int    kConnectTimeoutS = 3;

// Longest control line accepted from the network, a guard against a peer
// streaming an unbounded "line" to exhaust memory.
inline constexpr size_t kMaxLineLen = 4096;

// Upper bound on any single declared transfer size. Sizes arrive as text
// from the network, so they are clamped before they can become an
// allocation or a disk reservation.
inline constexpr uint64_t kMaxTransferSize = 1ull << 40;  // 1 TiB

}  // namespace config
}  // namespace pcs
