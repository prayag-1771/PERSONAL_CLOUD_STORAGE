# Personal Cloud Storage

A distributed, encrypted, erasure-coded personal cloud storage system. Every connected device acts as both a client and a storage node — you use the network, you contribute to the network.

## How It Works

```
Upload:
  File --> AES-256-CBC Encrypt --> Split (k=2 chunks) --> Erasure Code (m=2 parities) --> Distribute to 4 peers

Download:
  Fetch from peers --> Erasure Recover (tolerates 2 missing) --> Reassemble --> AES-256-CBC Decrypt --> File
```

Data is encrypted before leaving your machine, split into chunks, and distributed across peer devices. Even if 2 of 4 peers go offline, your data is fully recoverable.

No peer ever sees your plaintext data. No single peer holds enough to reconstruct anything.

## Architecture

### Client (`client.cpp`)

Handles upload and download with:

- **AES-256-CBC encryption** with passphrase-derived key and random IV
- **Erasure coding** (k=2 data, m=2 parity) using GF(2^8) arithmetic for true redundancy
- **Content-addressed chunk IDs** via full SHA-256 hashes (collision-proof)
- **Metadata file** (`.ecmeta`) stores IV, chunk mappings, and server addresses

#### Recovery Matrix

The system generates 4 chunks from your file. Any 2 of 4 are enough to recover:

| Available Chunks | Recovery Method |
|---|---|
| d0 + d1 | Direct reassembly |
| d0 + P0 | `d1 = d0 XOR P0` |
| d1 + P0 | `d0 = d1 XOR P0` |
| d0 + P1 | `d1 = GF_inv(3) * (P1 XOR 2*d0)` |
| d1 + P1 | `d0 = GF_inv(2) * (P1 XOR 3*d1)` |
| P0 + P1 | `d1 = P1 XOR 2*P0`, then `d0 = P0 XOR d1` |

### Server (`server.cpp`)

A lightweight TCP chunk storage daemon. Each peer runs one.

- Stores and serves chunks by ID
- Simple text protocol: `PUT <id> <size>` and `FETCH <id>`
- Chunks stored on disk at `storage/server_<port>/chunks/`

## Dependencies

- C++17 compiler (g++ or clang++)
- OpenSSL (libssl-dev / openssl-devel)
- CMake 3.10+ (optional, can compile directly)

## Build

```bash
# With CMake
mkdir build && cd build
cmake ..
cmake --build .

# Or directly
g++ -std=c++17 -o server server.cpp
g++ -std=c++17 -o client client.cpp -lssl -lcrypto
```

## Usage

### Start storage nodes (on 4 devices/ports)

```bash
./server 9000
./server 9001
./server 9002
./server 9003
```

### Upload a file

```bash
./client upload myfile.txt 127.0.0.1:9000 127.0.0.1:9001 127.0.0.1:9002 127.0.0.1:9003
# Enter passphrase when prompted
# Creates myfile.txt.ecmeta (keep this safe)
```

### Download a file

```bash
./client download myfile.txt
# Enter same passphrase
# Recovers even if 2 of 4 servers are down
```

## Project Structure

```
.
├── client.cpp          # Main client: encrypt, split, distribute, recover
├── server.cpp          # Chunk storage server
├── CMakeLists.txt      # Build configuration
├── phase9/             # Prototype: local erasure coding (k=3, m=1)
├── phase10/            # Prototype: distributed erasure coding over TCP
└── phase11/            # Prototype: distributed reconstruction
```

## Protocol

```
# Store a chunk
PUT <chunk_id> <size_in_bytes>\n
<raw bytes>

# Retrieve a chunk
FETCH <chunk_id>\n

# Server response to FETCH
<size_in_bytes>\n
<raw bytes>
```

## Metadata Format (`.ecmeta`)

```
<original_file_size>
<iv_length>
<iv_bytes>
<k> <m>
<index> <chunk_hash> <server_address>
<index> <chunk_hash> <server_address>
...
```

## Security Model

- Files are AES-256-CBC encrypted locally before any network transfer
- Each chunk is a fragment of ciphertext — meaningless without the key and other chunks
- Chunk IDs are SHA-256 hashes of content (no metadata leakage)
- Passphrase never leaves the client

## Known Limitations

- Key derivation uses raw SHA-256 (should be PBKDF2/Argon2 with salt)
- No authenticated encryption (CBC without HMAC — should be AES-GCM)
- No error checking on crypto return values
- Single-threaded server (one connection at a time)
- No chunk ID sanitization on server (path traversal risk)
- Entire file loaded into memory (no streaming)
- No user accounts, quotas, or access control
- No automatic peer discovery or NAT traversal