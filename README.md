# Personal Cloud Storage

Turn your laptop into your own Google Photos / cloud drive. A server-first encrypted storage system with peer-to-peer fallback. Files go directly to your server (your laptop) when it's online. When the server is down, files are encrypted, erasure-coded, and distributed across peer clients. As soon as the server comes back, pending files automatically sync back.

## How It Works

```
Server Online:
  File --> Dedup Check --> AES-256-GCM Encrypt (session key) --> TLS --> Server Decrypts --> Stored

Server Offline (Fallback):
  File --> PBKDF2 Key --> AES-256-GCM Encrypt --> Split (k=2) --> Erasure Code (m=2) --> TLS --> Distribute to 4 Peers

Sync-Back (Server Returns):
  TLS --> Fetch from Peers --> Verify SHA-256 --> Erasure Recover --> Decrypt --> Upload to Server --> Cleanup Peers
```

## Architecture

### Client (`client.cpp`)

- **Direct upload**: encrypts with random session key, sends to server over TLS, server decrypts and stores
- **Deduplication**: checks SHA-256 hash with server before uploading — skips if identical content exists
- **Fallback mode**: encrypts with PBKDF2-derived key, erasure-codes into 4 chunks, distributes to peers
- **Sync**: recovers from peers when server comes back, uploads decrypted file, cleans up chunks
- **Autosync**: background daemon that monitors server availability
- **Integrity**: SHA-256 verification on every chunk fetched from peers
- **Progress**: visual progress bar for uploads and downloads
- **Authentication**: token-based auth for all server operations

### Server (`server.cpp`)

- **Multithreaded**: handles multiple concurrent clients via thread-per-connection
- **TLS**: all connections encrypted with auto-generated self-signed certificate
- **Authentication**: token-based access control (token auto-generated on first run)
- **Deduplication**: CHECK_HASH command to detect duplicate uploads
- **Input sanitization**: chunk ID and filename validation to prevent path traversal
- Accepts direct file uploads (decrypts session-encrypted data, stores plaintext)
- Stores/serves erasure-coded chunks for peer fallback mode
- Supports PING health checks, LIST files, DELETE chunks

### Protocol

All connections use TLS. All commands except PING require authentication via `AUTH <token>\n`.

```
PING\n                                          --> PONG\n
AUTH <token>\n                                  --> (proceed or AUTH_FAILED\n)
CHECK_HASH <filename> <sha256>\n                --> EXISTS\n or SEND\n
UPLOAD <filename> <size> <key_hex> <iv_hex>\n   --> OK\n
  <encrypted bytes>
PUT <chunk_id> <size>\n
  <raw bytes>
FETCH <chunk_id>\n                              --> <size>\n<raw bytes>
FETCH_FILE <filename>\n                         --> <size>\n<raw bytes>
DELETE <chunk_id>\n                             --> OK\n
LIST\n                                          --> <name>\n...\nEND\n
```

### Erasure Coding Recovery Matrix

Any 2 of 4 chunks are enough to recover:

| Available Chunks | Recovery Method |
|---|---|
| d0 + d1 | Direct reassembly |
| d0 + P0 | `d1 = d0 XOR P0` |
| d1 + P0 | `d0 = d1 XOR P0` |
| d0 + P1 | `d1 = GF_inv(3) * (P1 XOR 2*d0)` |
| d1 + P1 | `d0 = GF_inv(2) * (P1 XOR 3*d1)` |
| P0 + P1 | `d1 = P1 XOR 2*P0`, then `d0 = P0 XOR d1` |

## Security

- **TLS transport**: all client-server communication encrypted via TLS (self-signed cert auto-generated)
- **Authentication**: 64-char hex token required for all operations (except health checks)
- **AES-256-GCM**: authenticated encryption with 12-byte IV and 16-byte auth tag — detects tampering
- **PBKDF2-HMAC-SHA256**: passphrase key derivation with 100,000 iterations and random salt (per file)
- **Input sanitization**: path traversal protection on all filename/chunk ID inputs
- **Integrity**: SHA-256 hash verification on every chunk fetch from peers
- **Deduplication**: content-hash check prevents redundant uploads
- **No plaintext passphrase storage**: passphrase asked at sync/download time, never saved to disk

## Dependencies

- C++17 compiler (g++ or clang++)
- OpenSSL (libssl-dev / openssl-devel)
- CMake 3.10+

## Build

```bash
mkdir build && cd build
cmake ..
cmake --build .

# Or directly
g++ -std=c++17 -o server server.cpp -lssl -lcrypto -lpthread
g++ -std=c++17 -o client client.cpp -lssl -lcrypto
```

## Usage

### Start your server

```bash
./server 9000
# Prints auth token on first run — save it for client use
```

### Upload a file (server online)

```bash
./client --token <token> upload myfile.txt 192.168.1.100:9000
# Checks for duplicates, then sends encrypted over TLS
```

### Upload a file (server offline — auto fallback)

```bash
./client --token <token> upload myfile.txt 192.168.1.100:9000 peer1:9001 peer2:9002 peer3:9003 peer4:9004
# Detects server is down, asks for passphrase, distributes to peers
```

### Sync pending files when server returns

```bash
./client --token <token> sync
# Asks for passphrase, recovers from peers, uploads to server, cleans up
```

### Auto-sync daemon

```bash
./client --token <token> autosync 30
# Checks every 30 seconds, notifies when server is back
```

### Download a file

```bash
./client --token <token> download myfile.txt 192.168.1.100:9000
# From server if online, from peers if offline
```

### List files on server

```bash
./client --token <token> list 192.168.1.100:9000
```

## Project Structure

```
.
├── client.cpp          # Client: upload, download, sync, autosync, list
├── server.cpp          # Server: multithreaded TLS file/chunk storage
├── CMakeLists.txt      # Build configuration
└── .gitignore          # Ignore build artifacts, certs, tokens, test files
```

## Known Limitations

- Entire file loaded into memory (no streaming for very large files)
- No user accounts, quotas, or access control (single-user / personal use)
- No automatic peer discovery or NAT traversal
- Autosync detects server but requires manual `sync` for passphrase entry
- Self-signed TLS cert (not CA-signed — fine for personal/LAN use)
- No web UI or mobile client yet


Limitations -