# Personal Cloud Storage

A server-first encrypted cloud storage system with peer-to-peer fallback. Files go directly to your server when it's online. When the server is down, files are encrypted, erasure-coded, and distributed across peer clients. As soon as the server comes back, pending files automatically sync back.

## How It Works

```
Server Online:
  File --> AES-256-CBC Encrypt (session key) --> Send to Server --> Server Decrypts --> Stored

Server Offline (Fallback):
  File --> AES-256-CBC Encrypt (passphrase) --> Split (k=2) --> Erasure Code (m=2) --> Distribute to 4 Peers

Sync-Back (Server Returns):
  Fetch from Peers --> Verify SHA-256 --> Erasure Recover --> Decrypt --> Upload to Server --> Cleanup Peers
```

## Architecture

### Client (`client.cpp`)

- **Direct upload**: encrypts with random session key, sends to server, server decrypts and stores
- **Fallback mode**: encrypts with passphrase, erasure-codes into 4 chunks, distributes to peers
- **Sync**: recovers from peers when server comes back, uploads decrypted file, cleans up chunks
- **Autosync**: background daemon that monitors server availability
- **Integrity**: SHA-256 verification on every chunk fetched from peers

### Server (`server.cpp`)

- Accepts direct file uploads (decrypts session-encrypted data, stores plaintext)
- Stores/serves erasure-coded chunks for peer fallback mode
- Supports PING health checks, LIST files, DELETE chunks

### Protocol

All commands except PING require authentication. Clients send `AUTH <token>\n` before the command.

```
PING\n                                          --> PONG\n
AUTH <token>\n                                  --> (proceed or AUTH_FAILED\n)
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

- **Transit encryption**: direct uploads encrypted with random AES-256 session key
- **Peer encryption**: fallback chunks are AES-256-CBC encrypted ciphertext fragments
- **Integrity**: SHA-256 hash verification on every chunk fetch
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
g++ -std=c++17 -o server server.cpp -lssl -lcrypto
g++ -std=c++17 -o client client.cpp -lssl -lcrypto
```

## Usage

### Start your server

```bash
./server 9000
```

### Upload a file (server online)

```bash
./client upload myfile.txt 192.168.1.100:9000
# File sent encrypted, server decrypts and stores it
```

### Upload a file (server offline — auto fallback)

```bash
./client upload myfile.txt 192.168.1.100:9000 peer1:9001 peer2:9002 peer3:9003 peer4:9004
# Detects server is down, asks for passphrase, distributes to peers
```

### Sync pending files when server returns

```bash
./client sync
# Asks for passphrase, recovers from peers, uploads to server, cleans up
```

### Auto-sync daemon

```bash
./client autosync 30
# Checks every 30 seconds, notifies when server is back
```

### Download a file

```bash
./client download myfile.txt 192.168.1.100:9000
# From server if online, from peers if offline
```

### List files on server

```bash
./client list 192.168.1.100:9000
```

## Project Structure

```
.
├── client.cpp          # Client: upload, download, sync, autosync, list
├── server.cpp          # Server: file storage, chunk storage, health check
├── CMakeLists.txt      # Build configuration
├── pending/            # Metadata for files waiting to sync to server
├── phase9/             # Prototype: local erasure coding (k=3, m=1)
├── phase10/            # Prototype: distributed erasure coding over TCP
└── phase11/            # Prototype: distributed reconstruction
```

## Known Limitations

- Key derivation uses raw SHA-256 (should be PBKDF2/Argon2 with salt)
- No authenticated encryption (CBC without HMAC — should be AES-GCM)
- Single-threaded server
- No chunk ID sanitization on server (path traversal risk)
- Entire file loaded into memory (no streaming)
- No user accounts, quotas, or access control
- No automatic peer discovery or NAT traversal
- Autosync detects server but requires manual `sync` for passphrase entry
