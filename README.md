# Personal Cloud Storage

Turn a machine you own into your own encrypted cloud drive. Files are
encrypted on your side before they go anywhere, and the server only ever
holds ciphertext. When the server is up, files go straight to it. When it is
down, each file is split into four pieces and spread across peer machines;
any two pieces are enough to put it back together. Once the server returns,
pending files are forwarded automatically.

## What it does

```
Server up
  file -> seal (AES-256-GCM, key from your passphrase) -> TLS -> stored sealed

Server down
  file -> seal -> split into d0,d1 + parity p0,p1 -> TLS -> four peers
                                                          + local manifest

Server back
  manifest -> fetch any 2 shards -> rebuild the sealed stream -> TLS -> server
```

The last step never decrypts anything. The shards hold a sealed stream and
the server stores sealed streams, so forwarding is a straight ciphertext
relay. That is what lets `autosync` run unattended: **syncing needs no
passphrase**.

## Layout

```
include/pcs/      public headers for the shared core
src/core/         the core itself, one concern per unit
src/server/       store, session, entry point
src/client/       remote, workspace, one file per command
tests/            unit tests, plus an end-to-end script
```

### Core (`src/core`)

| Unit | Responsibility |
|---|---|
| `hex` | hex encoding, and rejecting malformed hex from the wire |
| `digest` | SHA-256 and HMAC-SHA256, incremental and whole-file |
| `cipher` | AES-256-GCM seal/open, PBKDF2 key derivation |
| `gf256` | GF(2^8) arithmetic |
| `erasure` | parity construction and the six recovery rules |
| `stream` | the sealed container, one block at a time |
| `shardfile` | splitting a stream into shards and rejoining it |
| `wire` | TLS transport, with the platform socket API confined here |
| `protocol` | one definition of the wire grammar, shared by both ends |
| `manifest` | the record of a file waiting to reach the server |
| `passwd` | account password verifiers |
| `tlsca` | the local certificate authority |
| `keysource` | where the passphrase comes from |
| `safename` | what may become a path |
| `progress` | the progress bar |

OpenSSL is an implementation detail: it appears in `src/core`, and nowhere
else in the tree.

## The sealed container

```
header   magic[4] version[1] iterations[4] salt[16] block_size[4] plain_size[8]
block    iv[12] length[4] ciphertext[length] tag[16]        (repeated)
```

A file is sealed one 1 MiB block at a time, so memory use is flat regardless
of file size: a 60 MB upload peaks around 10 MB of resident memory, and a
60 GB one would look the same.

Each block is authenticated against **the whole header plus its own block
index**. Reordering, duplicating or dropping a block therefore fails to open
rather than decrypting into something plausible, and since the header carries
the plaintext length, truncation is caught too.

Two keys are derived from your passphrase with PBKDF2-HMAC-SHA256 at 100,000
iterations, separated by a label:

- the **content key**, from a random per-file salt
- the **dedup key**, from a fixed salt, so the same content always produces
  the same tag

The deduplication tag is `HMAC-SHA256(dedup key, plaintext)`. The server can
tell that a re-upload is identical to what it already has, without learning
the plaintext or its hash.

## Erasure coding

The sealed stream is halved into `d0` and `d1`, and two parity shards follow:

```
p0 = d0 XOR d1
p1 = (2 . d0) XOR (3 . d1)          . is GF(2^8) multiplication
```

Any two of the four rebuild both halves:

| Available | Recovery |
|---|---|
| d0, d1 | straight copy |
| d0, p0 | `d1 = d0 XOR p0` |
| d1, p0 | `d0 = d1 XOR p0` |
| d0, p1 | `d1 = inv(3) . (p1 XOR 2.d0)` |
| d1, p1 | `d0 = inv(2) . (p1 XOR 3.d1)` |
| p0, p1 | `d1 = p1 XOR 2.p0`, then `d0 = p0 XOR d1` |

Every shard is named by its own SHA-256, and a shard whose contents do not
match its name is discarded rather than used.

## Protocol

One connection carries as many commands as the client wants.

```
-> HELLO pcs/2                    <- OK pcs/2
-> PING                           <- PONG                        (no auth)
-> AUTH <token>                   <- OK | ERR <reason>
   -- everything below requires a successful AUTH --
-> STAT <name>                    <- META <size> <tag> | NONE
-> PUTFILE <name> <size> <tag>    <- OK           then <size> raw bytes
-> GETFILE <name>                 <- DATA <size> | NONE  then raw bytes
   -- chunk commands: require AUTH --
-> PUTCHUNK <id> <size>           <- OK           then <size> raw bytes
-> GETCHUNK <id>                  <- DATA <size> | NONE  then raw bytes
-> DELCHUNK <id>                  <- OK
-> LIST                           <- COUNT <n>, then n lines "<name> <size>"
-> QUIT                           <- BYE
```

`PING` stays outside authentication on purpose: deciding whether to fall back
to peers should not cost a token round trip.

## Building

Needs a C++17 compiler, OpenSSL, and CMake 3.16+.

Built and tested against g++ 13.3 with OpenSSL 3.0 on Linux. There is a
fallback path for OpenSSL 1.1.1 in `src/core/digest.cpp`, but it has not been
compiled against that version, so treat 1.1.1 as unverified.

```bash
cmake -S . -B build
cmake --build build
```

That produces `build/pcs-server`, `build/pcs-client` and `build/pcs-tests`.

The socket layer has a Winsock path so the tree can build on Windows, and
everything above that layer is platform-neutral. That path has not been
compiled yet, though, so a native Windows build should be expected to need
some fixing. WSL is the tested route on a Windows machine.

## Using it

Every machine in a peer group needs the same token, since peers hold shards
for one another.

### Run your server

```bash
./build/pcs-server 9000
# prints the auth token on first run; it is kept in
# storage/server_9000/auth.token
```

### Store a file

```bash
export PCS_TOKEN=<token>
./build/pcs-client upload holiday.jpg 192.168.1.10:9000
# asks for a passphrase, encrypts locally, uploads the ciphertext
```

If the server is down, name four peers and the pieces go there instead:

```bash
./build/pcs-client upload holiday.jpg 192.168.1.10:9000 \
    192.168.1.11:9000 192.168.1.12:9000 192.168.1.13:9000 192.168.1.14:9000
```

### Get it back

```bash
./build/pcs-client download holiday.jpg 192.168.1.10:9000
./build/pcs-client download holiday.jpg 192.168.1.10:9000 /tmp/copy.jpg
```

Works whether the file is on the server or still scattered across peers.

### Forward what is pending

```bash
./build/pcs-client sync             # once, now
./build/pcs-client autosync 30      # keep watching, every 30s
```

Neither asks for a passphrase.

### See what is stored

```bash
./build/pcs-client list 192.168.1.10:9000
```

### Options

| Option | Meaning |
|---|---|
| `--token <token>` | server token, or set `PCS_TOKEN` |
| `--keyfile <path>` | read the passphrase from a file instead of prompting |
| `--dir <path>` | where pending files are tracked (default: `.`) |
| `--quiet` | no progress bars |

`PCS_PASSPHRASE` works too. Prompted entry does not echo.

## Testing

```bash
./build/pcs-tests            # 43 unit tests
ctest --test-dir build       # the same, through CTest
tests/e2e.sh build           # 22 checks against the running binaries
```

The unit tests cover the algorithms; `e2e.sh` starts real servers and checks
what only a running system shows, including peer fallback, parity-only
recovery, passphrase-free syncing, unattended autosync, and that a 60 MB
upload does not balloon memory.

## What the security model does and does not give you

It does give you:

- **Content the server cannot read.** Encryption happens before anything
  leaves your machine; the server never receives a key or a passphrase.
- **Tamper detection.** Every block is authenticated, so altered data fails
  to open instead of decrypting into garbage.
- **Transport encryption**, on top of that, via TLS 1.2 or newer.
- **A verified server identity.** The client checks that the certificate
  chains to your CA *and* that it actually covers the address being dialled,
  so a machine in the group cannot stand in for another one, and an outsider
  cannot stand in at all.
- **Access control**, by way of a 32-byte token compared in constant time. A
  wrong token drops the connection, so an attacker gets one guess per
  handshake.
- **Input that cannot escape its directory.** Names and chunk ids arriving
  from the network are validated before they become paths, and declared
  sizes are bounds-checked before anything is allocated.

It does not give you:

- **Anything if you use `--insecure`.** That switch exists for the first
  connection to a server whose CA you have not collected yet, and it accepts
  any certificate from anyone. It warns each time it is used.
- **Protection if the CA key leaks.** `ca.key` can issue a certificate any
  client in the group will trust. It sits in the server's data directory;
  treat it like a password.
- **Protection from a weak passphrase.** PBKDF2 at 100,000 iterations slows
  guessing down, it does not stop it.
- **Recovery if you forget the passphrase.** There is no escrow and no reset.
  The data is gone.
- **Hidden metadata.** File names and sizes are visible to the server.

## Limitations

- No user accounts or quotas; this is a single-user system.
- No peer discovery or NAT traversal, so peers are addresses you supply.
- The shard layout is fixed at 2 data + 2 parity, needing exactly four peers.
- A changed file is re-uploaded whole; there is no delta sync.
- No versioning: uploading the same name replaces what was there.
- No web or mobile client.
