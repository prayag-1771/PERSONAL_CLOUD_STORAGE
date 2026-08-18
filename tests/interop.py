#!/usr/bin/env python3
"""Cross-implementation check of the sealed container format.

The web client re-implements the container in JavaScript, and two readings of
a format drift apart quietly: a wrong offset or a mis-ordered field still
produces a file, just one the other side cannot open.

This script is a third implementation, written by transliterating the
JavaScript in src/server/page.cpp step for step. It then seals a file here and
opens it with the C++ binary, and seals with the C++ binary and opens it here.
Agreement across two independent implementations is what makes the third one
believable.

    usage: tests/interop.py [build-directory]      (default: ./build)
"""

import os
import struct
import subprocess
import sys
import tempfile
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK_SIZE = 1048576
ITERATIONS = 100000
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
HEADER_LEN = 37
MAGIC = b"PCS1"
VERSION = 1
CONTENT_LABEL = b"pcs-content-v1"

PASSPHRASE = "an interop passphrase"

passed = 0
failed = 0


def check(label, condition):
    global passed, failed
    if condition:
        print("  ok   %s" % label)
        passed += 1
    else:
        print("  FAIL %s" % label)
        failed += 1


def derive(passphrase, salt, label, iterations):
    """PBKDF2 over label-prefixed salt, matching derive_key on both sides."""
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(), label + salt, iterations, 32)


def build_header(salt, plain_size):
    return (MAGIC + bytes([VERSION]) + struct.pack("<I", ITERATIONS) + salt +
            struct.pack("<I", BLOCK_SIZE) + struct.pack("<Q", plain_size))


def block_aad(header, index):
    return header + struct.pack("<Q", index)


def seal(plain, passphrase):
    salt = os.urandom(SALT_LEN)
    key = AESGCM(derive(passphrase, salt, CONTENT_LABEL, ITERATIONS))
    header = build_header(salt, len(plain))

    out = bytearray(header)
    index = 0
    at = 0
    while at < len(plain):
        chunk = plain[at:at + BLOCK_SIZE]
        iv = os.urandom(IV_LEN)
        # AESGCM returns ciphertext followed by the tag, exactly as
        # WebCrypto does; the container keeps them as separate fields.
        sealed = key.encrypt(iv, chunk, block_aad(header, index))
        body, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]

        out += iv + struct.pack("<I", len(body)) + body + tag
        at += len(chunk)
        index += 1
    return bytes(out)


def open_stream(stream, passphrase):
    if len(stream) < HEADER_LEN:
        raise ValueError("too short")
    header = stream[:HEADER_LEN]
    if header[:4] != MAGIC:
        raise ValueError("bad magic")
    if header[4] != VERSION:
        raise ValueError("bad version")

    iterations = struct.unpack("<I", header[5:9])[0]
    salt = header[9:9 + SALT_LEN]
    block_size = struct.unpack("<I", header[9 + SALT_LEN:13 + SALT_LEN])[0]
    plain_size = struct.unpack("<Q", header[13 + SALT_LEN:HEADER_LEN])[0]

    key = AESGCM(derive(passphrase, salt, CONTENT_LABEL, iterations))
    blocks = 0 if plain_size == 0 else (plain_size + block_size - 1) // block_size

    out = bytearray()
    at = HEADER_LEN
    for index in range(blocks):
        iv = stream[at:at + IV_LEN]
        at += IV_LEN
        length = struct.unpack("<I", stream[at:at + 4])[0]
        at += 4
        body = stream[at:at + length]
        at += length
        tag = stream[at:at + TAG_LEN]
        at += TAG_LEN
        out += key.decrypt(iv, body + tag, block_aad(header, index))

    if len(out) != plain_size:
        raise ValueError("size mismatch")
    return bytes(out)


def run(client, args, passphrase=PASSPHRASE):
    env = dict(os.environ, PCS_PASSPHRASE=passphrase)
    return subprocess.run([client] + args + ["--quiet"], env=env,
                          capture_output=True, text=True)


def main():
    build = sys.argv[1] if len(sys.argv) > 1 else "./build"
    client = os.path.join(build, "pcs-client")
    if not os.path.isfile(client):
        print("Missing %s" % client)
        return 1

    work = tempfile.mkdtemp()
    sizes = [0, 1, 5000, BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 12345]

    for size in sizes:
        original = os.urandom(size)

        # This implementation seals; the C++ one has to be able to open it.
        sealed_here = os.path.join(work, "here.pcs")
        opened_there = os.path.join(work, "there.bin")
        with open(sealed_here, "wb") as f:
            f.write(seal(original, PASSPHRASE))

        result = run(client, ["open", sealed_here, opened_there])
        ok = result.returncode == 0 and open(opened_there, "rb").read() == original
        check("C++ opens what this script sealed (%d bytes)" % size, ok)

        # And the other direction.
        plain_in = os.path.join(work, "plain.bin")
        sealed_there = os.path.join(work, "there.pcs")
        with open(plain_in, "wb") as f:
            f.write(original)

        result = run(client, ["seal", plain_in, sealed_there])
        try:
            recovered = open_stream(open(sealed_there, "rb").read(), PASSPHRASE)
            ok = result.returncode == 0 and recovered == original
        except Exception as e:
            ok = False
        check("this script opens what C++ sealed (%d bytes)" % size, ok)

    # A wrong passphrase must fail rather than return plausible bytes.
    sealed = seal(b"secret contents", PASSPHRASE)
    try:
        open_stream(sealed, "the wrong passphrase")
        check("a wrong passphrase is refused", False)
    except Exception:
        check("a wrong passphrase is refused", True)

    # Reordering two blocks must be caught by the block index in the AAD.
    original = os.urandom(BLOCK_SIZE * 2 + 10)
    stream = bytearray(seal(original, PASSPHRASE))
    first = HEADER_LEN
    block_len = IV_LEN + 4 + BLOCK_SIZE + TAG_LEN
    second = first + block_len
    stream[first:first + block_len], stream[second:second + block_len] = \
        stream[second:second + block_len], stream[first:first + block_len]
    try:
        open_stream(bytes(stream), PASSPHRASE)
        check("swapped blocks are detected", False)
    except Exception:
        check("swapped blocks are detected", True)

    print()
    print("=== interop: %d passed, %d failed ===" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
