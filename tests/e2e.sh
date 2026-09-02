#!/bin/bash
#
# End-to-end exercise of the real binaries over real TLS sockets. The unit
# tests cover the algorithms; this covers the parts only a running system can
# show: the protocol, the fallback path, and memory behaviour under a file
# larger than anything you would want buffered.
#
#   usage: tests/e2e.sh [build-directory]      (default: ./build)

set -u

BUILD="${1:-./build}"
BUILD="$(cd "$BUILD" 2>/dev/null && pwd)" || {
    echo "No such build directory: ${1:-./build}"
    echo "Build first:  cmake -S . -B build && cmake --build build"
    exit 1
}

for binary in pcs-server pcs-client; do
    [ -x "$BUILD/$binary" ] || { echo "Missing $BUILD/$binary"; exit 1; }
done

LAB="$(mktemp -d)"
BASE_PORT="${PCS_E2E_PORT:-9400}"
TOKEN="1111111111111111111111111111111111111111111111111111111111111111"
export PCS_TOKEN="$TOKEN"
export PCS_PASSPHRASE="an end to end passphrase"
export PCS_USER="alice"
export PCS_PASSWORD="alice-password"
BOB_PASSWORD="bob-password"

pass=0
fail=0
declare -a SERVER_PIDS=()

cleanup() {
    for pid in "${SERVER_PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    rm -rf "$LAB"
}
trap cleanup EXIT

ok()   { echo "  ok   $1"; pass=$((pass + 1)); }
bad()  { echo "  FAIL $1"; fail=$((fail + 1)); }
want() { if echo "$2" | grep -q "$3"; then ok "$1"; else bad "$1 (expected '$3')"; fi; }
same() { if cmp -s "$2" "$3"; then ok "$1"; else bad "$1 (files differ)"; fi; }

start_server() {
    mkdir -p "$LAB/srv$1"
    if [ "$1" != "$BASE_PORT" ] && [ -f "$LAB/srv$BASE_PORT/ca.crt" ]; then
        cp "$LAB/srv$BASE_PORT/ca.crt" "$LAB/srv$BASE_PORT/ca.key" "$LAB/srv$1/"
    fi
    "$BUILD/pcs-server" "$1" --root "$LAB/srv$1" > "$LAB/srv$1.log" 2>&1 &
    SERVER_PIDS+=($!)
    echo $!
}

client() { "$BUILD/pcs-client" --token "$TOKEN" --quiet "$@" 2>&1; }

MAIN=$BASE_PORT
P1=$((BASE_PORT + 1)); P2=$((BASE_PORT + 2))
P3=$((BASE_PORT + 3)); P4=$((BASE_PORT + 4))
PEERS="127.0.0.1:$P1 127.0.0.1:$P2 127.0.0.1:$P3 127.0.0.1:$P4"
SERVER="127.0.0.1:$MAIN"

mkdir -p "$LAB/work"
cd "$LAB/work" || exit 1

echo "=== the local certificate authority ==="
MAIN_PID=$(start_server $MAIN)
sleep 2

[ -f "$LAB/srv$MAIN/ca.crt" ] && ok "a CA was created on first run"                              || bad "no CA certificate was created"

# Every later client call verifies the server against this.
export PCS_CACERT="$LAB/srv$MAIN/ca.crt"

"$BUILD/pcs-server" $MAIN --root "$LAB/srv$MAIN" ca-export "$LAB/exported.crt" > /dev/null 2>&1
[ -f "$LAB/exported.crt" ] && ok "the CA can be exported for installing"                            || bad "ca-export produced nothing"

CA_BEFORE=$(cat "$LAB/srv$MAIN/ca.crt")

echo "=== accounts ==="

# useradd prompts twice; feeding it on stdin keeps the test unattended.
printf "%s\n%s\n" "$PCS_PASSWORD" "$PCS_PASSWORD" | \
    "$BUILD/pcs-server" $MAIN --root "$LAB/srv$MAIN" useradd alice > /dev/null 2>&1
printf "%s\n%s\n" "$BOB_PASSWORD" "$BOB_PASSWORD" | \
    "$BUILD/pcs-server" $MAIN --root "$LAB/srv$MAIN" useradd bob > /dev/null 2>&1

ACCOUNTS=$("$BUILD/pcs-server" $MAIN --root "$LAB/srv$MAIN" userlist 2>&1)
want "both accounts exist" "$ACCOUNTS" "alice"
want "second account exists" "$ACCOUNTS" "bob"

if grep -q "$PCS_PASSWORD" "$LAB/srv$MAIN/users.txt" 2>/dev/null; then
    bad "the password was stored in the account file"
else
    ok "no password stored, only a verifier"
fi

echo "=== server online: upload, list, download ==="

head -c 3000000 /dev/urandom > original.bin
cp original.bin sample.bin

want "upload succeeds" "$(client upload sample.bin $SERVER)" "Stored"
want "listing shows the file" "$(client list $SERVER)" "sample.bin"

if cmp -s "$LAB/srv$MAIN/files/sample.bin" original.bin; then
    bad "the server stored plaintext"
else
    ok "the server stored ciphertext, not the original bytes"
fi

rm -f sample.bin
want "download succeeds" "$(client download sample.bin $SERVER)" "Wrote"
same "downloaded file matches the original" sample.bin original.bin

echo "=== refusals ==="
rm -f sample.bin
want "wrong passphrase is refused" \
     "$(PCS_PASSPHRASE=wrong client download sample.bin $SERVER)" \
     "Could not decrypt"
[ -f sample.bin ] && bad "a partial file was left behind" \
                  || ok "no partial file left behind"

want "wrong password is refused" \
     "$(PCS_PASSWORD=nonsense client list $SERVER)" \
     "rejected that account or password"
want "unknown account is refused" \
     "$(PCS_USER=nobody PCS_PASSWORD=nonsense client list $SERVER)" \
     "rejected that account or password"

# Chunk traffic is gated by the machine token rather than by an account, so
# a bad token has to be refused on that path specifically. The server is up
# here, so the upload succeeds without ever touching a peer.
BAD_TOKEN="2222222222222222222222222222222222222222222222222222222222222222"
want "a bad machine token does not block ordinary uploads" \
     "$("$BUILD/pcs-client" --token "$BAD_TOKEN" --user alice \
        --password "$PCS_PASSWORD" --quiet upload original.bin $SERVER 2>&1)" \
     "Stored"
want "a traversal name is refused" \
     "$(client download ../../etc/passwd $SERVER)" "Not a valid stored name"

echo "=== the web client on the same port ==="
if command -v curl > /dev/null; then
    CURL="curl -s --cacert $PCS_CACERT"

    PAGE=$($CURL https://127.0.0.1:$MAIN/)
    want "the page is served" "$PAGE" "Personal Cloud"
    want "the page carries its own encryption" "$PAGE" "crypto.subtle"

    WEB_TOKEN=$($CURL -X POST https://127.0.0.1:$MAIN/api/login \
        -H "Content-Type: application/json" \
        -d "{\"user\":\"alice\",\"password\":\"$PCS_PASSWORD\"}" \
        | sed "s/.*token.:.//; s/\".*//")
    [ ${#WEB_TOKEN} -eq 64 ] && ok "signing in returns a session token" \
                             || bad "no session token returned"

    want "a wrong password is refused by the api" \
         "$($CURL -X POST https://127.0.0.1:$MAIN/api/login \
             -H "Content-Type: application/json" \
             -d "{\"user\":\"alice\",\"password\":\"nope\"}")" \
         "wrong account or password"

    want "the api needs a token" \
         "$($CURL https://127.0.0.1:$MAIN/api/files)" "not signed in"

    want "the api lists the account files" \
         "$($CURL https://127.0.0.1:$MAIN/api/files \
             -H "Authorization: Bearer $WEB_TOKEN")" "sample.bin"

    head -c 4096 /dev/urandom > web.bin
    $CURL -X PUT "https://127.0.0.1:$MAIN/api/files/web.bin?tag=deadbeef" \
        -H "Authorization: Bearer $WEB_TOKEN" --data-binary @web.bin > /dev/null
    $CURL "https://127.0.0.1:$MAIN/api/files/web.bin" \
        -H "Authorization: Bearer $WEB_TOKEN" -o web-back.bin
    same "a file put through the api comes back unchanged" web.bin web-back.bin

    want "a traversal name is refused by the api" \
         "$($CURL -X PUT "https://127.0.0.1:$MAIN/api/files/..%2f..%2fescape" \
             -H "Authorization: Bearer $WEB_TOKEN" --data-binary x)" \
         "cannot be stored"

    # The whole point of one port: our own protocol still answers on it.
    want "the pcs protocol still works on the same port" \
         "$(client list $SERVER)" "web.bin"
else
    echo "  (skipped: curl not available)"
fi

echo "=== a server under a different authority is refused ==="
STRANGER=$((BASE_PORT + 8))
mkdir -p "$LAB/srv$STRANGER"        # no CA copied in, so it mints its own
"$BUILD/pcs-server" $STRANGER --root "$LAB/srv$STRANGER"     > "$LAB/srv$STRANGER.log" 2>&1 &
SERVER_PIDS+=($!)
sleep 2

want "a certificate from an unknown CA is rejected"      "$(client list 127.0.0.1:$STRANGER)"      "certificate rejected"

# The same server is reachable once verification is deliberately waived,
# which shows the refusal above came from verification and not from a
# server that was simply down.
want "the same server is reachable with --insecure"      "$("$BUILD/pcs-client" --token "$TOKEN" --insecure --quiet         list 127.0.0.1:$STRANGER 2>&1)"      "rejected that account or password"

echo "=== accounts are isolated from each other ==="
BOB_LIST=$(PCS_USER=bob PCS_PASSWORD="$BOB_PASSWORD" client list $SERVER)
if echo "$BOB_LIST" | grep -q "sample.bin"; then
    bad "bob can see alice's files"
else
    ok "bob cannot see alice's files"
fi

BOB_GET=$(PCS_USER=bob PCS_PASSWORD="$BOB_PASSWORD" client download sample.bin $SERVER)
want "bob cannot fetch alice's file" "$BOB_GET" "does not have"

echo "=== the settings file ==="
cat > "$LAB/work/pcs.conf" <<CONF
[default]
server = 127.0.0.1:$MAIN
user   = alice
token  = $TOKEN
cacert = $PCS_CACERT
peers  = 127.0.0.1:$P1, 127.0.0.1:$P2, 127.0.0.1:$P3, 127.0.0.1:$P4

[nowhere]
server = 127.0.0.1:1
CONF

# With settings in place, nothing but the password needs supplying, and none
# of the server, token, CA or peer addresses appear on the command line.
BARE="$BUILD/pcs-client --quiet"
want "config reports the file it found" \
     "$(env -u PCS_TOKEN -u PCS_CACERT -u PCS_USER $BARE config 2>&1)" \
     "pcs.conf"

cp original.bin configured.bin
want "upload works with no server argument" \
     "$(env -u PCS_TOKEN -u PCS_CACERT -u PCS_USER $BARE upload configured.bin 2>&1)" \
     "Stored"
want "list works with no server argument" \
     "$(env -u PCS_TOKEN -u PCS_CACERT -u PCS_USER $BARE list 2>&1)" \
     "configured.bin"

rm -f configured.bin
want "download honours --out" \
     "$(env -u PCS_TOKEN -u PCS_CACERT -u PCS_USER $BARE download configured.bin \
        --out elsewhere.bin 2>&1)" "Wrote"
same "the downloaded copy matches" elsewhere.bin original.bin

# A profile selects a section rather than merging it over the default, so
# the other section must not inherit the user or CA set in [default].
PROFILE_OUT=$(env -u PCS_TOKEN -u PCS_CACERT -u PCS_USER $BARE \
              --profile nowhere config 2>&1)
want "a profile selects another section" "$PROFILE_OUT" "127.0.0.1:1"
want "and inherits nothing from the default section" "$PROFILE_OUT" "user *(unset)"

want "an explicitly named missing file is an error" \
     "$($BARE --config /nonexistent/pcs.conf list 2>&1)" "no such settings file"

env -u PCS_TOKEN -u PCS_CACERT -u PCS_USER $BARE delete configured.bin > /dev/null 2>&1
mv "$LAB/work/pcs.conf" "$LAB/pcs.conf.saved"

echo "=== deleting a file ==="
cp original.bin gone.bin
client upload gone.bin $SERVER > /dev/null
want "the file is there first" "$(client list $SERVER)" "gone.bin"

want "delete reports success" "$(client delete gone.bin $SERVER)" "Deleted"
LIST_AFTER=$(client list $SERVER)
if echo "$LIST_AFTER" | grep -q "gone.bin"; then
    bad "the file is still listed after deleting"
else
    ok "the file is gone from the listing"
fi

want "deleting it again says so" \
     "$(client delete gone.bin $SERVER)" "no .gone.bin. to delete"

# Deleting must take the dedup sidecar with it, or re-uploading the same
# content would be skipped and the file would never come back.
cp original.bin gone.bin
want "the same file can be uploaded again after deleting" \
     "$(client upload gone.bin $SERVER)" "Stored"
client delete gone.bin $SERVER > /dev/null

want "bob cannot delete alice's file" \
     "$(PCS_USER=bob PCS_PASSWORD="$BOB_PASSWORD" client delete sample.bin $SERVER)" \
     "no .sample.bin. to delete"
want "and alice still has it" "$(client list $SERVER)" "sample.bin"

echo "=== deduplication ==="
cp original.bin sample.bin
want "an identical re-upload is skipped" \
     "$(client upload sample.bin $SERVER)" "already holds identical"

echo "=== server offline: scatter to peers ==="
for port in $P1 $P2 $P3 $P4; do start_server $port > /dev/null; done
sleep 1
kill $MAIN_PID 2>/dev/null
sleep 1

cp original.bin offline.bin
want "shards are distributed" \
     "$(client upload offline.bin $SERVER $PEERS)" "4 of 4 shards distributed"
[ -f "$LAB/work/pending/offline.bin.manifest" ] \
    && ok "pending file recorded" || bad "no manifest written"

rm -f offline.bin
want "rebuild from peers succeeds" "$(client download offline.bin $SERVER)" "Wrote"
same "peer-rebuilt file matches the original" offline.bin original.bin

echo "=== losing two of the four peers ==="
cp original.bin twolost.bin
client upload twolost.bin $SERVER $PEERS > /dev/null
pkill -f "pcs-server $P1" 2>/dev/null
pkill -f "pcs-server $P2" 2>/dev/null
sleep 1

rm -f twolost.bin
want "recovery from the parity pair succeeds" \
     "$(client download twolost.bin $SERVER)" "Wrote"
same "parity-only recovery matches the original" twolost.bin original.bin

for port in $P1 $P2; do start_server $port > /dev/null; done
sleep 1

echo "=== sync needs no passphrase ==="
cp original.bin later.bin
client upload later.bin $SERVER $PEERS > /dev/null
MAIN_PID=$(start_server $MAIN)
sleep 1

want "sync runs with no passphrase available" \
     "$(env -u PCS_PASSPHRASE "$BUILD/pcs-client" --token "$TOKEN" --quiet sync 2>&1)" \
     "synced to"
[ -f "$LAB/work/pending/later.bin.manifest" ] \
    && bad "the manifest survived a successful sync" \
    || ok "manifest cleared after sync"

rm -f later.bin
client download later.bin $SERVER > /dev/null
same "the synced file downloads intact" later.bin original.bin

echo "=== autosync completes on its own ==="
kill $MAIN_PID 2>/dev/null
sleep 1
cp original.bin watched.bin
client upload watched.bin $SERVER $PEERS > /dev/null

env -u PCS_PASSPHRASE "$BUILD/pcs-client" --token "$TOKEN" --quiet \
    autosync 2 > "$LAB/autosync.log" 2>&1 &
DAEMON=$!
sleep 1
start_server $MAIN > /dev/null      # the server comes back while it watches

for _ in $(seq 1 20); do
    [ -f "$LAB/work/pending/watched.bin.manifest" ] || break
    sleep 1
done
kill -INT $DAEMON 2>/dev/null
wait $DAEMON 2>/dev/null

[ -f "$LAB/work/pending/watched.bin.manifest" ] \
    && bad "autosync did not forward the pending file" \
    || ok "autosync forwarded the file unattended"

rm -f watched.bin
client download watched.bin $SERVER > /dev/null
same "the autosynced file downloads intact" watched.bin original.bin

echo "=== the CA survives a restart ==="
if [ "$CA_BEFORE" = "$(cat "$LAB/srv$MAIN/ca.crt")" ]; then
    ok "the CA was not regenerated across restarts"
else
    bad "the CA changed, which would break every installed copy"
fi

echo "=== memory does not track file size ==="
head -c 60000000 /dev/urandom > huge.bin
if command -v /usr/bin/time > /dev/null; then
    PEAK=$(/usr/bin/time -f "%M" "$BUILD/pcs-client" --token "$TOKEN" --quiet \
           upload huge.bin $SERVER 2>&1 >/dev/null | tail -1)
    echo "  peak client memory for a 60 MB upload: ${PEAK} KB"
    if [ "${PEAK:-999999}" -lt 40000 ]; then
        ok "stayed far below the file size"
    else
        bad "peak of ${PEAK} KB suggests the file was buffered whole"
    fi
else
    echo "  (skipped: /usr/bin/time not available)"
fi

echo
echo "=== $pass passed, $fail failed ==="
exit $((fail > 0 ? 1 : 0))
