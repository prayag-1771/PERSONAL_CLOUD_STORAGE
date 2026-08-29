#include "page.hpp"

using namespace std;

namespace pcs {
namespace server {

// Raw string literal: the markup and script below contain no escape
// sequences, so what is written here is exactly what the browser receives.
const string& web_page() {
    static const string kPage = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Personal Cloud</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f6f7f9; --card: #ffffff; --ink: #16181d; --muted: #6b7280;
    --line: #e3e6ea; --accent: #2f6feb; --bad: #b3261e; --good: #1a7f37;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14161a; --card: #1c1f25; --ink: #e8eaed; --muted: #9aa1ab;
      --line: #2c313a; --accent: #6c9cf0;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--ink);
    font: 15px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }
  main { max-width: 720px; margin: 0 auto; padding: 24px 16px 64px; }
  h1 { font-size: 20px; margin: 0; }
  header {
    display: flex; align-items: baseline; justify-content: space-between;
    gap: 12px; margin-bottom: 20px;
  }
  .who { color: var(--muted); font-size: 13px; }
  .card {
    background: var(--card); border: 1px solid var(--line);
    border-radius: 10px; padding: 18px; margin-bottom: 16px;
  }
  label { display: block; font-size: 13px; color: var(--muted); margin: 10px 0 4px; }
  input[type=text], input[type=password] {
    width: 100%; padding: 9px 11px; border: 1px solid var(--line);
    border-radius: 7px; background: var(--bg); color: var(--ink); font: inherit;
  }
  button {
    padding: 9px 15px; border: 0; border-radius: 7px; background: var(--accent);
    color: #fff; font: inherit; font-weight: 500; cursor: pointer;
  }
  button.quiet { background: transparent; color: var(--muted); border: 1px solid var(--line); }
  button:disabled { opacity: .55; cursor: default; }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .drop {
    border: 2px dashed var(--line); border-radius: 10px; padding: 26px;
    text-align: center; color: var(--muted); cursor: pointer;
  }
  .drop.over { border-color: var(--accent); color: var(--accent); }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 9px 4px; border-top: 1px solid var(--line); vertical-align: middle; }
  td.size { color: var(--muted); font-size: 13px; text-align: right; white-space: nowrap; }
  td.act { text-align: right; width: 1%; white-space: nowrap; }
  .note { font-size: 13px; color: var(--muted); margin-top: 10px; }
  .bad { color: var(--bad); }
  .good { color: var(--good); }
  .bar { height: 4px; background: var(--line); border-radius: 3px; overflow: hidden; margin-top: 10px; }
  .bar > i { display: block; height: 100%; width: 0; background: var(--accent); transition: width .15s; }
  .hide { display: none; }
</style>
</head>
<body>
<main>
  <header>
    <h1>Personal Cloud</h1>
    <span class="who" id="who"></span>
  </header>

  <section class="card" id="signin">
    <strong>Sign in</strong>
    <label for="user">Account</label>
    <input type="text" id="user" autocomplete="username" autocapitalize="none">
    <label for="password">Password</label>
    <input type="password" id="password" autocomplete="current-password">
    <label for="passphrase">Encryption passphrase</label>
    <input type="password" id="passphrase" autocomplete="off">
    <p class="note">
      Two different secrets. The password proves who you are to the server.
      The passphrase encrypts your files here in this tab and is never sent
      anywhere, so nobody can recover your files without it.
    </p>
    <div class="row" style="margin-top:12px">
      <button id="go">Sign in</button>
      <span id="signin-msg" class="note"></span>
    </div>
  </section>

  <section class="card hide" id="uploader">
    <div class="drop" id="drop">Drop files here, or click to choose</div>
    <input type="file" id="picker" multiple class="hide">
    <div class="bar hide" id="bar"><i id="barfill"></i></div>
    <div class="note" id="upload-msg"></div>
  </section>

  <section class="card hide" id="files">
    <div class="row" style="justify-content:space-between">
      <strong>Your files</strong>
      <button class="quiet" id="signout">Sign out</button>
    </div>
    <table><tbody id="rows"></tbody></table>
    <div class="note" id="files-msg"></div>
  </section>
</main>

<script>
// The container format, reproduced exactly as the C++ implementation writes
// it. Anything sealed here opens with the command-line client and the other
// way round, so the two must agree byte for byte.
const BLOCK_SIZE = 1048576;
const ITERATIONS = 100000;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = 37;
const MAGIC = [80, 67, 83, 49];   // PCS1
const VERSION = 1;
const CONTENT_LABEL = "pcs-content-v1";

const text = new TextEncoder();
let session = null;
let passphrase = "";

const $ = (id) => document.getElementById(id);

function concat(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function le32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

function le64(value) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
}

function readLe32(bytes, at) {
  return new DataView(bytes.buffer, bytes.byteOffset).getUint32(at, true);
}

function readLe64(bytes, at) {
  return Number(new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(at, true));
}

async function deriveBits(pass, saltBytes, iterations) {
  const base = await crypto.subtle.importKey(
    "raw", text.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: iterations, hash: "SHA-256" },
    base, 256);
  return new Uint8Array(bits);
}

// The label is prefixed to the salt, matching derive_key on the C++ side.
async function contentKey(pass, salt, iterations) {
  const raw = await deriveBits(
    pass, concat([text.encode(CONTENT_LABEL), salt]), iterations);
  return crypto.subtle.importKey(
    "raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function buildHeader(salt, plainSize) {
  return concat([
    new Uint8Array(MAGIC), new Uint8Array([VERSION]), le32(ITERATIONS),
    salt, le32(BLOCK_SIZE), le64(plainSize),
  ]);
}

// Each block is bound to the whole header and to its own index, so a
// reordered or truncated stream fails to open instead of decrypting.
function blockAad(header, index) {
  return concat([header, le64(index)]);
}

async function sealFile(file, onProgress) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const key = await contentKey(passphrase, salt, ITERATIONS);
  const header = buildHeader(salt, file.size);

  const parts = [header];
  let done = 0;
  let index = 0;

  while (done < file.size) {
    const end = Math.min(done + BLOCK_SIZE, file.size);
    const plain = new Uint8Array(await file.slice(done, end).arrayBuffer());
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));

    const sealed = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: blockAad(header, index),
        tagLength: TAG_LEN * 8 },
      key, plain));

    // WebCrypto appends the tag; the container keeps them as separate
    // fields, so split it back off here.
    const body = sealed.subarray(0, sealed.length - TAG_LEN);
    const tag = sealed.subarray(sealed.length - TAG_LEN);

    parts.push(iv, le32(body.length), body, tag);

    done = end;
    index += 1;
    if (onProgress) onProgress(done, file.size);
  }

  // A Blob lets the browser keep the sealed copy on disk rather than in
  // memory, which is what makes a large file survive this.
  return new Blob(parts);
}

async function openBlob(blob, onProgress) {
  const header = new Uint8Array(await blob.slice(0, HEADER_LEN).arrayBuffer());
  if (header.length !== HEADER_LEN) throw new Error("file is too short");

  for (let i = 0; i < 4; i++) {
    if (header[i] !== MAGIC[i]) throw new Error("not an encrypted file");
  }
  if (header[4] !== VERSION) throw new Error("unsupported format version");

  const iterations = readLe32(header, 5);
  const salt = header.subarray(9, 9 + SALT_LEN);
  const blockSize = readLe32(header, 9 + SALT_LEN);
  const plainSize = readLe64(header, 13 + SALT_LEN);

  const key = await contentKey(passphrase, salt, iterations);
  const blocks = plainSize === 0 ? 0 : Math.ceil(plainSize / blockSize);

  const parts = [];
  let at = HEADER_LEN;
  let done = 0;

  for (let index = 0; index < blocks; index++) {
    const meta = new Uint8Array(await blob.slice(at, at + IV_LEN + 4).arrayBuffer());
    if (meta.length !== IV_LEN + 4) throw new Error("file ends mid-block");

    const iv = meta.subarray(0, IV_LEN);
    const length = readLe32(meta, IV_LEN);
    at += IV_LEN + 4;

    const sealed = new Uint8Array(
      await blob.slice(at, at + length + TAG_LEN).arrayBuffer());
    if (sealed.length !== length + TAG_LEN) throw new Error("file ends mid-block");
    at += length + TAG_LEN;

    let plain;
    try {
      plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv, additionalData: blockAad(header, index),
          tagLength: TAG_LEN * 8 },
        key, sealed);
    } catch (e) {
      throw new Error("wrong passphrase, or the file was altered");
    }

    parts.push(plain);
    done += plain.byteLength;
    if (onProgress) onProgress(done, plainSize);
  }

  if (done !== plainSize) throw new Error("recovered size does not match");
  return new Blob(parts);
}
</script>

<script>
function humanSize(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return (unit === 0 ? value : value.toFixed(1)) + " " + units[unit];
}

function showProgress(done, total) {
  $("bar").classList.remove("hide");
  $("barfill").style.width = (total ? (done * 100 / total) : 100) + "%";
}

function hideProgress() {
  $("bar").classList.add("hide");
  $("barfill").style.width = "0%";
}

async function api(path, options) {
  const settings = options || {};
  settings.headers = settings.headers || {};
  if (session) settings.headers["Authorization"] = "Bearer " + session.token;
  return fetch(path, settings);
}

async function signIn() {
  const user = $("user").value.trim();
  const password = $("password").value;
  passphrase = $("passphrase").value;

  if (!user || !password || !passphrase) {
    $("signin-msg").textContent = "Fill in all three fields.";
    $("signin-msg").className = "note bad";
    return;
  }

  $("go").disabled = true;
  $("signin-msg").textContent = "Signing in...";
  $("signin-msg").className = "note";

  try {
    const reply = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user: user, password: password }),
    });
    const data = await reply.json();
    if (!reply.ok) throw new Error(data.error || "sign-in failed");

    session = data;
    // The password has done its job; the passphrase stays only in memory.
    $("password").value = "";
    $("passphrase").value = "";

    $("signin").classList.add("hide");
    $("uploader").classList.remove("hide");
    $("files").classList.remove("hide");
    $("who").textContent = "signed in as " + session.user;
    await refresh();
  } catch (e) {
    $("signin-msg").textContent = e.message;
    $("signin-msg").className = "note bad";
  } finally {
    $("go").disabled = false;
  }
}

async function refresh() {
  const reply = await api("/api/files");
  if (!reply.ok) { $("files-msg").textContent = "Could not list files."; return; }

  const data = await reply.json();
  const rows = $("rows");
  rows.textContent = "";

  if (!data.files.length) {
    $("files-msg").textContent = "Nothing stored yet.";
    return;
  }
  $("files-msg").textContent = "";

  for (const file of data.files) {
    const tr = document.createElement("tr");

    const name = document.createElement("td");
    name.textContent = file.name;

    const size = document.createElement("td");
    size.className = "size";
    size.textContent = humanSize(file.size) + " sealed";

    const act = document.createElement("td");
    act.className = "act";
    const get = document.createElement("button");
    get.className = "quiet";
    get.textContent = "Download";
    get.onclick = () => download(file.name, get);

    const drop = document.createElement("button");
    drop.className = "quiet";
    drop.textContent = "Delete";
    drop.style.marginLeft = "6px";
    drop.onclick = () => remove(file.name);

    act.append(get, drop);

    tr.append(name, size, act);
    rows.appendChild(tr);
  }
}

async function upload(files) {
  for (const file of files) {
    $("upload-msg").textContent = "Encrypting " + file.name + "...";
    $("upload-msg").className = "note";
    try {
      const sealed = await sealFile(file, showProgress);

      $("upload-msg").textContent = "Uploading " + file.name + "...";
      const reply = await api("/api/files/" + encodeURIComponent(file.name), {
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
        body: sealed,
      });
      if (!reply.ok) {
        const data = await reply.json().catch(() => ({}));
        throw new Error(data.error || "upload failed");
      }

      $("upload-msg").textContent = "Stored " + file.name + ".";
      $("upload-msg").className = "note good";
    } catch (e) {
      $("upload-msg").textContent = file.name + ": " + e.message;
      $("upload-msg").className = "note bad";
    } finally {
      hideProgress();
    }
  }
  await refresh();
}

async function remove(name) {
  // Deleting is irreversible and there are no versions to fall back on, so
  // it asks first.
  if (!confirm("Delete " + name + "? This cannot be undone.")) return;

  const reply = await api("/api/files/" + encodeURIComponent(name), {
    method: "DELETE",
  });
  if (reply.ok) {
    $("files-msg").textContent = "Deleted " + name + ".";
    $("files-msg").className = "note";
  } else {
    $("files-msg").textContent = "Could not delete " + name + ".";
    $("files-msg").className = "note bad";
  }
  await refresh();
}

async function download(name, button) {
  button.disabled = true;
  $("files-msg").textContent = "Fetching " + name + "...";
  $("files-msg").className = "note";
  try {
    const reply = await api("/api/files/" + encodeURIComponent(name));
    if (!reply.ok) throw new Error("could not fetch it");

    const sealed = await reply.blob();
    $("files-msg").textContent = "Decrypting " + name + "...";

    const plain = await openBlob(sealed, showProgress);

    const url = URL.createObjectURL(plain);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);

    $("files-msg").textContent = "Saved " + name + ".";
    $("files-msg").className = "note good";
  } catch (e) {
    $("files-msg").textContent = name + ": " + e.message;
    $("files-msg").className = "note bad";
  } finally {
    hideProgress();
    button.disabled = false;
  }
}

$("go").onclick = signIn;
$("password").onkeydown = (e) => { if (e.key === "Enter") $("passphrase").focus(); };
$("passphrase").onkeydown = (e) => { if (e.key === "Enter") signIn(); };

$("signout").onclick = async () => {
  await api("/api/logout", { method: "POST" });
  session = null;
  passphrase = "";
  location.reload();
};

$("drop").onclick = () => $("picker").click();
$("picker").onchange = () => { if ($("picker").files.length) upload($("picker").files); };

$("drop").ondragover = (e) => { e.preventDefault(); $("drop").classList.add("over"); };
$("drop").ondragleave = () => $("drop").classList.remove("over");
$("drop").ondrop = (e) => {
  e.preventDefault();
  $("drop").classList.remove("over");
  if (e.dataTransfer.files.length) upload(e.dataTransfer.files);
};

if (!crypto || !crypto.subtle) {
  // Without a secure context there is no WebCrypto, and this page cannot
  // encrypt anything. Better to say so than to appear to work.
  $("signin-msg").textContent =
    "This browser will not allow encryption on this page. Install the " +
    "server CA certificate and open the site over https.";
  $("signin-msg").className = "note bad";
  $("go").disabled = true;
}
</script>
</body>
</html>
)HTML";
    return kPage;
}

}  // namespace server
}  // namespace pcs
