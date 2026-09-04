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
<meta name="color-scheme" content="light dark">
<title>Personal Cloud</title>
<style>
  :root {
    --bg: #f4f5f7;
    --card: #ffffff;
    --ink: #14161a;
    --muted: #666e7a;
    --faint: #9aa2ad;
    --line: #e2e5ea;
    --line-soft: #eef0f3;
    --accent: #2f6feb;
    --accent-ink: #ffffff;
    --bad: #b3261e;
    --good: #1a7f37;
    --shadow: 0 1px 2px rgba(16, 22, 30, .06), 0 8px 24px rgba(16, 22, 30, .06);
    --radius: 12px;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1115;
      --card: #171a20;
      --ink: #e9ecf1;
      --muted: #9aa3af;
      --faint: #6b7482;
      --line: #262b33;
      --line-soft: #1f242b;
      --accent: #5b8def;
      --shadow: 0 1px 2px rgba(0, 0, 0, .4), 0 8px 24px rgba(0, 0, 0, .3);
    }
  }

  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
  }

  .wrap { max-width: 780px; margin: 0 auto; padding: 28px 18px 80px; }

  .topbar {
    display: flex; align-items: center; justify-content: space-between;
    gap: 14px; margin-bottom: 22px;
  }
  .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .brand .mark {
    width: 30px; height: 30px; border-radius: 8px; flex: 0 0 auto;
    background: linear-gradient(140deg, var(--accent), #7aa7f5);
  }
  .brand h1 { font-size: 17px; font-weight: 620; margin: 0; letter-spacing: -.2px; }
  .session { display: flex; align-items: center; gap: 10px; }
  .session .name { font-size: 13px; color: var(--muted); }

  .card {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 20px;
    margin-bottom: 16px;
  }
  .card h2 { font-size: 15px; font-weight: 600; margin: 0 0 4px; }
  .lede { color: var(--muted); font-size: 13.5px; margin: 0 0 16px; }

  label { display: block; font-size: 12.5px; color: var(--muted); margin: 12px 0 5px; font-weight: 500; }
  input[type=text], input[type=password], input[type=search] {
    width: 100%; padding: 10px 12px;
    border: 1px solid var(--line); border-radius: 9px;
    background: var(--bg); color: var(--ink);
    font: inherit; outline: none;
  }
  input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(47, 111, 235, .16); }

  button {
    padding: 9px 15px; border: 1px solid transparent; border-radius: 9px;
    background: var(--accent); color: var(--accent-ink);
    font: inherit; font-weight: 550; cursor: pointer;
  }
  button:hover { filter: brightness(1.06); }
  button:disabled { opacity: .5; cursor: default; filter: none; }
  button.ghost {
    background: transparent; color: var(--muted); border-color: var(--line);
    font-weight: 500; padding: 6px 11px; font-size: 13px;
  }
  button.ghost:hover { color: var(--ink); border-color: var(--faint); filter: none; }
  button.danger:hover { color: var(--bad); border-color: var(--bad); }
  button.block { width: 100%; padding: 11px; }

  .row { display: flex; gap: 10px; align-items: center; }
  .grow { flex: 1 1 auto; min-width: 0; }

  .drop {
    border: 1.5px dashed var(--line); border-radius: var(--radius);
    padding: 30px 18px; text-align: center; color: var(--muted);
    cursor: pointer; transition: border-color .15s, background .15s;
  }
  .drop:hover { border-color: var(--faint); }
  .drop.over { border-color: var(--accent); background: rgba(47, 111, 235, .06); color: var(--accent); }
  .drop .big { font-size: 15px; color: var(--ink); font-weight: 550; }
  .drop .small { font-size: 12.5px; margin-top: 3px; }

  .queue { margin-top: 14px; display: grid; gap: 8px; }
  .job {
    display: grid; grid-template-columns: 1fr auto; gap: 4px 10px;
    align-items: center; font-size: 13.5px;
    padding: 9px 11px; border: 1px solid var(--line-soft);
    border-radius: 9px; background: var(--bg);
  }
  .job .who { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .job .state { color: var(--muted); font-size: 12.5px; white-space: nowrap; }
  .job .track { grid-column: 1 / -1; height: 3px; background: var(--line); border-radius: 3px; overflow: hidden; }
  .job .track > i { display: block; height: 100%; width: 0; background: var(--accent); transition: width .12s linear; }
  .job.done .state { color: var(--good); }
  .job.failed .state { color: var(--bad); }

  .listhead {
    display: flex; align-items: center; justify-content: space-between;
    gap: 10px; margin-bottom: 12px; flex-wrap: wrap;
  }
  .tools { display: flex; gap: 8px; align-items: center; }
  .tools input[type=search] { width: 190px; padding: 7px 11px; font-size: 13.5px; }
  select {
    padding: 7px 10px; border: 1px solid var(--line); border-radius: 9px;
    background: var(--bg); color: var(--ink); font: inherit; font-size: 13.5px;
  }

  table { width: 100%; border-collapse: collapse; }
  tbody tr { border-top: 1px solid var(--line-soft); }
  tbody tr:hover { background: var(--bg); }
  td { padding: 11px 6px; vertical-align: middle; }
  td.icon { width: 1%; padding-right: 2px; font-size: 17px; opacity: .85; }
  td.name { min-width: 0; }
  td.name .n { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  td.name .m { display: block; font-size: 12px; color: var(--faint); }
  td.size { text-align: right; color: var(--muted); font-size: 13px; white-space: nowrap; }
  td.act { text-align: right; width: 1%; white-space: nowrap; }
  td.act button + button { margin-left: 6px; }

  .empty { text-align: center; color: var(--muted); padding: 26px 10px; }
  .empty .big { font-size: 15px; color: var(--ink); font-weight: 550; margin-bottom: 3px; }

  .msg { font-size: 13px; margin-top: 10px; min-height: 18px; color: var(--muted); }
  .msg.bad { color: var(--bad); }
  .msg.good { color: var(--good); }
  .foot { text-align: center; color: var(--faint); font-size: 12px; margin-top: 22px; }
  .hide { display: none !important; }

  @media (max-width: 560px) {
    .wrap { padding: 18px 12px 60px; }
    .tools input[type=search] { width: 130px; }
    td.size { display: none; }
  }
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">
      <div class="mark"></div>
      <h1>Personal Cloud</h1>
    </div>
    <div class="session hide" id="session">
      <span class="name" id="who"></span>
      <button class="ghost" id="signout">Sign out</button>
    </div>
  </div>

  <div class="card" id="signin">
    <h2>Sign in</h2>
    <p class="lede">
      Two secrets, and they do different jobs. The password proves who you
      are to the server. The passphrase encrypts your files here in this tab
      and is never sent anywhere &mdash; without it nobody can read them, and
      neither can you.
    </p>
    <label for="user">Account</label>
    <input type="text" id="user" autocomplete="username" autocapitalize="none" spellcheck="false">
    <label for="password">Password</label>
    <input type="password" id="password" autocomplete="current-password">
    <label for="passphrase">Encryption passphrase</label>
    <input type="password" id="passphrase" autocomplete="off">
    <div style="margin-top:16px">
      <button class="block" id="go">Sign in</button>
    </div>
    <div class="msg" id="signin-msg"></div>
  </div>

  <div class="card hide" id="uploader">
    <div class="drop" id="drop">
      <div class="big">Drop files here</div>
      <div class="small">or click to choose &mdash; they are encrypted before they leave this device</div>
    </div>
    <input type="file" id="picker" multiple class="hide">
    <div class="queue" id="queue"></div>
  </div>

  <div class="card hide" id="files">
    <div class="listhead">
      <div>
        <h2 style="margin:0">Your files</h2>
        <div class="lede" style="margin:2px 0 0" id="summary"></div>
      </div>
      <div class="tools">
        <input type="search" id="filter" placeholder="Filter" autocomplete="off">
        <select id="sort">
          <option value="name">Name</option>
          <option value="new">Newest</option>
          <option value="big">Largest</option>
        </select>
      </div>
    </div>
    <table><tbody id="rows"></tbody></table>
    <div class="empty hide" id="empty">
      <div class="big">Nothing stored yet</div>
      <div>Drop a file above to get started.</div>
    </div>
    <div class="msg" id="files-msg"></div>
  </div>

  <div class="foot">Files are encrypted on this device. The server only ever holds ciphertext.</div>
</div>

<script>
// The sealed container, reproduced exactly as the C++ implementation writes
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
const DEDUP_LABEL = "pcs-dedup-v1";

// The deduplication tag is an HMAC over the whole plaintext, and WebCrypto
// offers no incremental HMAC. Hand-rolling SHA-256 here would allow it to be
// streamed, but a subtly wrong hash could make two different files agree,
// and the upload would then be skipped and the wrong content left stored
// under that name. Rather than risk that on code no browser has run yet,
// the vetted one-shot is used for files small enough to hold in memory, and
// anything larger simply uploads without a tag.
const DEDUP_LIMIT = 64 * 1024 * 1024;

const text = new TextEncoder();
const $ = (id) => document.getElementById(id);

let session = null;
let passphrase = "";
let files = [];

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

function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

// Matches derive_dedup_key: a fixed salt, so the same content and passphrase
// always produce the same tag, which is the whole point of it.
async function dedupKey(pass) {
  const salt = text.encode(DEDUP_LABEL + DEDUP_LABEL);
  const raw = await deriveBits(pass, salt, ITERATIONS);
  return crypto.subtle.importKey(
    "raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function dedupTagFor(file) {
  if (file.size > DEDUP_LIMIT) return "";
  const key = await dedupKey(passphrase);
  const signature = await crypto.subtle.sign(
    "HMAC", key, await file.arrayBuffer());
  return toHex(new Uint8Array(signature));
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
    parts.push(iv, le32(sealed.length - TAG_LEN),
               sealed.subarray(0, sealed.length - TAG_LEN),
               sealed.subarray(sealed.length - TAG_LEN));

    done = end;
    index += 1;
    if (onProgress) onProgress(done, file.size);
  }

  // A Blob lets the browser keep the sealed copy on disk rather than in
  // memory, which is what lets a large file get through this at all.
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

function whenText(seconds) {
  if (!seconds) return "";
  const then = new Date(seconds * 1000);
  const ago = (Date.now() - then.getTime()) / 1000;
  if (ago < 60) return "just now";
  if (ago < 3600) return Math.floor(ago / 60) + " min ago";
  if (ago < 86400) return Math.floor(ago / 3600) + " hr ago";
  if (ago < 604800) return Math.floor(ago / 86400) + " days ago";
  return then.toLocaleDateString();
}

function iconFor(name) {
  const dot = name.lastIndexOf(".");
  const ext = dot < 0 ? "" : name.slice(dot + 1).toLowerCase();
  if (["jpg", "jpeg", "png", "gif", "webp", "heic", "bmp", "svg"].includes(ext)) return "\u{1F5BC}";
  if (["mp4", "mov", "mkv", "avi", "webm"].includes(ext)) return "\u{1F3AC}";
  if (["mp3", "wav", "flac", "m4a", "ogg"].includes(ext)) return "\u{1F3B5}";
  if (["pdf"].includes(ext)) return "\u{1F4C4}";
  if (["zip", "gz", "tar", "7z", "rar"].includes(ext)) return "\u{1F5DC}";
  if (["txt", "md", "rtf", "doc", "docx"].includes(ext)) return "\u{1F4DD}";
  return "\u{1F4E6}";
}

function say(where, message, kind) {
  const node = $(where);
  node.textContent = message || "";
  node.className = "msg" + (kind ? " " + kind : "");
}

async function api(path, options) {
  const settings = options || {};
  settings.headers = settings.headers || {};
  if (session) settings.headers["Authorization"] = "Bearer " + session.token;

  const reply = await fetch(path, settings);

  // Sessions expire on their own. Without this the page would just report
  // that it could not list anything, with no hint that signing in again is
  // what is needed.
  if (reply.status === 401 && session) signedOut();
  return reply;
}

function signedOut() {
  session = null;
  passphrase = "";
  files = [];

  $("signin").classList.remove("hide");
  $("uploader").classList.add("hide");
  $("files").classList.add("hide");
  $("session").classList.add("hide");
  say("signin-msg", "That session expired. Please sign in again.", "bad");
  $("user").focus();
}

// --- the upload queue -----------------------------------------------------

function addJob(name) {
  const job = document.createElement("div");
  job.className = "job";

  const who = document.createElement("div");
  who.className = "who";
  who.textContent = name;

  const state = document.createElement("div");
  state.className = "state";
  state.textContent = "waiting";

  const track = document.createElement("div");
  track.className = "track";
  const fill = document.createElement("i");
  track.appendChild(fill);

  job.append(who, state, track);
  $("queue").appendChild(job);

  return {
    progress(done, total) { fill.style.width = (total ? done * 100 / total : 100) + "%"; },
    status(word, kind) {
      state.textContent = word;
      job.className = "job" + (kind ? " " + kind : "");
    },
    retire(delay) { setTimeout(() => job.remove(), delay); },
  };
}

async function upload(chosen) {
  for (const file of chosen) {
    const job = addJob(file.name);
    try {
      job.status("checking");
      const tag = await dedupTagFor(file);

      // Nothing to do when the server already holds this exact content
      // under this name.
      const existing = files.find((f) => f.name === file.name);
      if (tag && existing && existing.tag === tag) {
        job.progress(1, 1);
        job.status("already stored", "done");
        job.retire(2500);
        continue;
      }

      job.status("encrypting");
      const sealed = await sealFile(file, job.progress);

      job.status("uploading");
      job.progress(0, 1);
      const query = tag ? "?tag=" + encodeURIComponent(tag) : "";
      const reply = await api(
        "/api/files/" + encodeURIComponent(file.name) + query, {
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
        body: sealed,
      });
      if (!reply.ok) {
        const data = await reply.json().catch(() => ({}));
        throw new Error(data.error || "upload failed");
      }

      job.progress(1, 1);
      job.status("stored", "done");
      job.retire(2500);
    } catch (e) {
      job.status(e.message, "failed");
      job.retire(9000);
    }
  }
  await refresh();
}

// --- the file list --------------------------------------------------------

function render() {
  const needle = $("filter").value.trim().toLowerCase();
  const order = $("sort").value;

  let shown = files.filter((f) => !needle || f.name.toLowerCase().includes(needle));
  shown.sort((a, b) => {
    if (order === "big") return b.size - a.size;
    if (order === "new") return b.modified - a.modified;
    return a.name.localeCompare(b.name);
  });

  const rows = $("rows");
  rows.textContent = "";

  for (const file of shown) {
    const tr = document.createElement("tr");

    const icon = document.createElement("td");
    icon.className = "icon";
    icon.textContent = iconFor(file.name);

    const name = document.createElement("td");
    name.className = "name";
    const line = document.createElement("span");
    line.className = "n";
    line.textContent = file.name;
    const meta = document.createElement("span");
    meta.className = "m";
    meta.textContent = whenText(file.modified);
    name.append(line, meta);

    const size = document.createElement("td");
    size.className = "size";
    size.textContent = humanSize(file.size);

    const act = document.createElement("td");
    act.className = "act";
    const get = document.createElement("button");
    get.className = "ghost";
    get.textContent = "Download";
    get.onclick = () => download(file.name, get);
    const drop = document.createElement("button");
    drop.className = "ghost danger";
    drop.textContent = "Delete";
    drop.onclick = () => remove(file.name);
    act.append(get, drop);

    tr.append(icon, name, size, act);
    rows.appendChild(tr);
  }

  const nothing = files.length === 0;
  $("empty").classList.toggle("hide", !nothing);

  const total = files.reduce((sum, f) => sum + f.size, 0);
  $("summary").textContent = nothing
    ? ""
    : files.length + (files.length === 1 ? " file" : " files") +
      " · " + humanSize(total) + " stored" +
      (shown.length !== files.length ? " · " + shown.length + " shown" : "");
}

async function refresh() {
  const reply = await api("/api/files");
  if (!reply.ok) { say("files-msg", "Could not list your files.", "bad"); return; }

  const data = await reply.json();
  files = data.files || [];
  render();
}
</script>

<script>
async function download(name, button) {
  button.disabled = true;
  say("files-msg", "Fetching " + name + "...");
  try {
    const reply = await api("/api/files/" + encodeURIComponent(name));
    if (!reply.ok) throw new Error("could not fetch it");

    const sealed = await reply.blob();

    const plain = await openBlob(sealed, (done, total) => {
      const percent = total ? Math.floor(done * 100 / total) : 100;
      say("files-msg", "Decrypting " + name + "... " + percent + "%");
    });

    const url = URL.createObjectURL(plain);
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);

    say("files-msg", "Saved " + name + ".", "good");
  } catch (e) {
    say("files-msg", name + ": " + e.message, "bad");
  } finally {
    button.disabled = false;
  }
}

async function remove(name) {
  // Irreversible, with no versions to fall back on, so it asks first.
  if (!confirm("Delete " + name + "? This cannot be undone.")) return;

  const reply = await api("/api/files/" + encodeURIComponent(name), {
    method: "DELETE",
  });
  if (reply.ok) {
    say("files-msg", "Deleted " + name + ".");
  } else {
    say("files-msg", "Could not delete " + name + ".", "bad");
  }
  await refresh();
}

// --- signing in -----------------------------------------------------------

async function signIn() {
  const user = $("user").value.trim();
  const password = $("password").value;
  const secret = $("passphrase").value;

  if (!user || !password || !secret) {
    say("signin-msg", "All three are needed.", "bad");
    return;
  }

  $("go").disabled = true;
  say("signin-msg", "Signing in...");

  try {
    const reply = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user: user, password: password }),
    });
    const data = await reply.json();
    if (!reply.ok) throw new Error(data.error || "sign-in failed");

    session = data;
    passphrase = secret;

    // The password has done its job. The passphrase stays in memory only,
    // which is why closing the tab means typing it again.
    $("password").value = "";
    $("passphrase").value = "";

    $("signin").classList.add("hide");
    $("uploader").classList.remove("hide");
    $("files").classList.remove("hide");
    $("session").classList.remove("hide");
    $("who").textContent = session.user;

    say("signin-msg", "");
    await refresh();
  } catch (e) {
    say("signin-msg", e.message, "bad");
  } finally {
    $("go").disabled = false;
  }
}

$("go").onclick = signIn;
$("user").onkeydown = (e) => { if (e.key === "Enter") $("password").focus(); };
$("password").onkeydown = (e) => { if (e.key === "Enter") $("passphrase").focus(); };
$("passphrase").onkeydown = (e) => { if (e.key === "Enter") signIn(); };

$("signout").onclick = async () => {
  await api("/api/logout", { method: "POST" });
  session = null;
  passphrase = "";
  location.reload();
};

$("drop").onclick = () => $("picker").click();
$("picker").onchange = () => {
  if ($("picker").files.length) upload($("picker").files);
  $("picker").value = "";
};

$("drop").ondragover = (e) => { e.preventDefault(); $("drop").classList.add("over"); };
$("drop").ondragleave = () => $("drop").classList.remove("over");
$("drop").ondrop = (e) => {
  e.preventDefault();
  $("drop").classList.remove("over");
  if (e.dataTransfer.files.length) upload(e.dataTransfer.files);
};

$("filter").oninput = render;
$("sort").onchange = render;

// Without a secure context there is no WebCrypto, and this page cannot
// encrypt anything. Better to say so plainly than to appear to work.
if (!window.crypto || !window.crypto.subtle) {
  say("signin-msg",
      "This browser will not allow encryption on this page. Install the " +
      "server CA certificate and open the site over https.", "bad");
  $("go").disabled = true;
}

$("user").focus();
</script>
</body>
</html>
)HTML";
    return kPage;
}

}  // namespace server
}  // namespace pcs
