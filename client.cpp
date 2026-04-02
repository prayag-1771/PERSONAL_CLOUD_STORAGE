#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <map>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
namespace fs = std::filesystem;

static string auth_token;
static SSL_CTX* ssl_ctx = nullptr;

static void print_progress(size_t done, size_t total) {
    int pct = total > 0 ? (int)(done * 100 / total) : 100;
    int bar_width = 30;
    int filled = bar_width * pct / 100;
    cout << "\r  [";
    for (int i = 0; i < bar_width; i++)
        cout << (i < filled ? '#' : '.');
    cout << "] " << pct << "% (" << done / 1024 << "/" << total / 1024 << " KB)" << flush;
    if (done >= total) cout << endl;
}

struct TLSConn {
    int fd = -1;
    SSL* ssl = nullptr;

    void close_conn() {
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = nullptr; }
        if (fd >= 0) { close(fd); fd = -1; }
    }
};

static bool ssl_send_all(SSL* ssl, const void* buf, size_t size) {
    size_t sent = 0;
    const char* p = (const char*)buf;
    while (sent < size) {
        int s = SSL_write(ssl, p + sent, size - sent);
        if (s <= 0) return false;
        sent += s;
    }
    return true;
}

static bool ssl_recv_all(SSL* ssl, void* buf, size_t size) {
    size_t got = 0;
    char* p = (char*)buf;
    while (got < size) {
        int r = SSL_read(ssl, p + got, size - got);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

static vector<uint8_t> sha256(const vector<uint8_t>& data) {
    vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

static string sha256_hex(const vector<uint8_t>& data) {
    auto hash = sha256(data);
    ostringstream oss;
    oss << hex;
    for (uint8_t b : hash)
        oss << setw(2) << setfill('0') << (int)b;
    return oss.str();
}

static string bytes_to_hex(const vector<uint8_t>& data) {
    ostringstream oss;
    oss << hex;
    for (uint8_t b : data)
        oss << setw(2) << setfill('0') << (int)b;
    return oss.str();
}

static vector<uint8_t> xor_buf(const vector<uint8_t>& a,
                               const vector<uint8_t>& b) {
    size_t n = min(a.size(), b.size());
    vector<uint8_t> r(n);
    for (size_t i = 0; i < n; i++) r[i] = a[i] ^ b[i];
    return r;
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        bool hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

static vector<uint8_t> gf_scale(const vector<uint8_t>& buf, uint8_t coeff) {
    vector<uint8_t> r(buf.size());
    for (size_t i = 0; i < buf.size(); i++)
        r[i] = gf_mul(buf[i], coeff);
    return r;
}

static vector<uint8_t> derive_key(const string& pass, const vector<uint8_t>& salt) {
    vector<uint8_t> key(32);
    PKCS5_PBKDF2_HMAC(pass.data(), pass.size(),
                       salt.data(), salt.size(),
                       100000, EVP_sha256(), 32, key.data());
    return key;
}

static vector<uint8_t> generate_salt() {
    vector<uint8_t> salt(16);
    RAND_bytes(salt.data(), 16);
    return salt;
}

static vector<uint8_t> aes_encrypt(const vector<uint8_t>& plain,
                                   const vector<uint8_t>& key,
                                   vector<uint8_t>& iv_out) {
    iv_out.resize(12);
    RAND_bytes(iv_out.data(), 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<uint8_t> out(plain.size() + 16);
    int len1, len2;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_out.data());
    EVP_EncryptUpdate(ctx, out.data(), &len1, plain.data(), plain.size());
    EVP_EncryptFinal_ex(ctx, out.data() + len1, &len2);

    int cipher_len = len1 + len2;
    // Append 16-byte GCM auth tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + cipher_len);
    EVP_CIPHER_CTX_free(ctx);

    out.resize(cipher_len + 16);
    return out;
}

static vector<uint8_t> aes_decrypt(const vector<uint8_t>& cipher,
                                   const vector<uint8_t>& key,
                                   const vector<uint8_t>& iv) {
    if (cipher.size() < 16) return {};

    size_t data_len = cipher.size() - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<uint8_t> out(data_len);
    int len1, len2;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, out.data(), &len1, cipher.data(), data_len);

    // Set expected auth tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                        (void*)(cipher.data() + data_len));

    if (EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        cout << "Decryption failed: authentication tag mismatch (wrong key or corrupted data)\n";
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);

    out.resize(len1 + len2);
    return out;
}

static TLSConn tls_connect(const string& addr) {
    TLSConn conn;
    auto p = addr.find(':');
    string host = addr.substr(0, p);
    int port = stoi(addr.substr(p + 1));

    conn.fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &a.sin_addr);

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(conn.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(conn.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(conn.fd, (sockaddr*)&a, sizeof(a)) < 0) {
        close(conn.fd);
        conn.fd = -1;
        return conn;
    }

    conn.ssl = SSL_new(ssl_ctx);
    SSL_set_fd(conn.ssl, conn.fd);
    if (SSL_connect(conn.ssl) <= 0) {
        SSL_free(conn.ssl);
        close(conn.fd);
        conn.fd = -1;
        conn.ssl = nullptr;
        return conn;
    }

    return conn;
}

static bool ping_server(const string& addr) {
    TLSConn c = tls_connect(addr);
    if (!c.ssl) return false;

    string req = "PING\n";
    ssl_send_all(c.ssl, req.c_str(), req.size());

    string line;
    char ch;
    while (SSL_read(c.ssl, &ch, 1) == 1 && ch != '\n')
        line.push_back(ch);

    c.close_conn();
    return line == "PONG";
}

static bool send_auth(SSL* ssl) {
    if (auth_token.empty()) return true;
    string auth = "AUTH " + auth_token + "\n";
    return ssl_send_all(ssl, auth.c_str(), auth.size());
}

static bool check_dedup(const string& addr, const string& filename,
                        const vector<uint8_t>& data) {
    string hash = sha256_hex(data);
    TLSConn c = tls_connect(addr);
    if (!c.ssl) return false;
    if (!send_auth(c.ssl)) { c.close_conn(); return false; }

    string req = "CHECK_HASH " + filename + " " + hash + "\n";
    ssl_send_all(c.ssl, req.c_str(), req.size());

    string line;
    char ch;
    while (SSL_read(c.ssl, &ch, 1) == 1 && ch != '\n')
        line.push_back(ch);
    c.close_conn();
    return line == "EXISTS";
}

static bool upload_direct(const string& addr, const string& filename,
                          const vector<uint8_t>& data) {
    // Check if file already exists with same content
    if (check_dedup(addr, filename, data)) {
        cout << "File already exists on server (identical content). Skipping upload.\n";
        return true;
    }

    vector<uint8_t> session_key(32);
    RAND_bytes(session_key.data(), 32);

    vector<uint8_t> iv;
    auto cipher = aes_encrypt(data, session_key, iv);

    TLSConn c = tls_connect(addr);
    if (!c.ssl) return false;
    if (!send_auth(c.ssl)) { c.close_conn(); return false; }

    string header = "UPLOAD " + filename + " " + to_string(cipher.size()) +
                    " " + bytes_to_hex(session_key) + " " + bytes_to_hex(iv) + "\n";
    if (!ssl_send_all(c.ssl, header.c_str(), header.size())) { c.close_conn(); return false; }

    // Send cipher data with progress
    size_t total = cipher.size();
    size_t sent = 0;
    size_t chunk_size = 64 * 1024;
    while (sent < total) {
        size_t to_send = min(chunk_size, total - sent);
        int s = SSL_write(c.ssl, cipher.data() + sent, to_send);
        if (s <= 0) { c.close_conn(); return false; }
        sent += s;
        print_progress(sent, total);
    }

    string line;
    char ch;
    while (SSL_read(c.ssl, &ch, 1) == 1 && ch != '\n')
        line.push_back(ch);

    c.close_conn();
    if (line == "AUTH_FAILED") {
        cout << "Authentication failed. Check your token.\n";
        return false;
    }
    return line == "OK";
}

static bool put_chunk(const string& addr, const string& id,
                      const vector<uint8_t>& data) {
    TLSConn c = tls_connect(addr);
    if (!c.ssl) return false;
    if (!send_auth(c.ssl)) { c.close_conn(); return false; }

    string header = "PUT " + id + " " + to_string(data.size()) + "\n";
    if (!ssl_send_all(c.ssl, header.c_str(), header.size())) { c.close_conn(); return false; }
    if (!ssl_send_all(c.ssl, data.data(), data.size())) { c.close_conn(); return false; }
    c.close_conn();
    return true;
}

static bool fetch_chunk(const string& addr, const string& id,
                        vector<uint8_t>& out) {
    TLSConn c = tls_connect(addr);
    if (!c.ssl) return false;
    if (!send_auth(c.ssl)) { c.close_conn(); return false; }

    string req = "FETCH " + id + "\n";
    ssl_send_all(c.ssl, req.c_str(), req.size());

    string line;
    char ch;
    while (SSL_read(c.ssl, &ch, 1) == 1 && ch != '\n')
        line.push_back(ch);

    if (line.empty()) { c.close_conn(); return false; }
    size_t size = stoul(line);

    out.resize(size);
    if (!ssl_recv_all(c.ssl, out.data(), size)) { c.close_conn(); return false; }
    c.close_conn();
    return true;
}

static bool delete_chunk(const string& addr, const string& id) {
    TLSConn c = tls_connect(addr);
    if (!c.ssl) return false;
    if (!send_auth(c.ssl)) { c.close_conn(); return false; }

    string req = "DELETE " + id + "\n";
    ssl_send_all(c.ssl, req.c_str(), req.size());

    string line;
    char ch;
    while (SSL_read(c.ssl, &ch, 1) == 1 && ch != '\n')
        line.push_back(ch);

    c.close_conn();
    return line == "OK";
}

static void do_erasure_upload(const string& file, const string& server_addr,
                              vector<string>& peers, const string& pass) {
    ifstream in(file, ios::binary);
    if (!in) {
        cout << "File not found\n";
        return;
    }

    auto salt = generate_salt();
    auto key = derive_key(pass, salt);

    in.seekg(0, ios::end);
    size_t orig_size = in.tellg();
    in.seekg(0);

    vector<uint8_t> plain(orig_size);
    in.read((char*)plain.data(), orig_size);

    vector<uint8_t> iv;
    auto cipher = aes_encrypt(plain, key, iv);

    size_t half = (cipher.size() + 1) / 2;
    vector<uint8_t> d0(cipher.begin(), cipher.begin() + half);
    vector<uint8_t> d1(half, 0);
    copy(cipher.begin() + half, cipher.end(), d1.begin());

    auto p0 = xor_buf(d0, d1);
    auto p1 = xor_buf(gf_scale(d0, 2), gf_scale(d1, 3));

    string h0  = sha256_hex(d0);
    string h1  = sha256_hex(d1);
    string hp0 = sha256_hex(p0);
    string hp1 = sha256_hex(p1);

    fs::path meta_dir = fs::current_path() / "pending";
    fs::create_directories(meta_dir);

    string basename = fs::path(file).filename().string();
    ofstream meta(meta_dir / (basename + ".ecmeta"));
    meta << server_addr << "\n";
    meta << basename << "\n";
    meta << orig_size << "\n";
    meta << cipher.size() << "\n";
    meta << iv.size() << "\n";
    meta.write((char*)iv.data(), iv.size());
    meta << "\n" << salt.size() << "\n";
    meta.write((char*)salt.data(), salt.size());
    meta << "\n2 2\n";

    bool ok = true;
    ok &= put_chunk(peers[0], h0, d0);
    meta << "0 " << h0 << " " << peers[0] << "\n";

    ok &= put_chunk(peers[1], h1, d1);
    meta << "1 " << h1 << " " << peers[1] << "\n";

    ok &= put_chunk(peers[2], hp0, p0);
    meta << "2 " << hp0 << " " << peers[2] << "\n";

    ok &= put_chunk(peers[3], hp1, p1);
    meta << "3 " << hp1 << " " << peers[3] << "\n";

    if (ok)
        cout << "Server offline. Distributed to peers. Will auto-sync when server is back.\n";
    else
        cout << "Warning: some chunks failed to distribute\n";
}

static vector<uint8_t> recover_from_peers(const string& meta_path,
                                          string& server_addr,
                                          string& filename,
                                          size_t& orig_size,
                                          const string& pass) {
    ifstream meta(meta_path, ios::binary);
    if (!meta) return {};

    size_t cipher_size, iv_len, salt_len;
    int k, m;

    getline(meta, server_addr);
    getline(meta, filename);
    meta >> orig_size >> cipher_size;
    meta >> iv_len;
    meta.get();

    vector<uint8_t> iv(iv_len);
    meta.read((char*)iv.data(), iv_len);
    meta.get();

    meta >> salt_len;
    meta.get();

    vector<uint8_t> salt(salt_len);
    meta.read((char*)salt.data(), salt_len);
    meta.get();

    meta >> k >> m;

    map<int, pair<string,string>> entries;
    int idx;
    string id, addr;
    while (meta >> idx >> id >> addr)
        entries[idx] = {id, addr};

    auto key = derive_key(pass, salt);

    vector<uint8_t> d0, d1, p0, p1;
    for (auto& [i, e] : entries) {
        vector<uint8_t> buf;
        if (fetch_chunk(e.second, e.first, buf)) {
            string actual_hash = sha256_hex(buf);
            if (actual_hash != e.first) {
                cout << "  Chunk " << i << " FAILED integrity check (corrupted). Skipping.\n";
                continue;
            }
            cout << "  Chunk " << i << " verified OK\n";
            if      (i == 0) d0 = buf;
            else if (i == 1) d1 = buf;
            else if (i == 2) p0 = buf;
            else if (i == 3) p1 = buf;
        } else {
            cout << "  Chunk " << i << " unavailable (peer down)\n";
        }
    }

    vector<uint8_t> cipher;

    if (!d0.empty() && !d1.empty()) {
        cipher = d0;
        cipher.insert(cipher.end(), d1.begin(), d1.end());
    } else if (!d0.empty() && !p0.empty()) {
        d1 = xor_buf(d0, p0);
        cipher = d0;
        cipher.insert(cipher.end(), d1.begin(), d1.end());
    } else if (!d1.empty() && !p0.empty()) {
        d0 = xor_buf(d1, p0);
        cipher = d0;
        cipher.insert(cipher.end(), d1.begin(), d1.end());
    } else if (!d0.empty() && !p1.empty()) {
        auto tmp = xor_buf(p1, gf_scale(d0, 2));
        d1 = gf_scale(tmp, 0xF6);
        cipher = d0;
        cipher.insert(cipher.end(), d1.begin(), d1.end());
    } else if (!d1.empty() && !p1.empty()) {
        auto tmp = xor_buf(p1, gf_scale(d1, 3));
        d0 = gf_scale(tmp, 0x8D);
        cipher = d0;
        cipher.insert(cipher.end(), d1.begin(), d1.end());
    } else if (!p0.empty() && !p1.empty()) {
        d1 = xor_buf(p1, gf_scale(p0, 2));
        d0 = xor_buf(p0, d1);
        cipher = d0;
        cipher.insert(cipher.end(), d1.begin(), d1.end());
    } else {
        cout << "  Not enough pieces (need at least 2 of 4)\n";
        return {};
    }

    cipher.resize(cipher_size);
    auto plain = aes_decrypt(cipher, key, iv);
    plain.resize(orig_size);

    for (auto& [i, e] : entries)
        delete_chunk(e.second, e.first);

    return plain;
}

static void do_list(const string& server) {
    TLSConn c = tls_connect(server);
    if (!c.ssl) {
        cout << "Cannot connect to server\n";
        return;
    }
    if (!send_auth(c.ssl)) { c.close_conn(); return; }

    string req = "LIST\n";
    ssl_send_all(c.ssl, req.c_str(), req.size());

    cout << "Files on server:\n";
    string line;
    while (true) {
        line.clear();
        char ch;
        while (SSL_read(c.ssl, &ch, 1) == 1 && ch != '\n')
            line.push_back(ch);
        if (line == "END" || line.empty()) break;
        cout << "  " << line << "\n";
    }
    c.close_conn();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage:\n";
        cout << "  ./client --token <token> upload <file> <server> [peer1 peer2 peer3 peer4]\n";
        cout << "  ./client --token <token> download <file> <server>\n";
        cout << "  ./client --token <token> sync\n";
        cout << "  ./client --token <token> autosync <interval_seconds>\n";
        cout << "  ./client --token <token> list <server>\n";
        return 1;
    }

    // Initialize TLS
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    // Accept self-signed certificates (personal cloud)
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);

    // Parse --token flag
    int arg_offset = 1;
    if (string(argv[1]) == "--token" && argc >= 3) {
        auth_token = argv[2];
        arg_offset = 3;
    }

    if (arg_offset >= argc) {
        cout << "No command specified.\n";
        return 1;
    }

    string mode = argv[arg_offset];

    if (mode == "upload") {
        if (argc < arg_offset + 3) {
            cout << "Usage: ./client --token <token> upload <file> <server> [peer1 peer2 peer3 peer4]\n";
            return 1;
        }

        string file = argv[arg_offset + 1];
        string server = argv[arg_offset + 2];

        ifstream in(file, ios::binary);
        if (!in) {
            cout << "File not found\n";
            return 1;
        }

        in.seekg(0, ios::end);
        size_t fsize = in.tellg();
        in.seekg(0);
        vector<uint8_t> data(fsize);
        in.read((char*)data.data(), fsize);
        in.close();

        if (ping_server(server)) {
            cout << "Server is online. Uploading directly (encrypted transit)...\n";
            string basename = fs::path(file).filename().string();
            if (upload_direct(server, basename, data))
                cout << "Upload complete. File stored on server.\n";
            else
                cout << "Direct upload failed.\n";
        } else {
            cout << "Server is offline. Falling back to peer distribution...\n";

            if (argc < arg_offset + 7) {
                cout << "Need 4 peer addresses for fallback.\n";
                cout << "Usage: ./client --token <token> upload <file> <server> <peer1> <peer2> <peer3> <peer4>\n";
                return 1;
            }

            cout << "Enter passphrase for encryption: ";
            string pass;
            getline(cin, pass);

            vector<string> peers = {argv[arg_offset + 3], argv[arg_offset + 4],
                                    argv[arg_offset + 5], argv[arg_offset + 6]};
            do_erasure_upload(file, server, peers, pass);
        }
    }

    else if (mode == "download") {
        if (argc < arg_offset + 3) {
            cout << "Usage: ./client --token <token> download <file> <server>\n";
            return 1;
        }

        string file = argv[arg_offset + 1];
        string server = argv[arg_offset + 2];
        string basename = fs::path(file).filename().string();

        if (ping_server(server)) {
            cout << "Downloading from server...\n";

            TLSConn c = tls_connect(server);
            if (!c.ssl) {
                cout << "Connection failed\n";
                return 1;
            }
            if (!send_auth(c.ssl)) { c.close_conn(); return 1; }

            string req = "FETCH_FILE " + basename + "\n";
            ssl_send_all(c.ssl, req.c_str(), req.size());

            string line;
            char ch;
            while (SSL_read(c.ssl, &ch, 1) == 1 && ch != '\n')
                line.push_back(ch);

            if (line.empty()) {
                cout << "File not found on server\n";
                c.close_conn();
                return 1;
            }

            size_t size = stoul(line);
            vector<uint8_t> filedata(size);
            size_t got = 0;
            while (got < size) {
                size_t to_read = min((size_t)(64 * 1024), size - got);
                int r = SSL_read(c.ssl, filedata.data() + got, to_read);
                if (r <= 0) {
                    cout << "\nDownload failed\n";
                    c.close_conn();
                    return 1;
                }
                got += r;
                print_progress(got, size);
            }
            c.close_conn();

            ofstream out(file, ios::binary);
            out.write((char*)filedata.data(), filedata.size());
            cout << "Download complete.\n";
        } else {
            cout << "Server offline. Trying peer recovery...\n";
            fs::path meta_path = fs::current_path() / "pending" / (basename + ".ecmeta");
            if (!fs::exists(meta_path)) {
                cout << "No pending metadata found for this file.\n";
                return 1;
            }

            cout << "Enter passphrase: ";
            string pass;
            getline(cin, pass);

            string srv, fname;
            size_t orig;
            auto plain = recover_from_peers(meta_path.string(), srv, fname, orig, pass);
            if (plain.empty()) {
                cout << "Recovery failed.\n";
                return 1;
            }

            ofstream out(file, ios::binary);
            out.write((char*)plain.data(), plain.size());
            fs::remove(meta_path);
            cout << "Recovered from peers.\n";
        }
    }

    else if (mode == "sync") {
        fs::path pending = fs::current_path() / "pending";
        if (!fs::exists(pending)) {
            cout << "No pending files to sync.\n";
            return 0;
        }

        bool has_pending = false;
        for (auto& entry : fs::directory_iterator(pending)) {
            if (entry.path().extension() == ".ecmeta") { has_pending = true; break; }
        }
        if (!has_pending) {
            cout << "No pending files to sync.\n";
            return 0;
        }

        cout << "Enter passphrase for decryption: ";
        string pass;
        getline(cin, pass);

        int synced = 0;
        for (auto& entry : fs::directory_iterator(pending)) {
            if (entry.path().extension() != ".ecmeta") continue;

            string server_addr, filename;
            size_t orig_size;

            ifstream peek(entry.path());
            getline(peek, server_addr);
            peek.close();

            cout << "Checking server " << server_addr << " for '" << entry.path().stem().string() << "'...\n";

            if (!ping_server(server_addr)) {
                cout << "  Server still offline. Skipping.\n";
                continue;
            }

            cout << "  Server is back online! Recovering from peers...\n";
            auto plain = recover_from_peers(entry.path().string(), server_addr, filename, orig_size, pass);
            if (plain.empty()) {
                cout << "  Recovery failed. Skipping.\n";
                continue;
            }

            cout << "  Uploading '" << filename << "' to server...\n";
            if (upload_direct(server_addr, filename, plain)) {
                fs::remove(entry.path());
                cout << "  Synced successfully! Chunks cleaned up.\n";
                synced++;
            } else {
                cout << "  Upload to server failed.\n";
            }
        }

        if (synced == 0)
            cout << "No files synced.\n";
        else
            cout << synced << " file(s) synced to server.\n";
    }

    else if (mode == "autosync") {
        int interval = 30;
        if (argc > arg_offset + 1) interval = stoi(argv[arg_offset + 1]);

        cout << "Auto-sync daemon started. Checking every " << interval << " seconds...\n";

        while (true) {
            fs::path pending = fs::current_path() / "pending";
            if (fs::exists(pending)) {
                for (auto& entry : fs::directory_iterator(pending)) {
                    if (entry.path().extension() != ".ecmeta") continue;

                    string server_addr;
                    ifstream peek(entry.path());
                    getline(peek, server_addr);
                    peek.close();

                    if (!ping_server(server_addr)) continue;

                    cout << "[autosync] Server " << server_addr << " is back online!\n";
                    cout << "[autosync] Run './client sync' to enter passphrase and complete sync.\n";
                }
            }
            sleep(interval);
        }
    }

    else if (mode == "list") {
        if (argc < arg_offset + 2) {
            cout << "Usage: ./client --token <token> list <server>\n";
            return 1;
        }
        do_list(argv[arg_offset + 1]);
    }

    SSL_CTX_free(ssl_ctx);
    return 0;
}
