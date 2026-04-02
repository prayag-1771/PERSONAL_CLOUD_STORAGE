#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <sstream>
#include <cstdlib>
#include <thread>
#include <mutex>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

using namespace std;
namespace fs = std::filesystem;

static string generate_token() {
    vector<uint8_t> buf(32);
    RAND_bytes(buf.data(), 32);
    string token;
    for (uint8_t b : buf) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", b);
        token += hex;
    }
    return token;
}

static string load_or_create_token(const fs::path& token_path) {
    if (fs::exists(token_path)) {
        ifstream in(token_path);
        string token;
        getline(in, token);
        if (!token.empty()) return token;
    }
    string token = generate_token();
    ofstream out(token_path);
    out << token << "\n";
    out.close();
    return token;
}

static void generate_self_signed_cert(const fs::path& cert_path, const fs::path& key_path) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)"PersonalCloud", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    FILE* f = fopen(cert_path.string().c_str(), "wb");
    PEM_write_X509(f, x509);
    fclose(f);

    f = fopen(key_path.string().c_str(), "wb");
    PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    cout << "[server] generated self-signed TLS certificate" << endl;
}

static string server_token;
static mutex fs_mutex;

static string sha256_file(const fs::path& path) {
    ifstream in(path, ios::binary);
    if (!in) return "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    char buf[8192];
    while (in.read(buf, sizeof(buf)) || in.gcount() > 0)
        SHA256_Update(&ctx, buf, in.gcount());
    unsigned char hash[32];
    SHA256_Final(hash, &ctx);
    string hex;
    for (int i = 0; i < 32; i++) {
        char h[3];
        snprintf(h, sizeof(h), "%02x", hash[i]);
        hex += h;
    }
    return hex;
}

static bool is_safe_name(const string& name) {
    if (name.empty()) return false;
    if (name == "." || name == "..") return false;
    if (name.find('/') != string::npos) return false;
    if (name.find('\\') != string::npos) return false;
    if (name.find('\0') != string::npos) return false;
    return true;
}

static bool ssl_recv_all(SSL* ssl, void* buf, size_t size) {
    size_t got = 0;
    char* p = static_cast<char*>(buf);
    while (got < size) {
        int r = SSL_read(ssl, p + got, size - got);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

static bool ssl_send_all(SSL* ssl, const void* buf, size_t size) {
    size_t sent = 0;
    const char* p = static_cast<const char*>(buf);
    while (sent < size) {
        int s = SSL_write(ssl, p + sent, size - sent);
        if (s <= 0) return false;
        sent += s;
    }
    return true;
}

static uint8_t hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return 0;
}

static vector<uint8_t> hex_to_bytes(const string& hex) {
    vector<uint8_t> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); i++)
        bytes[i] = (hex_val(hex[2*i]) << 4) | hex_val(hex[2*i+1]);
    return bytes;
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

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                        (void*)(cipher.data() + data_len));

    if (EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);

    out.resize(len1 + len2);
    return out;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: ./server <port>\n";
        return 1;
    }

    int port = stoi(argv[1]);

    fs::path server_dir = fs::current_path() / "storage" / ("server_" + to_string(port));
    fs::create_directories(server_dir);

    fs::path chunk_storage = server_dir / "chunks";
    fs::create_directories(chunk_storage);

    fs::path file_storage = server_dir / "files";
    fs::create_directories(file_storage);

    fs::path token_path = server_dir / "auth.token";
    server_token = load_or_create_token(token_path);
    cout << "[server] auth token: " << server_token << endl;
    cout << "[server] (save this token — clients need it to connect)" << endl;

    // TLS setup
    fs::path cert_path = server_dir / "server.crt";
    fs::path key_path = server_dir / "server.key";
    if (!fs::exists(cert_path) || !fs::exists(key_path))
        generate_self_signed_cert(cert_path, key_path);

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        cerr << "Failed to create SSL context\n";
        return 1;
    }
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_path.string().c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path.string().c_str(), SSL_FILETYPE_PEM) <= 0) {
        cerr << "Failed to load TLS certificate/key\n";
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 16) < 0) {
        perror("listen");
        return 1;
    }

    cout << "[server] listening on port " << port << " (TLS)" << endl;
    cout << "[server] chunks: " << chunk_storage << endl;
    cout << "[server] files:  " << file_storage << endl;

    auto handle_client = [&](int client_fd) {
        SSL* ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(client_fd);
            return;
        }

        // Read first line: AUTH or PING
        string auth_line;
        char ch;
        while (SSL_read(ssl, &ch, 1) == 1) {
            if (ch == '\n') break;
            auth_line.push_back(ch);
        }

        // PING is unauthenticated (health check)
        if (auth_line == "PING") {
            string resp = "PONG\n";
            ssl_send_all(ssl, resp.c_str(), resp.size());
            cout << "[server " << port << "] PING -> PONG" << endl;
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            return;
        }

        // All other commands require AUTH
        if (auth_line.rfind("AUTH ", 0) != 0 || auth_line.substr(5) != server_token) {
            string resp = "AUTH_FAILED\n";
            ssl_send_all(ssl, resp.c_str(), resp.size());
            cout << "[server " << port << "] auth failed" << endl;
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            return;
        }

        // Read the actual command
        string line;
        while (SSL_read(ssl, &ch, 1) == 1) {
            if (ch == '\n') break;
            line.push_back(ch);
        }

        if (line == "PING") {
            string resp = "PONG\n";
            ssl_send_all(ssl, resp.c_str(), resp.size());
            cout << "[server " << port << "] PING -> PONG" << endl;
        }

        else if (line.rfind("UPLOAD ", 0) == 0) {
            string cmd, filename, key_hex, iv_hex;
            size_t cipher_size;
            stringstream ss(line);
            ss >> cmd >> filename >> cipher_size >> key_hex >> iv_hex;

            if (filename.empty() || cipher_size == 0 || !is_safe_name(filename)) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);
                return;
            }

            vector<char> raw(cipher_size);
            if (!ssl_recv_all(ssl, raw.data(), cipher_size)) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);
                return;
            }

            vector<uint8_t> cipher_data(raw.begin(), raw.end());
            auto key = hex_to_bytes(key_hex);
            auto iv = hex_to_bytes(iv_hex);
            auto plain = aes_decrypt(cipher_data, key, iv);

            {
                lock_guard<mutex> lock(fs_mutex);
                ofstream out(file_storage / filename, ios::binary);
                out.write((char*)plain.data(), plain.size());
                out.close();
            }

            string resp = "OK\n";
            ssl_send_all(ssl, resp.c_str(), resp.size());

            cout << "[server " << port << "] stored file '"
                 << filename << "' (" << plain.size() << " bytes, decrypted)" << endl;
        }

        else if (line.rfind("PUT ", 0) == 0) {
            string cmd, chunk_id;
            size_t size;
            stringstream ss(line);
            ss >> cmd >> chunk_id >> size;

            if (chunk_id.empty() || size == 0 || !is_safe_name(chunk_id)) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);
                return;
            }

            vector<char> data(size);
            if (!ssl_recv_all(ssl, data.data(), size)) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_fd);
                return;
            }

            {
                lock_guard<mutex> lock(fs_mutex);
                ofstream out(chunk_storage / chunk_id, ios::binary);
                out.write(data.data(), data.size());
                out.close();
            }

            cout << "[server " << port << "] stored chunk "
                 << chunk_id << " (" << size << " bytes)" << endl;
        }

        else if (line.rfind("FETCH ", 0) == 0) {
            string chunk_id = line.substr(6);
            if (!is_safe_name(chunk_id)) {
                SSL_shutdown(ssl); SSL_free(ssl); close(client_fd); return;
            }

            lock_guard<mutex> lock(fs_mutex);
            fs::path file = chunk_storage / chunk_id;

            if (!fs::exists(file)) {
                SSL_shutdown(ssl); SSL_free(ssl); close(client_fd); return;
            }

            ifstream in(file, ios::binary);
            in.seekg(0, ios::end);
            size_t size = in.tellg();
            in.seekg(0);

            string header = to_string(size) + "\n";
            ssl_send_all(ssl, header.c_str(), header.size());

            vector<char> buf(size);
            in.read(buf.data(), size);
            ssl_send_all(ssl, buf.data(), buf.size());
        }

        else if (line.rfind("DELETE ", 0) == 0) {
            string chunk_id = line.substr(7);
            if (!is_safe_name(chunk_id)) {
                SSL_shutdown(ssl); SSL_free(ssl); close(client_fd); return;
            }

            lock_guard<mutex> lock(fs_mutex);
            fs::path file = chunk_storage / chunk_id;

            if (fs::exists(file)) {
                fs::remove(file);
                cout << "[server " << port << "] deleted chunk " << chunk_id << endl;
            }

            string resp = "OK\n";
            ssl_send_all(ssl, resp.c_str(), resp.size());
        }

        else if (line.rfind("FETCH_FILE ", 0) == 0) {
            string fname = line.substr(11);
            if (!is_safe_name(fname)) {
                SSL_shutdown(ssl); SSL_free(ssl); close(client_fd); return;
            }

            lock_guard<mutex> lock(fs_mutex);
            fs::path file = file_storage / fname;

            if (!fs::exists(file)) {
                SSL_shutdown(ssl); SSL_free(ssl); close(client_fd); return;
            }

            ifstream in(file, ios::binary);
            in.seekg(0, ios::end);
            size_t size = in.tellg();
            in.seekg(0);

            string header = to_string(size) + "\n";
            ssl_send_all(ssl, header.c_str(), header.size());

            vector<char> buf(size);
            in.read(buf.data(), size);
            ssl_send_all(ssl, buf.data(), buf.size());

            cout << "[server " << port << "] served file '" << fname
                 << "' (" << size << " bytes)" << endl;
        }

        else if (line.rfind("CHECK_HASH ", 0) == 0) {
            // CHECK_HASH <filename> <sha256_hex>
            string cmd, fname, client_hash;
            stringstream ss(line);
            ss >> cmd >> fname >> client_hash;

            if (!is_safe_name(fname)) {
                string resp = "ERROR\n";
                ssl_send_all(ssl, resp.c_str(), resp.size());
            } else {
                lock_guard<mutex> lock(fs_mutex);
                fs::path file = file_storage / fname;
                if (fs::exists(file) && sha256_file(file) == client_hash) {
                    string resp = "EXISTS\n";
                    ssl_send_all(ssl, resp.c_str(), resp.size());
                    cout << "[server " << port << "] dedup: '" << fname << "' already exists" << endl;
                } else {
                    string resp = "SEND\n";
                    ssl_send_all(ssl, resp.c_str(), resp.size());
                }
            }
        }

        else if (line == "LIST") {
            lock_guard<mutex> lock(fs_mutex);
            for (auto& entry : fs::directory_iterator(file_storage)) {
                string name = entry.path().filename().string() + "\n";
                ssl_send_all(ssl, name.c_str(), name.size());
            }
            string end = "END\n";
            ssl_send_all(ssl, end.c_str(), end.size());
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    };

    while (true) {
        int client = accept(server_fd, nullptr, nullptr);
        if (client < 0) continue;
        thread(handle_client, client).detach();
    }
}
