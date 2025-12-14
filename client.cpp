#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <filesystem>
#include <map>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
using namespace std;
namespace fs = std::filesystem;

/* ===================== UTILITIES ===================== */

static bool send_all(int sock, const void* buf, size_t size) {
    size_t sent = 0;
    const char* p = (const char*)buf;
    while (sent < size) {
        ssize_t s = send(sock, p + sent, size - sent, 0);
        if (s <= 0) return false;
        sent += s;
    }
    return true;
}

static bool recv_all(int sock, void* buf, size_t size) {
    size_t got = 0;
    char* p = (char*)buf;
    while (got < size) {
        ssize_t r = recv(sock, p + got, size - got, 0);
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

static vector<uint8_t> xor_buf(const vector<uint8_t>& a,
                               const vector<uint8_t>& b) {
    size_t n = min(a.size(), b.size());
    vector<uint8_t> r(n);
    for (size_t i = 0; i < n; i++) r[i] = a[i] ^ b[i];
    return r;
}

/* ===================== CRYPTO ===================== */

static vector<uint8_t> derive_key(const string& pass) {
    vector<uint8_t> key(32);
    SHA256((const uint8_t*)pass.data(), pass.size(), key.data());
    return key;
}

static vector<uint8_t> aes_encrypt(const vector<uint8_t>& plain,
                                   const vector<uint8_t>& key,
                                   vector<uint8_t>& iv_out) {
    iv_out.resize(16);
    RAND_bytes(iv_out.data(), 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<uint8_t> out(plain.size() + 16);
    int len1, len2;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       key.data(), iv_out.data());
    EVP_EncryptUpdate(ctx, out.data(), &len1,
                      plain.data(), plain.size());
    EVP_EncryptFinal_ex(ctx, out.data() + len1, &len2);
    EVP_CIPHER_CTX_free(ctx);

    out.resize(len1 + len2);
    return out;
}

static vector<uint8_t> aes_decrypt(const vector<uint8_t>& cipher,
                                   const vector<uint8_t>& key,
                                   const vector<uint8_t>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<uint8_t> out(cipher.size());
    int len1, len2;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                       key.data(), iv.data());
    EVP_DecryptUpdate(ctx, out.data(), &len1,
                      cipher.data(), cipher.size());
    EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2);
    EVP_CIPHER_CTX_free(ctx);

    out.resize(len1 + len2);
    return out;
}

/* ===================== NETWORK ===================== */

static bool put_chunk(const string& addr,
                      const string& id,
                      const vector<uint8_t>& data) {
    auto p = addr.find(':');
    string host = addr.substr(0, p);
    int port = stoi(addr.substr(p + 1));

    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &a.sin_addr);

    if (connect(s, (sockaddr*)&a, sizeof(a)) < 0) return false;

    string header = "PUT " + id + " " + to_string(data.size()) + "\n";
    if (!send_all(s, header.c_str(), header.size())) return false;
    if (!send_all(s, data.data(), data.size())) return false;
    close(s);
    return true;
}

static bool fetch_chunk(const string& addr,
                        const string& id,
                        vector<uint8_t>& out) {
    auto p = addr.find(':');
    string host = addr.substr(0, p);
    int port = stoi(addr.substr(p + 1));

    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &a.sin_addr);

    if (connect(s, (sockaddr*)&a, sizeof(a)) < 0) return false;

    string req = "FETCH " + id + "\n";
    send_all(s, req.c_str(), req.size());

    string line;
    char ch;
    while (recv(s, &ch, 1, 0) == 1 && ch != '\n')
        line.push_back(ch);

    if (line.empty()) return false;
    size_t size = stoul(line);

    out.resize(size);
    if (!recv_all(s, out.data(), size)) return false;
    close(s);
    return true;
}

/* ===================== MAIN ===================== */

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage:\n";
        cout << "./client upload <file> <ip:port>...\n";
        cout << "./client download <file>\n";
        return 1;
    }

    string mode = argv[1];
    string file = argv[2];

    if (mode == "upload") {
        if (argc < 6) {
            cout << "Need at least 4 servers (k=2 m=2)\n";
            return 1;
        }

        ifstream in(file, ios::binary);
        if (!in) {
            cout << "File not found\n";
            return 1;
        }

        cout << "Enter passphrase: ";
        string pass;
        getline(cin, pass);
        auto key = derive_key(pass);

        in.seekg(0, ios::end);
        size_t orig_size = in.tellg();
        in.seekg(0);

        vector<uint8_t> plain(orig_size);
        in.read((char*)plain.data(), orig_size);

        vector<uint8_t> iv;
        auto cipher = aes_encrypt(plain, key, iv);

        size_t mid = cipher.size() / 2;
        vector<uint8_t> d0(cipher.begin(), cipher.begin() + mid);
        vector<uint8_t> d1(cipher.begin() + mid, cipher.end());
        auto parity = xor_buf(d0, d1);

        string h0 = "chunk_" + to_string(sha256(d0)[0]);
        string h1 = "chunk_" + to_string(sha256(d1)[0]);
        string hp = "chunk_" + to_string(sha256(parity)[0]);

        ofstream meta(file + ".ecmeta");
        meta << orig_size << "\n";
        meta << iv.size() << "\n";
        meta.write((char*)iv.data(), iv.size());
        meta << "\n2 2\n";

        put_chunk(argv[3], h0, d0);
        meta << "0 " << h0 << " " << argv[3] << "\n";

        put_chunk(argv[4], h1, d1);
        meta << "1 " << h1 << " " << argv[4] << "\n";

        put_chunk(argv[5], hp, parity);
        meta << "2 " << hp << " " << argv[5] << "\n";

        put_chunk(argv[6], hp, parity);
        meta << "3 " << hp << " " << argv[6] << "\n";

        cout << "Encrypted erasure upload complete\n";
    }

    else if (mode == "download") {
        ifstream meta(file + ".ecmeta", ios::binary);
        if (!meta) {
            cout << "Metadata not found\n";
            return 1;
        }

        size_t orig_size;
        meta >> orig_size;

        size_t iv_len;
        meta >> iv_len;
        meta.get();

        vector<uint8_t> iv(iv_len);
        meta.read((char*)iv.data(), iv_len);
        meta.get();

        int k, m;
        meta >> k >> m;

        map<int, pair<string,string>> entries;
        int idx;
        string id, addr;
        while (meta >> idx >> id >> addr)
            entries[idx] = {id, addr};

        cout << "Enter passphrase: ";
        string pass;
        getline(cin, pass);
        auto key = derive_key(pass);

        vector<uint8_t> d0, d1, p;

        for (auto& [i, e] : entries) {
            vector<uint8_t> buf;
            if (fetch_chunk(e.second, e.first, buf)) {
                if (i == 0) d0 = buf;
                else if (i == 1) d1 = buf;
                else p = buf;
            }
        }

        vector<uint8_t> cipher;
        if (!d0.empty() && !d1.empty()) {
            cipher = d0;
            cipher.insert(cipher.end(), d1.begin(), d1.end());
        } else if (!d0.empty() && !p.empty()) {
            d1 = xor_buf(d0, p);
            cipher = d0;
            cipher.insert(cipher.end(), d1.begin(), d1.end());
        } else if (!d1.empty() && !p.empty()) {
            d0 = xor_buf(d1, p);
            cipher = d0;
            cipher.insert(cipher.end(), d1.begin(), d1.end());
        } else {
            cout << "Not enough pieces\n";
            return 1;
        }

        auto plain = aes_decrypt(cipher, key, iv);
        plain.resize(orig_size);

        ofstream out(file, ios::binary);
        out.write((char*)plain.data(), plain.size());
        cout << "Download + recovery complete\n";
    }
}
