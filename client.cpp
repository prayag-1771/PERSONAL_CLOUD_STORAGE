#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define PORT 9000
#define BUF 4096
#define IV_SIZE 12
#define TAG_SIZE 16
#define KEY_SIZE 32

/* ---------------- helpers ---------------- */

bool recv_line(int fd, std::string &line) {
    char c;
    line.clear();
    while (true) {
        int r = recv(fd, &c, 1, 0);
        if (r <= 0) return false;
        if (c == '\n') break;
        line.push_back(c);
    }
    return true;
}

int connect_server() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in s{};
    s.sin_family = AF_INET;
    s.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &s.sin_addr);
    connect(sock, (sockaddr*)&s, sizeof(s));
    return sock;
}

std::string sha256(const unsigned char *data, size_t len) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(data, len, h);
    char out[65];
    for (int i = 0; i < 32; i++)
        sprintf(out + i * 2, "%02x", h[i]);
    out[64] = 0;
    return std::string(out);
}

/* ---------------- crypto ---------------- */

/*
 * Stable key derivation:
 * key = PBKDF2(passphrase, no-salt)
 */
void derive_key(const std::string &pass, unsigned char *key) {
    PKCS5_PBKDF2_HMAC(
        pass.c_str(), pass.size(),
        nullptr, 0,          // NO SALT (stable key)
        100000,
        EVP_sha256(),
        KEY_SIZE,
        key
    );
}

/*
 * Deterministic encryption:
 * IV = first 12 bytes of SHA256(plaintext_chunk)
 */
int encrypt_chunk(unsigned char *plain, int plen,
                  unsigned char *key, unsigned char *out) {

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(plain, plen, hash);

    unsigned char iv[IV_SIZE];
    memcpy(iv, hash, IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);

    int len, clen;
    EVP_EncryptUpdate(ctx, out + IV_SIZE, &len, plain, plen);
    clen = len;

    EVP_EncryptFinal_ex(ctx, out + IV_SIZE + clen, &len);
    clen += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                        out + IV_SIZE + clen);

    memcpy(out, iv, IV_SIZE);
    EVP_CIPHER_CTX_free(ctx);

    return IV_SIZE + clen + TAG_SIZE;
}

/* ---------------- main ---------------- */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cout << "./client upload <file>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string file = argv[2];

    if (mode != "upload") {
        std::cout << "Only upload supported in this phase\n";
        return 1;
    }

    std::string pass;
    std::cout << "Enter passphrase: ";
    std::getline(std::cin, pass);

    unsigned char key[KEY_SIZE];
    derive_key(pass, key);

    std::ifstream in(file, std::ios::binary);
    if (!in) {
        std::cout << "File not found\n";
        return 1;
    }

    unsigned char plain[BUF];
    unsigned char enc[BUF + 64];

    while (true) {
        in.read((char*)plain, BUF);
        int r = in.gcount();
        if (r <= 0) break;

        int enc_len = encrypt_chunk(plain, r, key, enc);
        std::string hash = sha256(enc, enc_len);

        /* ---------- HAVE ---------- */
        int sock = connect_server();
        std::ostringstream hq;
        hq << "HAVE " << hash << "\n";
        send(sock, hq.str().c_str(), hq.str().size(), 0);

        std::string resp;
        bool ok = recv_line(sock, resp);
        close(sock);

        /* ---------- PUT unless server explicitly says YES ---------- */
        if (!ok || resp != "YES") {
            sock = connect_server();
            std::ostringstream pq;
            pq << "PUT " << hash << " " << enc_len << "\n";
            send(sock, pq.str().c_str(), pq.str().size(), 0);
            send(sock, enc, enc_len, 0);
            recv_line(sock, resp);
            close(sock);
        }

        /* ---------- APPEND ---------- */
        sock = connect_server();
        std::ostringstream aq;
        aq << "APPEND " << file << " " << hash << "\n";
        send(sock, aq.str().c_str(), aq.str().size(), 0);
        recv_line(sock, resp);
        close(sock);
    }

    in.close();
    std::cout << "Deduplicated encrypted upload complete\n";
    return 0;
}
