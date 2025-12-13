#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define CHUNK 4096
#define KEYLEN 32
#define IVLEN 12
#define TAGLEN 16

bool recv_line(int fd, std::string &line) {
    char c; line.clear();
    while (recv(fd, &c, 1, 0) == 1) {
        if (c == '\n') return true;
        line.push_back(c);
    }
    return false;
}

int connect_server(const std::string &addr) {
    auto p = addr.find(':');
    std::string ip = addr.substr(0, p);
    int port = std::stoi(addr.substr(p+1));

    int s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &a.sin_addr);

    if (connect(s, (sockaddr*)&a, sizeof(a)) < 0) {
        perror("connect");
        exit(1);
    }
    return s;
}

void derive_key(const std::string &pass, unsigned char *key) {
    PKCS5_PBKDF2_HMAC(pass.c_str(), pass.size(),
        nullptr, 0, 100000, EVP_sha256(), KEYLEN, key);
}

int encrypt_chunk(unsigned char *plain, int plen,
                  unsigned char *key, unsigned char *out) {

    unsigned char iv[IVLEN];
    SHA256(plain, plen, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IVLEN, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);

    int len, clen;
    EVP_EncryptUpdate(ctx, out + IVLEN, &len, plain, plen);
    clen = len;
    EVP_EncryptFinal_ex(ctx, out + IVLEN + clen, &len);
    clen += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAGLEN,
                        out + IVLEN + clen);

    memcpy(out, iv, IVLEN);
    EVP_CIPHER_CTX_free(ctx);

    return IVLEN + clen + TAGLEN;
}

std::string sha256(const unsigned char *d, int n) {
    unsigned char h[32];
    SHA256(d, n, h);
    char out[65];
    for (int i = 0; i < 32; i++)
        sprintf(out + i*2, "%02x", h[i]);
    out[64] = 0;
    return out;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cout <<
        "Usage:\n"
        "  ./client upload <file> <ip:port>\n"
        "  ./client download <file> <ip:port>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string file = argv[2];
    std::string server = argv[3];

    std::string pass;
    std::cout << "Enter passphrase: ";
    std::getline(std::cin, pass);

    unsigned char key[KEYLEN];
    derive_key(pass, key);

    if (mode == "upload") {
        int s = connect_server(server);
        std::ostringstream b;
        b << "BEGIN " << file << "\n";
        send(s, b.str().c_str(), b.str().size(), 0);
        recv_line(s, pass);
        close(s);

        s = connect_server(server);
        std::ostringstream r;
        r << "RESUME " << file << "\n";
        send(s, r.str().c_str(), r.str().size(), 0);
        std::string resp;
        recv_line(s, resp);
        close(s);

        int offset = std::stoi(resp.substr(7));
        std::ifstream in(file, std::ios::binary);
        in.seekg((long long)offset * CHUNK);

        unsigned char plain[CHUNK], enc[CHUNK + 64];

        while (true) {
            in.read((char*)plain, CHUNK);
            int n = in.gcount();
            if (n <= 0) break;

            int esz = encrypt_chunk(plain, n, key, enc);
            std::string h = sha256(enc, esz);

            s = connect_server(server);
            std::ostringstream q;
            q << "HAVE " << h << "\n";
            send(s, q.str().c_str(), q.str().size(), 0);
            recv_line(s, resp);
            close(s);

            if (resp != "YES") {
                s = connect_server(server);
                std::ostringstream p;
                p << "PUT " << h << " " << esz << "\n";
                send(s, p.str().c_str(), p.str().size(), 0);
                send(s, enc, esz, 0);
                recv_line(s, resp);
                close(s);
            }

            s = connect_server(server);
            std::ostringstream a;
            a << "APPEND " << file << " " << h << "\n";
            send(s, a.str().c_str(), a.str().size(), 0);
            recv_line(s, resp);
            close(s);
        }
        std::cout << "Upload complete\n";
    }

    if (mode == "download") {
        int s = connect_server(server);
        std::ostringstream q;
        q << "DOWNLOAD " << file << "\n";
        send(s, q.str().c_str(), q.str().size(), 0);

        std::string line;
        recv_line(s, line);
        if (line != "OK") {
            std::cout << "Download failed\n";
            return 1;
        }

        std::ofstream out(file, std::ios::binary);
        unsigned char buf[CHUNK + 64];

        while (recv_line(s, line)) {
            if (line.rfind("CHUNK ", 0) != 0) break;
            int sz = std::stoi(line.substr(6));
            int r = 0;
            while (r < sz)
                r += recv(s, buf + r, sz - r, 0);
            out.write((char*)buf, sz);
        }
        close(s);
        std::cout << "Download complete\n";
    }
}
