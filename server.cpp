#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#define PORT 9000
#define BUF 4096
#define STORAGE "storage/"
#define CHUNKS  "storage/chunks/"
#define FILES   "storage/files/"

/* ---------- helpers ---------- */

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

std::string sha256(const unsigned char *data, size_t len) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(data, len, h);
    char out[65];
    for (int i = 0; i < 32; i++)
        sprintf(out + i * 2, "%02x", h[i]);
    out[64] = 0;
    return std::string(out);
}

bool file_exists(const std::string &p) {
    return access(p.c_str(), F_OK) == 0;
}

/* ---------- main ---------- */

int main() {
    mkdir(STORAGE, 0755);
    mkdir(CHUNKS, 0755);
    mkdir(FILES, 0755);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(sfd, (sockaddr*)&addr, sizeof(addr));
    listen(sfd, 10);

    std::cout << "Dedup server listening on " << PORT << "\n";

    while (true) {
        int cfd = accept(sfd, nullptr, nullptr);
        if (cfd < 0) continue;

        std::string header;
        if (!recv_line(cfd, header)) {
            close(cfd);
            continue;
        }

        std::istringstream iss(header);
        std::string cmd;
        iss >> cmd;

        /* ---------- HAVE ---------- */
        if (cmd == "HAVE") {
            std::string hash;
            iss >> hash;

            std::string path = std::string(CHUNKS) + hash;
            if (file_exists(path))
                send(cfd, "YES\n", 4, 0);
            else
                send(cfd, "NO\n", 3, 0);

            close(cfd);
            continue;
        }

        /* ---------- PUT ---------- */
        if (cmd == "PUT") {
            std::string hash;
            int size;
            iss >> hash >> size;

            std::vector<char> buf(size);
            int rec = 0;
            while (rec < size) {
                int n = recv(cfd, buf.data() + rec, size - rec, 0);
                if (n <= 0) break;
                rec += n;
            }

            if (rec != size) {
                close(cfd);
                continue;
            }

            std::string calc = sha256((unsigned char*)buf.data(), size);
            if (calc != hash) {
                close(cfd);
                continue;
            }

            std::string path = std::string(CHUNKS) + hash;
            if (!file_exists(path)) {
                std::ofstream out(path, std::ios::binary);
                out.write(buf.data(), size);
                out.close();
            }

            send(cfd, "OK\n", 3, 0);
            close(cfd);
            continue;
        }

        /* ---------- FILE META (append chunk) ---------- */
        if (cmd == "APPEND") {
            std::string filename, hash;
            iss >> filename >> hash;

            std::string meta = std::string(FILES) + filename + ".meta";
            std::ofstream out(meta, std::ios::app);
            out << hash << "\n";
            out.close();

            send(cfd, "OK\n", 3, 0);
            close(cfd);
            continue;
        }

        /* ---------- DOWNLOAD ---------- */
        if (cmd == "DOWNLOAD") {
            std::string filename;
            iss >> filename;

            std::string meta = std::string(FILES) + filename + ".meta";
            std::ifstream in(meta);
            if (!in) {
                send(cfd, "ERROR\n", 6, 0);
                close(cfd);
                continue;
            }

            std::vector<std::string> chunks;
            std::string line;
            while (std::getline(in, line)) {
                if (!line.empty())
                    chunks.push_back(line);
            }
            in.close();

            send(cfd, "OK\n", 3, 0);

            for (auto &h : chunks) {
                std::string path = std::string(CHUNKS) + h;
                std::ifstream c(path, std::ios::binary);
                char buf[BUF];
                while (!c.eof()) {
                    c.read(buf, BUF);
                    send(cfd, buf, c.gcount(), 0);
                }
                c.close();
            }

            close(cfd);
            continue;
        }

        /* ---------- UNKNOWN ---------- */
        send(cfd, "ERROR\n", 6, 0);
        close(cfd);
    }
}
