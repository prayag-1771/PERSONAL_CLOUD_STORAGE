#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define BUF 4096
#define CHUNKS "storage/chunks/"
#define FILES  "storage/files/"

bool recv_line(int fd, std::string &line) {
    char c; line.clear();
    while (recv(fd, &c, 1, 0) == 1) {
        if (c == '\n') return true;
        line.push_back(c);
    }
    return false;
}

bool exists(const std::string &p) {
    return access(p.c_str(), F_OK) == 0;
}

int count_lines(const std::string &f) {
    std::ifstream in(f);
    int c = 0; std::string s;
    while (std::getline(in, s)) if (!s.empty()) c++;
    return c;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cout << "Usage: ./server <port>\n";
        return 1;
    }

    int port = std::stoi(argv[1]);

    mkdir("storage", 0755);
    mkdir(CHUNKS, 0755);
    mkdir(FILES, 0755);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(sfd, (sockaddr*)&addr, sizeof(addr));
    listen(sfd, 10);

    std::cout << "Server listening on " << port << "\n";

    while (true) {
        int cfd = accept(sfd, nullptr, nullptr);
        if (cfd < 0) continue;

        std::string h;
        if (!recv_line(cfd, h)) { close(cfd); continue; }

        std::istringstream iss(h);
        std::string cmd; iss >> cmd;

        if (cmd == "BEGIN") {
            std::string f; iss >> f;
            std::ofstream(FILES + f + ".meta", std::ios::trunc);
            send(cfd, "OK\n", 3, 0);
        }

        else if (cmd == "RESUME") {
            std::string f; iss >> f;
            int off = exists(FILES + f + ".meta")
                      ? count_lines(FILES + f + ".meta")
                      : 0;
            std::ostringstream r;
            r << "OFFSET " << off << "\n";
            send(cfd, r.str().c_str(), r.str().size(), 0);
        }

        else if (cmd == "HAVE") {
            std::string x; iss >> x;
            send(cfd, exists(CHUNKS + x) ? "YES\n" : "NO\n", 4, 0);
        }

        else if (cmd == "PUT") {
            std::string x; int sz;
            iss >> x >> sz;
            std::vector<char> b(sz);
            int r = 0;
            while (r < sz)
                r += recv(cfd, b.data()+r, sz-r, 0);

            if (!exists(CHUNKS + x)) {
                std::ofstream o(CHUNKS + x, std::ios::binary);
                o.write(b.data(), sz);
            }
            send(cfd, "OK\n", 3, 0);
        }

        else if (cmd == "APPEND") {
            std::string f, x;
            iss >> f >> x;
            std::ofstream o(FILES + f + ".meta", std::ios::app);
            o << x << "\n";
            send(cfd, "OK\n", 3, 0);
        }

        else if (cmd == "DOWNLOAD") {
            std::string f; iss >> f;
            std::ifstream m(FILES + f + ".meta");
            if (!m) {
                send(cfd, "ERROR\n", 6, 0);
            } else {
                send(cfd, "OK\n", 3, 0);
                std::string x;
                while (std::getline(m, x)) {
                    if (x.empty()) continue;
                    std::ifstream in(CHUNKS + x, std::ios::binary);
                    in.seekg(0, std::ios::end);
                    int sz = in.tellg();
                    in.seekg(0);
                    std::ostringstream h;
                    h << "CHUNK " << sz << "\n";
                    send(cfd, h.str().c_str(), h.str().size(), 0);
                    char buf[BUF];
                    while (!in.eof()) {
                        in.read(buf, BUF);
                        send(cfd, buf, in.gcount(), 0);
                    }
                }
            }
        }
        close(cfd);
    }
}
