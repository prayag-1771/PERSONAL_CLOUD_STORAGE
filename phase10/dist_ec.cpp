#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>

#define K 3
#define M 1
#define TOTAL (K + M)

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

void send_piece(const std::string &server,
                const std::string &id,
                const std::vector<unsigned char> &data) {

    int s = connect_server(server);
    std::string header =
        "PUT " + id + " " + std::to_string(data.size()) + "\n";

    send(s, header.c_str(), header.size(), 0);
    send(s, data.data(), data.size(), 0);
    close(s);
}

int main() {
    std::vector<std::string> servers = {
        "127.0.0.1:9000",
        "127.0.0.1:9001",
        "127.0.0.1:9002",
        "127.0.0.1:9003"
    };

    std::ifstream in("chunk.bin", std::ios::binary | std::ios::ate);
    if (!in) {
        std::cout << "chunk.bin not found\n";
        return 1;
    }

    size_t size = in.tellg();
    in.seekg(0);

    std::vector<unsigned char> data(size);
    in.read((char*)data.data(), size);

    size_t part = (size + K - 1) / K;

    std::vector<std::vector<unsigned char>> pieces(TOTAL);

    // Split
    for (int i = 0; i < K; i++) {
        size_t start = i * part;
        size_t end = std::min(start + part, size);
        pieces[i].assign(data.begin() + start, data.begin() + end);
        pieces[i].resize(part, 0);
    }

    // Parity
    pieces[K].resize(part, 0);
    for (size_t i = 0; i < part; i++) {
        pieces[K][i] =
            pieces[0][i] ^
            pieces[1][i] ^
            pieces[2][i];
    }

    // Distribute
    for (int i = 0; i < TOTAL; i++) {
        std::string pid = "piece_" + std::to_string(i);
        send_piece(servers[i], pid, pieces[i]);
        std::cout << "Stored " << pid
                  << " on " << servers[i] << "\n";
    }

    std::cout << "Distributed erasure storage complete\n";
}
