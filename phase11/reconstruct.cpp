#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>

#define K 3

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

std::vector<unsigned char> fetch_piece(
    const std::string &server,
    const std::string &id)
{
    int s = connect_server(server);
    std::string cmd = "FETCH " + id + "\n";
    send(s, cmd.c_str(), cmd.size(), 0);

    std::string line;
    char c;

    while (recv(s, &c, 1, 0) == 1 && c != '\n')
        line.push_back(c);

    if (line != "OK") {
        std::cout << "Failed to fetch " << id << "\n";
        exit(1);
    }

    line.clear();
    while (recv(s, &c, 1, 0) == 1 && c != '\n')
        line.push_back(c);

    int size = std::stoi(line.substr(6));
    std::vector<unsigned char> buf(size);

    int r = 0;
    while (r < size)
        r += recv(s, buf.data() + r, size - r, 0);

    close(s);
    return buf;
}

int main() {
    size_t original_size = 30;

    std::vector<std::pair<std::string,std::string>> pieces = {
        {"piece_0", "127.0.0.1:9000"},
        {"piece_1", "127.0.0.1:9001"},
        {"piece_2", "127.0.0.1:9002"},
        {"piece_3", "127.0.0.1:9003"}
    };

    auto p0 = fetch_piece(pieces[0].second, pieces[0].first);
    auto p2 = fetch_piece(pieces[2].second, pieces[2].first);
    auto p3 = fetch_piece(pieces[3].second, pieces[3].first);

    size_t part = p0.size();
    std::vector<unsigned char> p1(part);

    for (size_t i = 0; i < part; i++)
        p1[i] = p0[i] ^ p2[i] ^ p3[i];

    std::ofstream out("recovered_chunk.bin", std::ios::binary);
    size_t written = 0;

    for (auto &p : {p0, p1, p2}) {
        size_t to_write = std::min(part, original_size - written);
        out.write((char*)p.data(), to_write);
        written += to_write;
    }

    std::cout << "Reconstruction complete\n";
}
