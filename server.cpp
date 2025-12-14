#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;
namespace fs = std::filesystem;

/*
 PROTOCOL (FINAL):

 PUT <chunk_id> <size>\n
 <raw bytes>

 FETCH <chunk_id>\n

 RESPONSE (FETCH):
 <size>\n
 <raw bytes>
*/

static bool recv_all(int sock, void* buf, size_t size) {
    size_t got = 0;
    char* p = static_cast<char*>(buf);
    while (got < size) {
        ssize_t r = recv(sock, p + got, size - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

static bool send_all(int sock, const void* buf, size_t size) {
    size_t sent = 0;
    const char* p = static_cast<const char*>(buf);
    while (sent < size) {
        ssize_t s = send(sock, p + sent, size - sent, 0);
        if (s <= 0) return false;
        sent += s;
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: ./server <port>\n";
        return 1;
    }

    int port = stoi(argv[1]);

    // Persistent storage path (absolute, deterministic)
    fs::path storage =
        fs::current_path() /
        "storage" /
        ("server_" + to_string(port)) /
        "chunks";

    fs::create_directories(storage);

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

    cout << "[server] listening on port " << port << endl;
    cout << "[server] storage: " << storage << endl;

    while (true) {
        int client = accept(server_fd, nullptr, nullptr);
        if (client < 0) continue;

        // Read command line
        string line;
        char ch;
        while (recv(client, &ch, 1, 0) == 1) {
            if (ch == '\n') break;
            line.push_back(ch);
        }

        if (line.rfind("PUT ", 0) == 0) {
            // PUT <chunk_id> <size>
            string cmd, chunk_id;
            size_t size;

            stringstream ss(line);
            ss >> cmd >> chunk_id >> size;

            if (chunk_id.empty() || size == 0) {
                close(client);
                continue;
            }

            vector<char> data(size);
            if (!recv_all(client, data.data(), size)) {
                close(client);
                continue;
            }

            ofstream out(storage / chunk_id, ios::binary);
            out.write(data.data(), data.size());
            out.close();

            cout << "[server " << port << "] stored chunk " << chunk_id
                 << " (" << size << " bytes)" << endl;
        }

        else if (line.rfind("FETCH ", 0) == 0) {
            // FETCH <chunk_id>
            string chunk_id = line.substr(6);
            fs::path file = storage / chunk_id;

            if (!fs::exists(file)) {
                close(client);
                continue;
            }

            ifstream in(file, ios::binary);
            in.seekg(0, ios::end);
            size_t size = in.tellg();
            in.seekg(0);

            string header = to_string(size) + "\n";
            send_all(client, header.c_str(), header.size());

            vector<char> buf(size);
            in.read(buf.data(), size);
            send_all(client, buf.data(), buf.size());
        }

        close(client);
    }
}
