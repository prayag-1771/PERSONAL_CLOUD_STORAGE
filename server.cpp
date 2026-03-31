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

    fs::path chunk_storage =
        fs::current_path() / "storage" / ("server_" + to_string(port)) / "chunks";
    fs::create_directories(chunk_storage);

    fs::path file_storage =
        fs::current_path() / "storage" / ("server_" + to_string(port)) / "files";
    fs::create_directories(file_storage);

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
    cout << "[server] chunks: " << chunk_storage << endl;
    cout << "[server] files:  " << file_storage << endl;

    while (true) {
        int client = accept(server_fd, nullptr, nullptr);
        if (client < 0) continue;

        string line;
        char ch;
        while (recv(client, &ch, 1, 0) == 1) {
            if (ch == '\n') break;
            line.push_back(ch);
        }

        if (line == "PING") {
            string resp = "PONG\n";
            send_all(client, resp.c_str(), resp.size());
            cout << "[server " << port << "] PING -> PONG" << endl;
        }

        else if (line.rfind("UPLOAD ", 0) == 0) {
            string cmd, filename;
            size_t size;
            stringstream ss(line);
            ss >> cmd >> filename >> size;

            if (filename.empty() || size == 0) {
                close(client);
                continue;
            }

            vector<char> data(size);
            if (!recv_all(client, data.data(), size)) {
                close(client);
                continue;
            }

            ofstream out(file_storage / filename, ios::binary);
            out.write(data.data(), data.size());
            out.close();

            string resp = "OK\n";
            send_all(client, resp.c_str(), resp.size());

            cout << "[server " << port << "] stored file '"
                 << filename << "' (" << size << " bytes)" << endl;
        }

        else if (line.rfind("PUT ", 0) == 0) {
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

            ofstream out(chunk_storage / chunk_id, ios::binary);
            out.write(data.data(), data.size());
            out.close();

            cout << "[server " << port << "] stored chunk "
                 << chunk_id << " (" << size << " bytes)" << endl;
        }

        else if (line.rfind("FETCH ", 0) == 0) {
            string chunk_id = line.substr(6);
            fs::path file = chunk_storage / chunk_id;

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

        else if (line.rfind("DELETE ", 0) == 0) {
            string chunk_id = line.substr(7);
            fs::path file = chunk_storage / chunk_id;

            if (fs::exists(file)) {
                fs::remove(file);
                cout << "[server " << port << "] deleted chunk " << chunk_id << endl;
            }

            string resp = "OK\n";
            send_all(client, resp.c_str(), resp.size());
        }

        else if (line == "LIST") {
            for (auto& entry : fs::directory_iterator(file_storage)) {
                string name = entry.path().filename().string() + "\n";
                send_all(client, name.c_str(), name.size());
            }
            string end = "END\n";
            send_all(client, end.c_str(), end.size());
        }

        close(client);
    }
}
