#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>

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
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<uint8_t> out(cipher.size());
    int len1, len2;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, out.data(), &len1, cipher.data(), cipher.size());
    EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2);
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
            string cmd, filename, key_hex, iv_hex;
            size_t cipher_size;
            stringstream ss(line);
            ss >> cmd >> filename >> cipher_size >> key_hex >> iv_hex;

            if (filename.empty() || cipher_size == 0) {
                close(client);
                continue;
            }

            vector<char> raw(cipher_size);
            if (!recv_all(client, raw.data(), cipher_size)) {
                close(client);
                continue;
            }

            vector<uint8_t> cipher_data(raw.begin(), raw.end());
            auto key = hex_to_bytes(key_hex);
            auto iv = hex_to_bytes(iv_hex);
            auto plain = aes_decrypt(cipher_data, key, iv);

            ofstream out(file_storage / filename, ios::binary);
            out.write((char*)plain.data(), plain.size());
            out.close();

            string resp = "OK\n";
            send_all(client, resp.c_str(), resp.size());

            cout << "[server " << port << "] stored file '"
                 << filename << "' (" << plain.size() << " bytes, decrypted)" << endl;
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

        else if (line.rfind("FETCH_FILE ", 0) == 0) {
            string fname = line.substr(11);
            fs::path file = file_storage / fname;

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

            cout << "[server " << port << "] served file '" << fname
                 << "' (" << size << " bytes)" << endl;
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
