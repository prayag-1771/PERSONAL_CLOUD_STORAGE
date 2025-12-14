#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>

#define K 3
#define M 1
#define TOTAL (K + M)

int main() {
    std::ifstream in("test.bin", std::ios::binary | std::ios::ate);
    if (!in) {
        std::cout << "test.bin not found\n";
        return 1;
    }

    // Get original size
    size_t original_size = in.tellg();
    in.seekg(0);

    std::vector<unsigned char> data(original_size);
    in.read((char*)data.data(), original_size);

    size_t part_size = (original_size + K - 1) / K;

    std::vector<std::vector<unsigned char>> pieces(TOTAL);

    // Split data
    for (int i = 0; i < K; i++) {
        size_t start = i * part_size;
        size_t end = std::min(start + part_size, original_size);
        pieces[i].assign(data.begin() + start, data.begin() + end);
        pieces[i].resize(part_size, 0); // padding
    }

    // Parity (XOR)
    pieces[K].resize(part_size, 0);
    for (size_t i = 0; i < part_size; i++) {
        pieces[K][i] = pieces[0][i] ^ pieces[1][i] ^ pieces[2][i];
    }

    // Write pieces
    for (int i = 0; i < TOTAL; i++) {
        std::ofstream out("piece" + std::to_string(i),
                          std::ios::binary);
        out.write((char*)pieces[i].data(), part_size);
    }

    std::cout << "Encoding done\n";

    // ---- simulate loss of piece1 ----
    pieces[1].clear();

    // ---- recovery ----
    pieces[1].resize(part_size);
    for (size_t i = 0; i < part_size; i++) {
        pieces[1][i] =
            pieces[0][i] ^
            pieces[2][i] ^
            pieces[3][i];
    }

    // Rebuild original (truncate to original size)
    std::ofstream rebuilt("recovered.bin", std::ios::binary);
    size_t written = 0;

    for (int i = 0; i < K && written < original_size; i++) {
        size_t to_write = std::min(part_size, original_size - written);
        rebuilt.write((char*)pieces[i].data(), to_write);
        written += to_write;
    }

    std::cout << "Recovery done\n";
}
