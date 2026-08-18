#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "pcs/cipher.hpp"
#include "pcs/hex.hpp"

// A scratch directory that cleans up after itself, so a failing test cannot
// leave megabytes of sealed streams behind.
namespace pcstest {

class TempDir {
public:
    TempDir() {
        path_ = std::filesystem::temp_directory_path() /
                ("pcs-test-" + pcs::to_hex(pcs::random_bytes(8)));
        std::filesystem::create_directories(path_);
    }

    ~TempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    std::filesystem::path file(const std::string& name) const {
        return path_ / name;
    }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

// Writes `size` bytes of repeatable, non-uniform content. A pattern beats
// all-zeros here: it would hide an off-by-one that silently drops or
// duplicates a slice.
inline void write_pattern(const std::filesystem::path& path, uint64_t size) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    std::vector<char> buf(64 * 1024);
    uint64_t written = 0;
    while (written < size) {
        const size_t want =
            static_cast<size_t>(std::min<uint64_t>(buf.size(), size - written));
        for (size_t i = 0; i < want; i++)
            buf[i] = static_cast<char>((written + i) * 31 + ((written + i) >> 8));
        out.write(buf.data(), static_cast<std::streamsize>(want));
        written += want;
    }
}

inline std::vector<uint8_t> read_all(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

inline bool files_identical(const std::filesystem::path& a,
                            const std::filesystem::path& b) {
    return read_all(a) == read_all(b);
}

}  // namespace pcstest
