#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "pcs/stream.hpp"
#include "pcs/wire.hpp"

namespace pcs {
namespace client {

// One authenticated connection to a server or peer. Every request the client
// can make lives here, so the command layer never touches the wire grammar.
class Remote {
public:
    ~Remote();

    // Connects, performs the version handshake and authenticates.
    static std::unique_ptr<Remote> connect(const std::string& address,
                                           const std::string& token,
                                           std::string& error);

    // Liveness probe. Deliberately needs no token, so deciding whether to
    // fall back to peers is a single cheap round trip.
    static bool reachable(const std::string& address);

    // `exists` distinguishes "no such file" from a failed request.
    bool stat(const std::string& name, uint64_t& size, std::string& tag,
              bool& exists, std::string& error);

    bool put_file(const std::string& name,
                  const std::filesystem::path& source,
                  const std::string& dedup_tag, const ProgressFn& progress,
                  std::string& error);

    bool get_file(const std::string& name,
                  const std::filesystem::path& destination, bool& found,
                  const ProgressFn& progress, std::string& error);

    bool put_chunk(const std::string& id, const std::filesystem::path& source,
                   std::string& error);

    bool get_chunk(const std::string& id,
                   const std::filesystem::path& destination, bool& found,
                   std::string& error);

    bool del_chunk(const std::string& id, std::string& error);

    bool list(std::vector<std::pair<std::string, uint64_t>>& out,
              std::string& error);

    void quit();

private:
    explicit Remote(ChannelPtr channel);

    bool send_file_body(const std::filesystem::path& source, uint64_t size,
                        const ProgressFn& progress, std::string& error);
    bool read_body_to_file(const std::filesystem::path& destination,
                           uint64_t size, const ProgressFn& progress,
                           std::string& error);

    ChannelPtr channel_;
};

}  // namespace client
}  // namespace pcs
