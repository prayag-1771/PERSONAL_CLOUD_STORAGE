#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "pcs/stream.hpp"
#include "pcs/wire.hpp"
#include "workspace.hpp"

namespace pcs {
namespace client {

// One authenticated connection to a server or peer. Every request the client
// can make lives here, so the command layer never touches the wire grammar.
// What a connection is going to be used for, which decides what it has to
// prove. Asking for the narrower one keeps a peer connection from needing an
// account password it has no business knowing.
enum class Access {
    Files,   // establishes an account with LOGIN
    Chunks,  // presents the shared machine token with AUTH
};

class Remote {
public:
    ~Remote();

    // Connects, performs the version handshake, and proves whatever the
    // requested access requires.
    static std::unique_ptr<Remote> connect(const std::string& address,
                                           const Options& options,
                                           Access access, std::string& error);

    // Liveness probe. Deliberately needs no token, so deciding whether to
    // fall back to peers is a single cheap round trip.
    static bool reachable(const std::string& address,
                          const TlsTrust& trust);

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

    // `found` distinguishes "there was nothing to delete" from a failure.
    bool del_file(const std::string& name, bool& found, std::string& error);

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
