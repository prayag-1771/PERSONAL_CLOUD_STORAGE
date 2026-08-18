#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Wire vocabulary. Both ends build and parse their lines through this header
// so a change to the grammar cannot drift between client and server.
//
//   -> HELLO pcs/2                  <- OK pcs/2
//   -> PING                         <- PONG                    (pre-auth)
//   -> AUTH <token>                 <- OK | ERR <reason>
//   -- everything below requires a successful AUTH --
//   -> STAT <name>                  <- META <size> <tag> | NONE
//   -> PUTFILE <name> <size> <tag>  <- OK            (then <size> raw bytes)
//   -> GETFILE <name>               <- DATA <size> | NONE   (then raw bytes)
//   -> PUTCHUNK <id> <size>         <- OK            (then <size> raw bytes)
//   -> GETCHUNK <id>                <- DATA <size> | NONE   (then raw bytes)
//   -> DELCHUNK <id>                <- OK
//   -> LIST                         <- COUNT <n>, then n lines "<name> <size>"
//   -> QUIT                         <- BYE
//
// A connection carries as many commands as the client wants; it is not one
// command per TCP connection.
namespace pcs {
namespace proto {

inline constexpr char kHello[]    = "HELLO";
inline constexpr char kPing[]     = "PING";
inline constexpr char kAuth[]     = "AUTH";
inline constexpr char kStat[]     = "STAT";
inline constexpr char kPutFile[]  = "PUTFILE";
inline constexpr char kGetFile[]  = "GETFILE";
inline constexpr char kPutChunk[] = "PUTCHUNK";
inline constexpr char kGetChunk[] = "GETCHUNK";
inline constexpr char kDelChunk[] = "DELCHUNK";
inline constexpr char kList[]     = "LIST";
inline constexpr char kQuit[]     = "QUIT";

inline constexpr char kOk[]    = "OK";
inline constexpr char kErr[]   = "ERR";
inline constexpr char kPong[]  = "PONG";
inline constexpr char kNone[]  = "NONE";
inline constexpr char kData[]  = "DATA";
inline constexpr char kMeta[]  = "META";
inline constexpr char kCount[] = "COUNT";
inline constexpr char kBye[]   = "BYE";

// Splits a line on single spaces. Empty fields are dropped.
std::vector<std::string> split(const std::string& line);

// Parses a decimal size, rejecting anything negative, non-numeric or above
// `limit`. Sizes arrive from the network, so an overflowing value must not
// become a huge allocation.
bool parse_size(const std::string& text, uint64_t limit, uint64_t& out);

}  // namespace proto
}  // namespace pcs
