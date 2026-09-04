#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Wire vocabulary. Both ends build and parse their lines through this header
// so a change to the grammar cannot drift between client and server.
//
//   -> HELLO pcs/3                  <- OK pcs/3
//   -> PING                         <- PONG                    (pre-auth)
//   -> LOGIN <user> <password>      <- OK | ERR <reason>
//   -> AUTH <token>                 <- OK | ERR <reason>
//
// Two separate things are being established, because they answer different
// questions. LOGIN says who you are, and scopes every file command below to
// that account. AUTH presents the shared machine token, and only unlocks the
// chunk commands, which is all a peer needs to hold shards on someone's
// behalf. A connection may present either, or both.
//
//   -- file commands: require LOGIN --
//   -> STAT <name>                  <- META <size> <tag> | NONE
//   -> PUTFILE <size> <tag> <name>  <- OK            (then <size> raw bytes)
//   -> GETFILE <name>               <- DATA <size> | NONE   (then raw bytes)
//   -> DELFILE <name>               <- OK | NONE
//
// A file name goes last in every command that carries one, because names may
// contain spaces. Anything before it is a fixed number of fields, so the
// remainder of the line is the name.
//   -- chunk commands: require AUTH --
//   -> PUTCHUNK <id> <size>         <- OK            (then <size> raw bytes)
//   -> GETCHUNK <id>                <- DATA <size> | NONE   (then raw bytes)
//   -> DELCHUNK <id>                <- OK
//   -> LIST                         <- COUNT <n>, then n lines
//                                      "<size> <modified> <name>"
//   -> QUIT                         <- BYE
//
// A connection carries as many commands as the client wants; it is not one
// command per TCP connection.
namespace pcs {
namespace proto {

inline constexpr char kHello[]    = "HELLO";
inline constexpr char kPing[]     = "PING";
inline constexpr char kAuth[]     = "AUTH";
inline constexpr char kLogin[]    = "LOGIN";
inline constexpr char kStat[]     = "STAT";
inline constexpr char kPutFile[]  = "PUTFILE";
inline constexpr char kGetFile[]  = "GETFILE";
inline constexpr char kDelFile[]  = "DELFILE";
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

// Splits into at most `limit` fields, with the last one taking the rest of
// the line verbatim. File names may contain spaces, so any command carrying
// one puts it last and parses it with this.
std::vector<std::string> split_n(const std::string& line, size_t limit);

// Parses a decimal size, rejecting anything negative, non-numeric or above
// `limit`. Sizes arrive from the network, so an overflowing value must not
// become a huge allocation.
bool parse_size(const std::string& text, uint64_t limit, uint64_t& out);

}  // namespace proto
}  // namespace pcs
