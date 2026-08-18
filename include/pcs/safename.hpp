#pragma once

#include <string>

namespace pcs {

// True only for a single path component that is safe to join onto a storage
// directory: no separators, no traversal, no NUL, no control characters and
// no leading dot. Every name arriving from the network passes through here
// before it is used to build a path.
bool is_safe_name(const std::string& name);

// True for a lowercase hex chunk identifier of exactly 64 characters.
bool is_safe_chunk_id(const std::string& id);

}  // namespace pcs
