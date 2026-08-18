#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pcs {

std::string to_hex(const uint8_t* data, size_t len);
std::string to_hex(const std::vector<uint8_t>& data);

// Returns false if the input has odd length or a non-hex digit, leaving
// `out` untouched. Callers treat hex from the wire as untrusted.
bool from_hex(const std::string& hex, std::vector<uint8_t>& out);

}  // namespace pcs
