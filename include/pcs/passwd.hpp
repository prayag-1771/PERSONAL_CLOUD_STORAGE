#pragma once

#include <cstdint>
#include <string>

// Password verifiers for user accounts.
//
// A verifier is a self-describing string:
//
//   pbkdf2-sha256$<iterations>$<salt-hex>$<hash-hex>
//
// carrying its own algorithm and cost, so raising the cost later does not
// invalidate accounts created before the change: existing verifiers keep
// stating what they were made with.
namespace pcs {

// Generates a fresh random salt and returns a complete verifier string.
std::string hash_password(const std::string& password, uint32_t iterations);

// Constant-time check of a password against a stored verifier. Returns false
// for a malformed or unsupported verifier rather than throwing.
bool verify_password(const std::string& password, const std::string& verifier);

// True if the verifier was produced with fewer iterations than `wanted`, so a
// caller can transparently re-hash on the next successful login.
bool verifier_is_stale(const std::string& verifier, uint32_t wanted);

}  // namespace pcs
