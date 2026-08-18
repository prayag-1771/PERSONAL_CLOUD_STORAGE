#include "harness.hpp"

#include "pcs/passwd.hpp"

using namespace std;
using namespace pcs;

namespace {

// Deliberately low, so the suite is not spending half a second per check.
// The production cost lives in config::kPasswordIterations.
constexpr uint32_t kFast = 1000;

}  // namespace

PCS_TEST(a_password_verifies_against_its_own_verifier) {
    const string verifier = hash_password("correct horse battery", kFast);
    CHECK(!verifier.empty());
    CHECK(verify_password("correct horse battery", verifier));
}

PCS_TEST(a_wrong_password_is_rejected) {
    const string verifier = hash_password("correct horse battery", kFast);
    CHECK(!verify_password("correct horse batterz", verifier));
    CHECK(!verify_password("", verifier));
    CHECK(!verify_password("correct horse battery ", verifier));
}

PCS_TEST(the_same_password_hashes_differently_every_time) {
    // A fresh random salt per verifier means two accounts with the same
    // password do not look the same on disk.
    const string a = hash_password("shared password", kFast);
    const string b = hash_password("shared password", kFast);
    CHECK(a != b);
    CHECK(verify_password("shared password", a));
    CHECK(verify_password("shared password", b));
}

PCS_TEST(the_verifier_states_its_own_scheme_and_cost) {
    const string verifier = hash_password("something", kFast);
    CHECK_EQ(verifier.rfind("pbkdf2-sha256$", 0), size_t{0});
    CHECK(verifier.find("$1000$") != string::npos);
}

PCS_TEST(a_malformed_verifier_fails_instead_of_throwing) {
    CHECK(!verify_password("anything", ""));
    CHECK(!verify_password("anything", "not-a-verifier"));
    CHECK(!verify_password("anything", "pbkdf2-sha256$"));
    CHECK(!verify_password("anything", "pbkdf2-sha256$1000$zz$zz"));
    CHECK(!verify_password("anything", "scrypt$1000$aabb$ccdd"));
    CHECK(!verify_password("anything", "pbkdf2-sha256$0$aabb$" + string(64, 'a')));
    // Right shape, wrong hash length.
    CHECK(!verify_password("anything", "pbkdf2-sha256$1000$aabb$aabb"));
}

PCS_TEST(cost_changes_are_detectable_for_rehashing) {
    const string verifier = hash_password("something", kFast);
    CHECK(!verifier_is_stale(verifier, kFast));
    CHECK(verifier_is_stale(verifier, kFast * 10));

    // An unreadable verifier counts as stale, so it gets replaced rather
    // than silently kept.
    CHECK(verifier_is_stale("garbage", kFast));
}

PCS_TEST(verifiers_are_bound_to_their_own_salt) {
    // Swapping in another verifier's salt must not still validate.
    const string verifier = hash_password("password one", kFast);
    const size_t first = verifier.find('$', 0);
    const size_t second = verifier.find('$', first + 1);
    const size_t third = verifier.find('$', second + 1);

    const string other_salt = string(32, 'a');
    const string tampered = verifier.substr(0, second + 1) + other_salt +
                            verifier.substr(third);
    CHECK(!verify_password("password one", tampered));
}
