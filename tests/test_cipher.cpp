#include "harness.hpp"

#include "pcs/cipher.hpp"
#include "pcs/config.hpp"
#include "pcs/digest.hpp"
#include "pcs/hex.hpp"

using namespace std;
using namespace pcs;

namespace {

const vector<uint8_t> kAad = {'a', 'a', 'd'};

}  // namespace

PCS_TEST(gcm_seals_and_opens) {
    const vector<uint8_t> key = random_bytes(config::kKeyLen);
    const vector<uint8_t> iv = random_bytes(config::kIvLen);
    const vector<uint8_t> plain = {'h', 'e', 'l', 'l', 'o'};

    vector<uint8_t> cipher, tag;
    CHECK(aes_gcm_seal(key, iv, kAad, plain.data(), plain.size(), cipher, tag));
    CHECK_EQ(cipher.size(), plain.size());
    CHECK_EQ(tag.size(), config::kTagLen);

    vector<uint8_t> recovered;
    CHECK(aes_gcm_open(key, iv, kAad, cipher.data(), cipher.size(), tag,
                       recovered));
    CHECK(recovered == plain);
}

PCS_TEST(gcm_handles_empty_plaintext) {
    const vector<uint8_t> key = random_bytes(config::kKeyLen);
    const vector<uint8_t> iv = random_bytes(config::kIvLen);

    vector<uint8_t> cipher, tag;
    CHECK(aes_gcm_seal(key, iv, kAad, nullptr, 0, cipher, tag));
    CHECK_EQ(cipher.size(), size_t{0});

    vector<uint8_t> recovered;
    CHECK(aes_gcm_open(key, iv, kAad, cipher.data(), 0, tag, recovered));
    CHECK_EQ(recovered.size(), size_t{0});
}

PCS_TEST(gcm_rejects_a_wrong_key) {
    const vector<uint8_t> key = random_bytes(config::kKeyLen);
    const vector<uint8_t> other = random_bytes(config::kKeyLen);
    const vector<uint8_t> iv = random_bytes(config::kIvLen);
    const vector<uint8_t> plain = {'s', 'e', 'c', 'r', 'e', 't'};

    vector<uint8_t> cipher, tag;
    CHECK(aes_gcm_seal(key, iv, kAad, plain.data(), plain.size(), cipher, tag));

    vector<uint8_t> recovered;
    CHECK(!aes_gcm_open(other, iv, kAad, cipher.data(), cipher.size(), tag,
                        recovered));
    // A failed open must not hand back partial plaintext.
    CHECK_EQ(recovered.size(), size_t{0});
}

PCS_TEST(gcm_detects_tampering) {
    const vector<uint8_t> key = random_bytes(config::kKeyLen);
    const vector<uint8_t> iv = random_bytes(config::kIvLen);
    const vector<uint8_t> plain(64, 'x');

    vector<uint8_t> cipher, tag;
    CHECK(aes_gcm_seal(key, iv, kAad, plain.data(), plain.size(), cipher, tag));

    vector<uint8_t> flipped = cipher;
    flipped[10] = static_cast<uint8_t>(flipped[10] ^ 0x01);
    vector<uint8_t> recovered;
    CHECK(!aes_gcm_open(key, iv, kAad, flipped.data(), flipped.size(), tag,
                        recovered));

    vector<uint8_t> bad_tag = tag;
    bad_tag[0] = static_cast<uint8_t>(bad_tag[0] ^ 0xFF);
    CHECK(!aes_gcm_open(key, iv, kAad, cipher.data(), cipher.size(), bad_tag,
                        recovered));

    // Changing the associated data invalidates it too, which is what binds a
    // block to its position in the stream.
    const vector<uint8_t> other_aad = {'o', 't', 'h', 'e', 'r'};
    CHECK(!aes_gcm_open(key, iv, other_aad, cipher.data(), cipher.size(), tag,
                        recovered));
}

PCS_TEST(key_derivation_is_deterministic_and_separated_by_label) {
    const vector<uint8_t> salt = random_bytes(config::kSaltLen);

    const vector<uint8_t> a = derive_key("correct horse", salt, "label-a", 1000);
    const vector<uint8_t> b = derive_key("correct horse", salt, "label-a", 1000);
    CHECK(a == b);
    CHECK_EQ(a.size(), config::kKeyLen);

    // A different label, passphrase or salt must give an unrelated key.
    CHECK(derive_key("correct horse", salt, "label-b", 1000) != a);
    CHECK(derive_key("wrong horse", salt, "label-a", 1000) != a);
    CHECK(derive_key("correct horse", random_bytes(config::kSaltLen),
                     "label-a", 1000) != a);
}

PCS_TEST(dedup_keys_are_reproducible_across_runs) {
    // Deduplication only works if the same passphrase always yields the same
    // key, so this one deliberately has no random salt.
    CHECK(derive_dedup_key("passphrase") == derive_dedup_key("passphrase"));
    CHECK(derive_dedup_key("passphrase") != derive_dedup_key("other"));
}

PCS_TEST(constant_time_compare_matches_ordinary_compare) {
    CHECK(secure_equal("", ""));
    CHECK(secure_equal("abc", "abc"));
    CHECK(!secure_equal("abc", "abd"));
    CHECK(!secure_equal("abc", "ab"));
    CHECK(!secure_equal("", "a"));
}

PCS_TEST(sha256_matches_a_known_answer) {
    // The published digest of the empty input, so a broken build of the
    // hashing path fails loudly instead of silently agreeing with itself.
    const vector<uint8_t> empty;
    CHECK_EQ(sha256_hex(empty),
             string("e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855"));
}
