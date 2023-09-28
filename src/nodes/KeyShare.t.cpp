#include "../doctest.h"
#include "../ssl/Util.hpp"
#include "KeyShare.hpp"

#include <array>

//! [KeyShareCreatePublicKeyTests]
TEST_CASE("Creating a new public key works") {
  KeyShare ks;

  // We can just iterate over all 16-bit integers.
  // Just like formal verification.
  // NOTE: this function doesn't test that the keys that are created are
  // actually valid. This is because we delegate to other, tested functions in
  // create_new_public_keys.
  constexpr auto maximum = std::numeric_limits<uint16_t>::max();
  for (uint16_t i = 0; i < maximum; i++) {
    const auto result = ks.create_new_public_key(i);
    // NOTE: unlike in more modern languages, we definitely need break clauses
    // here.
    switch (i) {
    case SSL_CURVE_SECP224R1:
      CHECK(result);
      break;
    case SSL_CURVE_SECP256R1:
      CHECK(result);
      break;
    case SSL_CURVE_SECP384R1:
      CHECK(result);
      break;
    case SSL_CURVE_SECP521R1:
      CHECK(result);
      break;
    default:
      CHECK(!result);
    }
  }
}
//! [KeyShareCreatePublicKeyTests]

//! [KeyShareRetrieveGroupIDTests]
TEST_CASE("Retrieving the groupID works") {
  KeyShare ks;

  SUBCASE("GroupID at beginning is 0") { CHECK(ks.get_group_id() == 0); }

  SUBCASE("GroupID otherwise matches the curve") {
    // We'll check it for all curves.
    std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                   SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};

    for (auto curve : curves) {
      REQUIRE(ks.create_new_public_key(curve));
      CHECK(ks.get_group_id() == curve);
    }
  }
}
//! [KeyShareRetrieveGroupIDTests]

//! [KeyShareCreateNewShareTests]
TEST_CASE("Creating a new share works") {
  KeyShare ks;

  // Make testing a little bit quicker.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  // We'll try it for all curves.
  std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                 SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};

  SUBCASE("Test that making the share returns true") {
    // NOTE: this test doesn't check that the created share is _correct_.
    for (auto curve : curves) {
      bssl::UniquePtr<EC_GROUP> group(
          EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
      REQUIRE(group);
      auto other_party = bssl::SSLKeyShare::Create(curve);
      REQUIRE(other_party);
      bssl::Array<uint8_t> other_key_bytes;
      REQUIRE(Util::generate_public_key(*other_party, other_key_bytes));
      // Now we need to strip off the leading bytes: this is because of how
      // BoringSSL packs its bytes.
      uint16_t group_id;
      CBS cbs, key;
      CBS_init(&cbs, other_key_bytes.data(), other_key_bytes.size());
      REQUIRE(CBS_get_u16(&cbs, &group_id));
      REQUIRE(CBS_get_u16_length_prefixed(&cbs, &key));
      const auto created_properly = ks.create_new_share(curve, key);

      CHECK(created_properly);
    }
  }
}
//! [KeyShareCreateNewShareTests]

//! [KeyShareGetPublicKeyTests]
TEST_CASE("Getting the public key works") {
  KeyShare ks;

  bssl::Array<uint8_t> arr;
  SUBCASE("Calling get_public_key before generating a public key works") {
    // First of all we'll resize arr to be greater than size 0.
    REQUIRE(arr.Init(100));
    REQUIRE(arr.size() == 100);
    const auto copied = ks.get_public_key(arr);
    CHECK(copied);
    if (copied) {
      // The public key should now have size 0
      CHECK(arr.size() == 0);
    }
  }

  SUBCASE("Calling get_public_key after generating a public key works") {
    // The test case here is essentially "the class writes something, and
    // it does it deterministically".
    // This isn't ideal, but it prevents us having to gain clear-box access to
    // the class.
    REQUIRE(arr.size() == 0);
    REQUIRE(ks.create_new_public_key(SSL_CURVE_SECP224R1));
    const auto copied = ks.get_public_key(arr);
    CHECK(copied);
    if (copied) {
      bssl::Array<uint8_t> other;
      constexpr auto repeats = 100;
      for (unsigned i = 0; i < repeats; i++) {
        REQUIRE(ks.get_public_key(other));
        REQUIRE(other.size() == arr.size());
        CHECK(memcmp(other.data(), arr.data(), sizeof(uint8_t) * arr.size()) ==
              0);
      }
    }
  }
}
//! [KeyShareGetPublicKeyTests]

//! [KeyShareGetAdditiveShareTests]
TEST_CASE("Server get_additive_share tests") {
  KeyShare ks;

  bssl::Array<uint8_t> arr;
  SUBCASE("Calling get_additive_share before generating an additive share "
          "works") {
    // First of all we'll resize arr to be greater than size 0.
    REQUIRE(arr.Init(100));
    REQUIRE(arr.size() == 100);
    const auto copied = ks.get_additive_share(arr);
    CHECK(copied);
    if (copied) {
      // The additive share should now have size 0
      CHECK(arr.size() == 0);
    }
  }

  SUBCASE(
      "Calling get_additive_share after generating an additive share works") {

    bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
    REQUIRE(bn_ctx);
    bssl::BN_CTXScope scope(bn_ctx.get());
    std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                   SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};

    for (auto curve : curves) {
      bssl::UniquePtr<EC_GROUP> group(
          EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
      REQUIRE(group);
      auto other_party = bssl::SSLKeyShare::Create(curve);
      REQUIRE(other_party);
      bssl::Array<uint8_t> other_key_bytes;
      REQUIRE(Util::generate_public_key(*other_party, other_key_bytes));

      // Now we need to strip off the leading bytes: this is because of how
      // BoringSSL packs its bytes.
      uint16_t group_id;
      CBS cbs, key;
      CBS_init(&cbs, other_key_bytes.data(), other_key_bytes.size());
      REQUIRE(CBS_get_u16(&cbs, &group_id));
      REQUIRE(CBS_get_u16_length_prefixed(&cbs, &key));

      const auto created_properly = ks.create_new_share(curve, key);
      CHECK(created_properly);
      // NOTE: we don't check the correctness here (see
      // ServerCreateNewShareTests for that). Our interest here is just that
      // the bytes retrieved are deterministic.
      if (created_properly) {
        // We'll fetch it once and check that it works
        REQUIRE(ks.get_additive_share(arr));
        REQUIRE(arr.size() > 0);

        bssl::Array<uint8_t> other;
        constexpr auto repeats = 100;
        for (unsigned i = 0; i < repeats; i++) {
          REQUIRE(ks.get_additive_share(other));
          REQUIRE(other.size() == arr.size());
          CHECK(memcmp(other.data(), arr.data(),
                       sizeof(uint8_t) * arr.size()) == 0);
        }
      }

      SUBCASE("We can also get a public key") {
        // Generating an additive share implies a public key too!
        bssl::Array<uint8_t> pk_key;
        REQUIRE(pk_key.size() == 0);
        REQUIRE(ks.get_public_key(pk_key));
        CHECK(pk_key.size() != 0);
      }
    }
  }
}
//! [KeyShareGetAdditiveShareTests]
