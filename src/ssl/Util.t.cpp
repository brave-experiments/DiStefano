#include "../doctest.h"
#include "Util.hpp"

#include <array>
#include <cstdint>
#include <limits>

#include "crypto/internal.h"
#include "openssl/ssl.h"
#include "ssl/internal.h"
#include <fstream>
#include <iostream>

//! [UtilIsNistCurveTests]
TEST_CASE("is_nist_curve") {
  // We can just iterate over all 16-bit integers
  // Just like formal verification.
  constexpr auto maximum = std::numeric_limits<uint16_t>::max();
  for (uint16_t i = 0; i < maximum; i++) {
    const auto result = Util::is_nist_curve(i);
    // NOTE: unlike in more modern languages, we definitely need brerak clauses
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
//! [UtilIsNistCurveTests]

//! [UtilGetNidFromUint16tTests]
TEST_CASE("GetNidFromUint16t") {
  // We can just iterate over all 16-bit integers.
  // Just like formal verification
  constexpr auto maximum = std::numeric_limits<uint16_t>::max();
  for (uint16_t i = 0; i < maximum; i++) {
    const auto result = Util::get_nid_from_uint16(i);
    // NOTE: unlike in more modern languages, we definitely need brerak clauses
    // here.
    switch (i) {
    case SSL_CURVE_SECP224R1:
      CHECK(result == NID_secp224r1);
      break;
    case SSL_CURVE_SECP256R1:
      CHECK(result == NID_X9_62_prime256v1);
      break;
    case SSL_CURVE_SECP384R1:
      CHECK(result == NID_secp384r1);
      break;
    case SSL_CURVE_SECP521R1:
      CHECK(result == NID_secp521r1);
      break;
    default:
      CHECK(result == 0);
    }
  }
}
//! [UtilGetNidFromUint16tTests]

//! [UtilInitialiseCBBForEcTests]
TEST_CASE("InitialiseCBBForEcPointData") {
  // We'll generate a small test case for the above function.
  // First of all, let's create an uninitialized client.
  // For simplicity we'll just choose a curve at random
  const uint16_t group_id = SSL_CURVE_SECP224R1;
  // And we'll create two CBBs. These can be subbed in and moved around later.
  bssl::ScopedCBB scbb;
  CBB cbb;
  SUBCASE("initialise_cbb_for_ec_point_data fails on null inputs") {
    CHECK(!Util::initialise_cbb_for_ec_point_data(group_id, nullptr, nullptr));
    CHECK(
        !Util::initialise_cbb_for_ec_point_data(group_id, scbb.get(), nullptr));
    CHECK(!Util::initialise_cbb_for_ec_point_data(group_id, nullptr, &cbb));
    // Null references are UB in C++, so we don't have to check that.
  }

  SUBCASE("initialise_cbb_for_ec_point_data works on normal inputs") {
    REQUIRE(Util::initialise_cbb_for_ec_point_data(group_id, scbb.get(), &cbb));
    CHECK(CBB_data(&cbb));
    // The cbb shouldn't have any data in it: we're expecting it to be
    // fully empty.
    CHECK(CBB_len(&cbb) == 0);
    // We'll also want to check that the first element of the CBB is the group
    // ID To do this, we convert the scbb to an array and then to a CBS.
    bssl::Array<uint8_t> arr;
    REQUIRE(CBBFinishArray(scbb.get(), &arr));
    // NOTE: at this point scbb and cbb are probably in an undefined state, so
    // checking them isn't a great idea.
    CBS in_cbs;
    CBS_init(&in_cbs, arr.data(), arr.size());
    uint16_t new_group_id;
    REQUIRE(CBS_get_u16(&in_cbs, &new_group_id));
    CHECK(group_id == new_group_id);
  }
}
//! [UtilInitialiseCBBForEcTests]

//! [UtilDeInitialiseCBBForEcTests]
TEST_CASE("DeinitialiseCBBForEcPointData") {
  SUBCASE("Fails on null inputs") {
    CBS test, test2;
    uint16_t base;
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(nullptr, nullptr, nullptr));
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(nullptr, nullptr, &test));
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(nullptr, &test, nullptr));
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(nullptr, &test, &test2));
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(&base, nullptr, nullptr));
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(&base, nullptr, &test2));
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(&base, &test, nullptr));
  }

  SUBCASE("Fails if in == out") {
    CBS test;
    uint16_t base;
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(&base, &test, &test));
  }

  SUBCASE("Fails if there's nothing in the input") {
    CBS test, test1;
    bssl::Array<uint8_t> arr;
    uint16_t base;

    CBS_init(&test, arr.data(), arr.size());
    CHECK(!Util::deinitialise_cbb_for_ec_point_data(&base, &test, &test1));
  }

  SUBCASE("Succeeds if we call initialise_cbb_for_ec_point first") {
    bssl::ScopedCBB scbb;
    CBB cbb;
    const uint16_t group_id = SSL_CURVE_SECP224R1;
    REQUIRE(Util::initialise_cbb_for_ec_point_data(group_id, scbb.get(), &cbb));

    // N.B we need to dump it to an array, or the write won't go through.
    bssl::Array<uint8_t> out_arr;
    REQUIRE(CBBFinishArray(scbb.get(), &out_arr));

    CBS in, out;
    uint16_t base;
    CBS_init(&in, out_arr.data(), out_arr.size());
    CHECK(Util::deinitialise_cbb_for_ec_point_data(&base, &in, &out));
    CHECK(base == group_id);
  }
}
//! [UtilDeInitialiseCBBForEcTests]

//! [UtilGeneratePublicKeyTests]
TEST_CASE("GeneratePublicKey") {
  auto client = bssl::SSLKeyShare::Create(SSL_CURVE_X25519);
  REQUIRE(client);
  bssl::Array<uint8_t> out;
  bssl::Array<uint8_t> out_2;
  SUBCASE("Can call GeneratePublicKey twice") {
    CHECK(Util::generate_public_key(*client, out));
    CHECK(Util::generate_public_key(*client, out_2));
    // We definitely don't expect out == out_2, but we would expect
    // their length to be the same.
    REQUIRE(out.size() == out_2.size());
  }

  SUBCASE("Should set the private key") {
    CHECK(Util::generate_public_key(*client, out));
    bssl::ScopedCBB scbb;
    CBB bb;
    REQUIRE(Util::initialise_cbb_for_ec_point_data(client->GroupID(),
                                                   scbb.get(), &bb));
    // N.b This will fail with a negative assertion if the private key wasn't
    // set.
    CHECK(client->SerializePrivateKey(&bb));
    CHECK(CBBFinishArray(scbb.get(), &out));
  }
}
//! [UtilGeneratePublicKeyTests]

//! [UtilRandomECPointTests]
TEST_CASE("RandomECPoint") {
  // This test case checks that:
  // 1) The RandomECPoint function returns false on null pointers, and
  // 2) The RandomECPoint function returns a point that is on the supplied
  // curve.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  SUBCASE("RandomECPoint fails on nullptr input") {
    // N.B for this test case we'll use a fixed curve.
    uint16_t curve = SSL_CURVE_SECP224R1;
    bssl::UniquePtr<EC_GROUP> group(
        EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
    REQUIRE(group);
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
    bssl::UniquePtr<EC_POINT> empty_point;
    REQUIRE(point);
    CHECK(!Util::RandomECPoint(nullptr, nullptr, nullptr));
    CHECK(!Util::RandomECPoint(nullptr, nullptr, bn_ctx.get()));
    CHECK(!Util::RandomECPoint(nullptr, point.get(), nullptr));
    CHECK(!Util::RandomECPoint(nullptr, empty_point.get(), nullptr));
    CHECK(!Util::RandomECPoint(nullptr, point.get(), bn_ctx.get()));
    CHECK(!Util::RandomECPoint(group.get(), nullptr, nullptr));
    CHECK(!Util::RandomECPoint(group.get(), nullptr, bn_ctx.get()));
    CHECK(!Util::RandomECPoint(group.get(), point.get(), nullptr));
    CHECK(!Util::RandomECPoint(group.get(), empty_point.get(), nullptr));
    CHECK(!Util::RandomECPoint(group.get(), empty_point.get(), bn_ctx.get()));
  }

  SUBCASE("Randomly generated points are produced") {
    // This subcase really just checks that the function returns "true" with
    // correct inputs.
    uint16_t curve = SSL_CURVE_SECP224R1;
    bssl::UniquePtr<EC_GROUP> group(
        EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
    REQUIRE(group);
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
    CHECK(Util::RandomECPoint(group.get(), point.get(), bn_ctx.get()));
  }

  SUBCASE("Randomly generated points live on a curve") {
    // We'll check this holds over all of the curves we care about.
    std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                   SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};
    // We'll repeat the random sampling some number of times per curve.
    constexpr auto repeats = 100;
    for (auto curve : curves) {
      bssl::UniquePtr<EC_GROUP> group(
          EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
      REQUIRE(group);
      bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
      REQUIRE(point);
      for (unsigned i = 0; i < repeats; i++) {
        REQUIRE(Util::RandomECPoint(group.get(), point.get(), bn_ctx.get()));
        // N.B Unlike with OpenSSL, BoringSSL returns 0 on error and 1 on
        // success (OpenSSL returns -1 on an error). So we don't need to compare
        // against 1 here.
        CHECK(EC_POINT_is_on_curve(group.get(), point.get(), bn_ctx.get()));
      }
    }
  }
}
//! [UtilRandomECPointTests]

//! [UtilECPointAdditionTests]
TEST_CASE("ECPointAddition") {
  // This just tests that addition is consistent between the BoringSSL's regular
  // adding routine and our version (after packing).
  // To do this, we randomly generate two elliptic curve points, add them using
  // BoringSSL's regular routine, then we pack them and use our own routine.
  // Hopefully the results are the same :)
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::UniquePtr<EC_GROUP> tmp_group(EC_GROUP_new_by_curve_name(
      Util::get_nid_from_uint16(SSL_CURVE_SECP224R1)));
  REQUIRE(tmp_group);

  SUBCASE("ECPointAddition fails on null inputs") {
    bssl::Array<uint8_t> a, b;
    CHECK(!Util::EC_point_addition(nullptr, nullptr, a, b, nullptr));
    CHECK(!Util::EC_point_addition(nullptr, nullptr, a, b, bn_ctx.get()));
    bssl::UniquePtr<EC_POINT> out_point(EC_POINT_new(tmp_group.get()));
    REQUIRE(out_point);
    CHECK(!Util::EC_point_addition(nullptr, &out_point, a, b, nullptr));
    CHECK(!Util::EC_point_addition(nullptr, &out_point, a, b, bn_ctx.get()));
    CHECK(!Util::EC_point_addition(tmp_group.get(), nullptr, a, b, nullptr));
    CHECK(
        !Util::EC_point_addition(tmp_group.get(), nullptr, a, b, bn_ctx.get()));
    bssl::UniquePtr<EC_POINT> empty_point;
    CHECK(!Util::EC_point_addition(tmp_group.get(), &empty_point, a, b,
                                   bn_ctx.get()));
  }

  SUBCASE("ECPointAddition works on NIST curves") {

    // We like to repeat things here.
    constexpr auto repeats = 100;

    // We'll check addition over all of the curves that we support.
    std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                   SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};

    for (auto curve : curves) {
      // We allocate all of these once to make the inner loop slightly faster.
      bssl::UniquePtr<EC_GROUP> group(
          EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve)));
      REQUIRE(group);

      for (unsigned i = 0; i < repeats; i++) {
        bssl::UniquePtr<EC_POINT> point_a(EC_POINT_new(group.get())),
            point_b(EC_POINT_new(group.get())), sum(EC_POINT_new(group.get()));
        REQUIRE(point_a);
        REQUIRE(point_b);
        REQUIRE(sum);
        // Generate two random points on our curve
        REQUIRE(Util::RandomECPoint(group.get(), point_a.get(), bn_ctx.get()));
        REQUIRE(Util::RandomECPoint(group.get(), point_b.get(), bn_ctx.get()));

        // And add them using BoringSSL's native implementation.
        REQUIRE(EC_POINT_add(group.get(), sum.get(), point_a.get(),
                             point_b.get(), bn_ctx.get()));

        // Now we're going to serialise the points into something that
        // EC_point_addition expects. These are converted into points in
        // EC_point_addition.
        bssl::Array<uint8_t> native_sum_out, a_out, b_out;
        REQUIRE(Util::ECPointToCBB(curve, group.get(), sum.get(),
                                   native_sum_out, bn_ctx.get()));
        REQUIRE(Util::ECPointToCBB(curve, group.get(), point_a.get(), a_out,
                                   bn_ctx.get()));
        REQUIRE(Util::ECPointToCBB(curve, group.get(), point_b.get(), b_out,
                                   bn_ctx.get()));

        bssl::UniquePtr<EC_POINT> our_sum(EC_POINT_new(group.get()));
        REQUIRE(our_sum);
        // Add our two points. This will deserialise the arrays into points
        // internally.
        REQUIRE(Util::EC_point_addition(group.get(), &our_sum, a_out, b_out,
                                        bn_ctx.get()));
        bssl::Array<uint8_t> sum_out;
        // Now we'll turn the result into an array too, so we can make
        // sure that the serialised forms are the same.
        REQUIRE(Util::ECPointToCBB(curve, group.get(), our_sum.get(), sum_out,
                                   bn_ctx.get()));

        // N.B this length check is to prevent segfaults on memcmp below.
        REQUIRE(sum_out.size() == native_sum_out.size());
        const auto are_same_bit_pattern =
            memcmp(sum_out.data(), native_sum_out.data(),
                   sizeof(uint8_t) * sum_out.size());
        CHECK(are_same_bit_pattern == 0);

        // We also want to make sure that the actual points compare to being the
        // same, as opposed to just the dumped output. N.B EC_POINT_cmp returns
        // 0 in case of equality, just like memcmp.
        CHECK(EC_POINT_cmp(group.get(), our_sum.get(), sum.get(),
                           bn_ctx.get()) == 0);
      }
    }
  }
}
//! [UtilECPointAdditionTests]

//! [UtilComputePremasterSecretTests]
TEST_CASE("ComputePremasterSecret") {
  auto prover = bssl::SSLKeyShare::Create(SSL_CURVE_SECP224R1);
  auto verifier = bssl::SSLKeyShare::Create(SSL_CURVE_SECP224R1);
  auto server = bssl::SSLKeyShare::Create(SSL_CURVE_SECP224R1);
  REQUIRE(prover);
  REQUIRE(verifier);
  REQUIRE(server);

  bssl::Array<uint8_t> prover_key_bytes, verifier_key_bytes;
  REQUIRE(Util::generate_public_key(*prover, prover_key_bytes));
  REQUIRE(Util::generate_public_key(*verifier, verifier_key_bytes));

  SUBCASE("2 party handshake works") {
    // We now need to convert the outputs from above into actual arrays.
    uint8_t alert;
    bssl::Array<uint8_t> out_prover_x, out_verifier_x, out_prover_y,
        out_verifier_y;
    REQUIRE(Util::compute_premaster_secret(*verifier, prover_key_bytes, alert,
                                           out_verifier_x, out_verifier_y));
    REQUIRE(Util::compute_premaster_secret(*prover, verifier_key_bytes, alert,
                                           out_prover_x, out_prover_y));
    REQUIRE(out_prover_x.size() == out_verifier_x.size());
    const auto are_same_bit_pattern_x =
        memcmp(out_prover_x.data(), out_verifier_x.data(),
               sizeof(uint8_t) * out_verifier_x.size());
    CHECK(are_same_bit_pattern_x == 0);

    SUBCASE("Check that the other wrapper does the same thing") {
      bssl::Array<uint8_t> out_prover_x_2, out_verifier_x_2;
      REQUIRE(Util::compute_premaster_secret(*verifier, prover_key_bytes, alert,
                                             out_verifier_x_2));
      REQUIRE(Util::compute_premaster_secret(*prover, verifier_key_bytes, alert,
                                             out_prover_x_2));
      REQUIRE(out_prover_x_2.size() == out_verifier_x_2.size());
      const auto are_same_bit_pattern_x_2 =
          memcmp(out_prover_x_2.data(), out_verifier_x_2.data(),
                 sizeof(uint8_t) * out_prover_x_2.size());
      CHECK(are_same_bit_pattern_x_2 == 0);

      // Now we'll check that the outputs in the non-y version are the same as
      // in the y-version.
      REQUIRE(out_prover_x_2.size() == out_prover_x.size());
      CHECK(memcmp(out_prover_x_2.data(), out_prover_x.data(),
                   sizeof(uint8_t) * out_prover_x_2.size()) == 0);
    }

    REQUIRE(out_prover_y.size() == out_verifier_y.size());
    const auto are_same_bit_pattern_y =
        memcmp(out_prover_y.data(), out_verifier_y.data(),
               sizeof(uint8_t) * out_verifier_y.size());
    CHECK(are_same_bit_pattern_y == 0);
  }
}
//! [UtilComputePremasterSecretTests]

//! [UtilECPointToCBBTests]
TEST_CASE("ECPointToCBB") {
  // The test cases here check that:
  // 1) We cause failures by passing in null pointers
  // 2) That we can encode a random point properly.
  // Checking that this CBBToECPoint undoes this function is done
  // in CBBToECPoint's tests.

  // For simplicity we'll just choose a curve at random
  // The exact curve here doesn't matter, as the function under test doesn't
  // depend on a particular representation.
  const uint16_t group_id = SSL_CURVE_SECP224R1;
  bssl::Array<uint8_t> arr;

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(
      Util::get_nid_from_uint16(SSL_CURVE_SECP224R1)));
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
  REQUIRE(group);
  REQUIRE(point);

  SUBCASE("ECPointToCBB fails on nullptr input") {
    CHECK(!Util::ECPointToCBB(group_id, nullptr, nullptr, arr, nullptr));
    CHECK(!Util::ECPointToCBB(group_id, nullptr, nullptr, arr, bn_ctx.get()));
    CHECK(!Util::ECPointToCBB(group_id, nullptr, point.get(), arr, nullptr));
    CHECK(
        !Util::ECPointToCBB(group_id, nullptr, point.get(), arr, bn_ctx.get()));
    CHECK(!Util::ECPointToCBB(group_id, group.get(), nullptr, arr, nullptr));
    CHECK(
        !Util::ECPointToCBB(group_id, group.get(), nullptr, arr, bn_ctx.get()));
    CHECK(
        !Util::ECPointToCBB(group_id, group.get(), point.get(), arr, nullptr));
  }

  SUBCASE("Encoding a random point properly works") {
    REQUIRE(Util::RandomECPoint(group.get(), point.get(), bn_ctx.get()));
    REQUIRE(Util::ECPointToCBB(group_id, group.get(), point.get(), arr,
                               bn_ctx.get()));

    SUBCASE("The result is what we'd expect if we did it by hand") {
      bssl::ScopedCBB active_scbb;
      CBB cbb;
      bssl::Array<uint8_t> manual_out;
      REQUIRE(Util::initialise_cbb_for_ec_point_data(group_id,
                                                     active_scbb.get(), &cbb));
      REQUIRE(EC_POINT_point2cbb(&cbb, group.get(), point.get(),
                                 POINT_CONVERSION_UNCOMPRESSED, bn_ctx.get()));
      REQUIRE(CBBFinishArray(active_scbb.get(), &manual_out));
      REQUIRE(manual_out.size() == arr.size());
      const auto are_same_bit_pattern =
          memcmp(manual_out.data(), arr.data(), sizeof(uint8_t) * arr.size());
      CHECK(are_same_bit_pattern == 0);
    }
  }
}
//! [UtilECPointToCBBTests]

//! [UtilCBBToECPointTests]
TEST_CASE("CBBToECPointTests") {
  // The test cases here check that:
  // 1) We cause failures by passing in null pointers
  // 2) That we can decode a random point properly.
  // 3) That we fail if the input point is not properly formed.
  // 4) That we can decode outputs from ECPointToCBB.

  // For simplicity we'll just choose a curve at random
  // The exact curve here doesn't matter, as the function under test doesn't
  // depend on a particular representation.
  const uint16_t group_id = SSL_CURVE_SECP224R1;
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(group_id)));

  REQUIRE(group);

  SUBCASE("CBBToECPoint fails on null inputs") {
    uint16_t out_id;
    bssl::Array<uint8_t> arr;
    bssl::UniquePtr<EC_POINT> empty_point;
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
    REQUIRE(point);

    CHECK(!Util::CBBToECPoint(nullptr, nullptr, nullptr, arr, nullptr));
    CHECK(!Util::CBBToECPoint(nullptr, nullptr, nullptr, arr, bn_ctx.get()));
    CHECK(!Util::CBBToECPoint(nullptr, nullptr, &out_id, arr, nullptr));
    CHECK(!Util::CBBToECPoint(nullptr, nullptr, &out_id, arr, bn_ctx.get()));
    CHECK(!Util::CBBToECPoint(nullptr, &point, nullptr, arr, nullptr));
    CHECK(!Util::CBBToECPoint(nullptr, &point, nullptr, arr, bn_ctx.get()));
    CHECK(!Util::CBBToECPoint(nullptr, &point, &out_id, arr, bn_ctx.get()));
    CHECK(
        !Util::CBBToECPoint(group.get(), nullptr, nullptr, arr, bn_ctx.get()));
    CHECK(!Util::CBBToECPoint(group.get(), nullptr, &out_id, arr, nullptr));
    CHECK(
        !Util::CBBToECPoint(group.get(), nullptr, &out_id, arr, bn_ctx.get()));
    CHECK(!Util::CBBToECPoint(group.get(), &point, nullptr, arr, nullptr));
    CHECK(!Util::CBBToECPoint(group.get(), &point, &out_id, arr, nullptr));
    CHECK(!Util::CBBToECPoint(group.get(), &point, nullptr, arr, bn_ctx.get()));
    // This checks that point->get() can't be null by supplying a valid
    // UniquePtr (that doesn't point to anything).
    CHECK(!Util::CBBToECPoint(group.get(), &empty_point, &out_id, arr,
                              bn_ctx.get()));
  }

  SUBCASE("Decoding a random, well-formed point works") {
    bssl::UniquePtr<EC_POINT> random_point(EC_POINT_new(group.get()));
    REQUIRE(random_point);
    REQUIRE(Util::RandomECPoint(group.get(), random_point.get(), bn_ctx.get()));
    // Manually serialise the point
    bssl::ScopedCBB active_scbb;
    CBB cbb;
    bssl::Array<uint8_t> manual_out;
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
    REQUIRE(Util::initialise_cbb_for_ec_point_data(group_id, active_scbb.get(),
                                                   &cbb));
    SUBCASE("Decoding works if POINT_CONVERSION_UNCOMPRESSED") {
      REQUIRE(EC_POINT_point2cbb(&cbb, group.get(), random_point.get(),
                                 POINT_CONVERSION_UNCOMPRESSED, bn_ctx.get()));
      REQUIRE(CBBFinishArray(active_scbb.get(), &manual_out));
      // Now convert back
      uint16_t out_id;
      const bool worked = Util::CBBToECPoint(group.get(), &point, &out_id,
                                             manual_out, bn_ctx.get());
      CHECK(worked);
      if (worked) {
        CHECK(out_id == group_id);
        // N.B this has the same output convention as memcmp.
        CHECK(EC_POINT_cmp(group.get(), point.get(), random_point.get(),
                           bn_ctx.get()) == 0);
      }
    }

    SUBCASE("Decoding fails if not POINT_CONVERSION_UNCOMPRESSED") {
      // The point format here could also be POINT_CONVERSION_HYBRID, but
      // the BoringSSL docs imply that this is never used in prcactice.
      REQUIRE(EC_POINT_point2cbb(&cbb, group.get(), random_point.get(),
                                 POINT_CONVERSION_COMPRESSED, bn_ctx.get()));
      REQUIRE(CBBFinishArray(active_scbb.get(), &manual_out));
      // Now convert back
      uint16_t out_id;
      bssl::Array<uint8_t> arr;
      CHECK(
          !Util::CBBToECPoint(group.get(), &point, &out_id, arr, bn_ctx.get()));
    }
  }

  SUBCASE("CBBToECPoint undoes ECPointToCBB") {
    uint16_t out_id;
    bssl::UniquePtr<EC_POINT> random_point(EC_POINT_new(group.get()));
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
    bssl::Array<uint8_t> point_as_arr;
    REQUIRE(Util::RandomECPoint(group.get(), random_point.get(), bn_ctx.get()));
    REQUIRE(Util::ECPointToCBB(group_id, group.get(), random_point.get(),
                               point_as_arr, bn_ctx.get()));
    REQUIRE(Util::CBBToECPoint(group.get(), &point, &out_id, point_as_arr,
                               bn_ctx.get()));
    CHECK(EC_POINT_cmp(group.get(), random_point.get(), point.get(),
                       bn_ctx.get()) == 0);
  }
}
//! [UtilCBBToECPointTests]

//! [UtilIsValidFilepath]
TEST_CASE("is_valid_filepath") {
  SUBCASE("Should fail on random filename") {
    CHECK(!Util::is_valid_filepath("alskdjaljsdlajds.txt"));
  }

  SUBCASE("Should succeed on newly created file") {
    std::ofstream outfile("test.txt");
    outfile << "does creation work?" << std::endl;
    outfile.close();
    CHECK(Util::is_valid_filepath("test.txt"));
    // This returns 0 on success, a la memcmp.
    // https://en.cppreference.com/w/cpp/io/c/remove
    REQUIRE(std::remove("test.txt") == 0);
  }
}
//! [UtilIsValidFilepath]

//! [UtilConvertBoolToUint8]
TEST_CASE("convert_bool_to_uint8") {
  // Create a random array of bools.
  std::array<bool, 128> bools;
  for (unsigned i = 0; i < 128; i++) {
    bools[i] = rand();
  }

  auto out = Util::convert_bool_to_uint8(bools);
  REQUIRE(out.size() == 16);

  SUBCASE("Default works as expected") {
    for (unsigned i = 0; i < 16; i++) {
      uint8_t curr = 0;
      for (unsigned j = 0; j < 8; j++) {
        curr |= static_cast<uint8_t>(bools[i * 8 + j]);
        curr = static_cast<uint8_t>(curr << 1);
      }
      CHECK(curr == out[i]);
    }
  }

  SUBCASE("Switching causes a mismatch") {
    bools[50] = !bools[50];
    auto out_2 = Util::convert_bool_to_uint8(bools);

    // Now convert back.
    std::array<bool, 128> back;
    for (unsigned i = 0; i < 16; i++) {
      uint8_t val = out_2[i];
      for (unsigned j = 0; j < 8; j++) {
        back[i * 8 + j] = val & 1;
        val >>= 1;
      }
    }

    // As we changed bools, it shouldn't match.
    CHECK(back != bools);
  }
}
//! [UtilConvertBoolToUint8]

// ![UtilConvertUint8ToBool]
TEST_CASE("convert_uint8_to_bool") {
  // Generate a random sequence of uint8_ts.
  std::array<uint8_t, 16> arr;
  for (unsigned i = 0; i < 16; i++) {
    arr[i] = static_cast<uint8_t>(rand());
  }

  std::array<bool, 128> out;
  Util::convert_uint8_to_bool<16>(arr.data(), out.data());

  // We now check that each bit of `out` is the same as the corresponding bit of
  // `in`.
  for (unsigned i = 0; i < 16; i++) {
    auto curr = arr[i];
    for (unsigned j = 0; j < 8; j++) {
      bool bit = curr & 1;
      CHECK(out[i * 8 + j] == bit);
      curr >>= 1;
    }
  }
}
// ![UtilConvertUint8ToBool]

// ![UtilGetHash]
TEST_CASE("get_hash") {
  std::array<uint8_t, 32> out;

  // This was extracted from a running BoringSSL instance.
  constexpr uint16_t version = 772;

  // This corresponds to AES_128_GCM_SHA256, see
  // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
  constexpr uint16_t aes_128_cipher_suite = 4865;
  // This corresponds to AES_256_GCM_SHA384, see above.
  constexpr uint16_t aes_256_cipher_suite = 4866;

  SUBCASE("Fails with null transcript") {
    CHECK(!Util::get_hash(nullptr, out));
  }

  // This is random data just to check determinism.
  std::array<uint8_t, 255> random_bytes;
  for (auto &r : random_bytes) {
    r = static_cast<uint8_t>(rand());
  }

  bssl::SSLTranscript transcript;
  REQUIRE(transcript.Init());
  REQUIRE(transcript.Update(
      bssl::MakeSpan<uint8_t>(random_bytes.data(), random_bytes.size())));

  SUBCASE("Fails with AES256") {
    REQUIRE(transcript.InitHash(version,
                                SSL_get_cipher_by_value(aes_256_cipher_suite)));
    CHECK(!Util::get_hash(&transcript, out));
  }

  SUBCASE("Succeeds with AES128") {
    REQUIRE(transcript.InitHash(version,
                                SSL_get_cipher_by_value(aes_128_cipher_suite)));
    CHECK(Util::get_hash(&transcript, out));
  }
}
// ![UtilGetHash]
