#include "ThreePartyHandshake.hpp"
#include "crypto/internal.h"
#include "openssl/bio.h"
#include "openssl/mem.h"
#include "openssl/ssl.h"
#include "ssl/internal.h"

#include <array>
#include <utility>

#include "../doctest.h"
#include "StatefulSocket.hpp"
#include "Util.hpp"

#include <iostream>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct KeySharePKPair {
  bssl::SSLKeyShare *party;
  bssl::Array<uint8_t> key;
  bssl::Array<uint8_t> x_secret;
  bssl::Array<uint8_t> y_secret;
  bool own;

  bool generate_public_key() { return Util::generate_public_key(*party, key); }

  KeySharePKPair(const uint16_t curve)
      : party{bssl::SSLKeyShare::Create(curve).release()}, key{}, x_secret{},
        y_secret{}, own{true} {
    assert(party);
    [[maybe_unused]] const auto worked = generate_public_key();
    assert(worked);
  }

  KeySharePKPair(bssl::SSLKeyShare *party_, bssl::Array<uint8_t> key_)
      : party{party_}, key{}, x_secret{}, y_secret{}, own{false} {
    assert(party);
    key.CopyFrom(key_);
  }

  ~KeySharePKPair() {
    if (own) {
      // Yes, this is hacky.
      // Essentially, the SSLKeyShare destructor is virtual,
      // but for some unknown reason calling it via `delete`
      // just fails (i.e we get SIGABORT).
      // However, if we wrap it in a unique ptr
      // the right deleter gets called. I know, it confuses me too.
      bssl::UniquePtr<bssl::SSLKeyShare> a(party);
    }
  }

  bool compute_premaster_secret(bssl::Array<uint8_t> &other_key,
                                uint8_t &alert) {
    return Util::compute_premaster_secret(*party, other_key, alert, x_secret,
                                          y_secret);
  }

  bssl::UniquePtr<BIGNUM> y_secret_to_bignum() {
    return bssl::UniquePtr<BIGNUM>(
        BN_bin2bn(y_secret.data(), y_secret.size(), nullptr));
  }

  bssl::UniquePtr<BIGNUM> x_secret_to_bignum() {
    return bssl::UniquePtr<BIGNUM>(
        BN_bin2bn(x_secret.data(), x_secret.size(), nullptr));
  }

  bssl::UniquePtr<EC_POINT> secrets_to_ec_point(EC_GROUP *group, BN_CTX *ctx) {
    if (!group || !ctx) {
      return nullptr;
    }

    auto x_point = x_secret_to_bignum(), y_point = y_secret_to_bignum();
    if (!x_point || !y_point) {
      return nullptr;
    }

    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group));
    if (!point) {
      return nullptr;
    }

    if (!EC_POINT_set_affine_coordinates_GFp(group, point.get(), x_point.get(),
                                             y_point.get(), ctx)) {
      return nullptr;
    }

    return point;
  }
};

static bool three_party_handshake_ideal_functionality(
    EC_GROUP *group, KeySharePKPair &prover, KeySharePKPair &verifier,
    KeySharePKPair &server, BN_CTX *ctx, bssl::UniquePtr<EC_POINT> *out) {
  // This function is meant to show the ideal functionality for the three party
  // handshake between three different parties.
  // At a high level, this function:
  // 1) Computes `out` = pk_{verifier} + pk_{prover}
  // 2) Forwards `out` to the server, who completes their DHKE using `out`.
  // 3) The prover and verifier run a DHKE using the server's key bytes.
  // 4) We write the sum of the prover and verifier's produced points to the
  //    `out` parameter.
  // The caller is responsible for checking that this behaves as expected.

  // This is just a safety check.
  if (!group || !ctx || !out || !out->get()) {
    return false;
  }

  const auto group_id = prover.party->GroupID();

  // Add the prover and verifier's public keys together
  bssl::UniquePtr<EC_POINT> prover_verifier_shared_key_sum(EC_POINT_new(group));

  if (!prover_verifier_shared_key_sum ||
      !Util::EC_point_addition(group, &prover_verifier_shared_key_sum,
                               prover.key, verifier.key, ctx)) {
    return false;
  }

  // Now we need to dump that sum into an array, so the server can deal with it.
  bssl::Array<uint8_t> prover_verifier_shared_key;
  if (!Util::ECPointToCBB(group_id, group, prover_verifier_shared_key_sum.get(),
                          prover_verifier_shared_key, ctx)) {
    return false;
  }

  // Now all parties will do the handshake
  // N.B we don't actually care about these, but the API needs it. We just
  // check the return codes.
  uint8_t server_alert, verifier_alert, prover_alert;
  if (!prover.compute_premaster_secret(server.key, prover_alert) ||
      !verifier.compute_premaster_secret(server.key, verifier_alert) ||
      !server.compute_premaster_secret(prover_verifier_shared_key,
                                       server_alert)) {
    return false;
  }
  // Now we need the verifier and the prover to compute their co-ordinates
  // into a combined EC point.

  auto prover_point = prover.secrets_to_ec_point(group, ctx);
  auto verifier_point = verifier.secrets_to_ec_point(group, ctx);
  if (!prover_point || !verifier_point) {
    return false;
  }

  // Finally add the points together and return
  if (!EC_POINT_add(group, out->get(), verifier_point.get(), prover_point.get(),
                    ctx)) {
    return false;
  }
  return true;
}

TEST_CASE("ThreePartyHandshakeIdealFunctionality") {
  // This test case shows what the ideal functionality is
  // for the three party handshake. This exists in a "whiteboard"
  // sense (e.g without a network connection).

  // Note that this means we have to do a lot of book-keeping here that
  // the clients on a network won't actually have to do. This is really rather
  // irritating, but where appropriate the comments should "hopefully" guide you
  // through what is (and what is not) necessary.

  // Note: we'll iterate this process over the NIST curves
  std::array<uint16_t, 4> curves{SSL_CURVE_SECP224R1, SSL_CURVE_SECP256R1,
                                 SSL_CURVE_SECP384R1, SSL_CURVE_SECP521R1};
  // and over some number of repetitions, to make it easier to
  // verify that this actually does what we want it to do.
  constexpr auto repeats = 100;

  // Note: defining the CTX here should make it slightly faster to do these
  // tests.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  REQUIRE(bn_ctx);
  bssl::BN_CTXScope scope(bn_ctx.get());

  for (auto curve : curves) {
    const auto nid = Util::get_nid_from_uint16(curve);
    bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid));

    REQUIRE(group);
    for (unsigned i = 0; i < repeats; i++) {
      // We have to make new shares on each iteration, because each share
      // can only do a single key exchange.
      // This automatically creates the public key for each party too.
      KeySharePKPair prover(curve), verifier(curve), server(curve);
      bssl::UniquePtr<EC_POINT> out(EC_POINT_new(group.get()));
      REQUIRE(three_party_handshake_ideal_functionality(
          group.get(), prover, verifier, server, bn_ctx.get(), &out));
      // Now we'll convert the server's secret into a point
      auto server_point = server.secrets_to_ec_point(group.get(), bn_ctx.get());
      REQUIRE(server_point);
      // N.B This has the same output convention as memcmp.
      CHECK(EC_POINT_cmp(group.get(), out.get(), server_point.get(),
                         bn_ctx.get()) == 0);
    }
  }
}

//! [ThreePartyHandshakeCommTests]
TEST_CASE("ThreePartyHandshakeComm and SSL interop") {
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));

  const bool is_verifier_null = ssl->verifier == nullptr;
  const bool is_commit_to_key_shares_null =
      ssl->commit_to_key_shares == nullptr;
  REQUIRE(is_verifier_null);
  REQUIRE(is_commit_to_key_shares_null);

  SUBCASE("ThreePartyComm does sensible things") {
    SUBCASE("ThreePartyComm returns false on nullptr") {
      CHECK(!ThreePartyHandshake::three_party_handshake_comm(nullptr, nullptr));
      CHECK(
          !ThreePartyHandshake::three_party_handshake_comm(ssl.get(), nullptr));
      CHECK(!ThreePartyHandshake::three_party_handshake_comm(
          nullptr, ssl->s3->hs.get()));
    }

    SUBCASE("ThreePartyComm returns false if verifier is not set") {
      CHECK(!ThreePartyHandshake::three_party_handshake_comm(
          ssl.get(), ssl->s3->hs.get()));
    }

    SUBCASE("ThreePartyComm returns false if verifier is a server") {
      SSL_set_accept_state(ssl.get());
      ssl->verifier = ssl.get();
      CHECK(!ThreePartyHandshake::three_party_handshake_comm(
          ssl.get(), ssl->s3->hs.get()));
    }
  }

  // More fully fledged tests can be found in Server.t.cpp
}
//! [ThreePartyHandshakeCommTests]

//! [ThreePartyHandshakeSendRKSTests]
TEST_CASE("ThreePartyHandshakeSendReceivedKeyShares and SSL interop") {
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));

  const bool is_verifier_null = ssl->verifier == nullptr;
  const bool is_send_key_shares_null = ssl->send_key_shares == nullptr;
  REQUIRE(is_verifier_null);
  REQUIRE(is_send_key_shares_null);
  CBS arr;
  uint16_t group_id{};

  SUBCASE("SendRKS does sensible things") {
    SUBCASE("SendRKS returns false on nullptr") {
      CHECK(
          !ThreePartyHandshake::three_party_handshake_send_received_key_shares(
              nullptr, group_id, arr));
    }

    SUBCASE("SendRKS returns false if verifier is not set") {
      CHECK(
          !ThreePartyHandshake::three_party_handshake_send_received_key_shares(
              ssl.get(), group_id, arr));
    }

    SUBCASE("SendRKS returns false if verifier is a server") {
      SSL_set_accept_state(ssl.get());
      ssl->verifier = ssl.get();
      CHECK(
          !ThreePartyHandshake::three_party_handshake_send_received_key_shares(
              ssl.get(), group_id, arr));
    }

    SUBCASE("SendRKS returns false if the size of the CBS is 0") {
      bssl::Array<uint8_t> under_arr;
      REQUIRE(under_arr.size() == 0);
      CBS_init(&arr, under_arr.data(), under_arr.size());
      REQUIRE(CBS_len(&arr) == 0);
      CHECK(
          !ThreePartyHandshake::three_party_handshake_send_received_key_shares(
              ssl.get(), group_id, arr));
    }

    // More fully fledged tests can be found in Server.t.cpp
  }
}
//! [ThreePartyHandshakeSendRKSTests]

//! [ThreePartyDeriveSharedMasterSecretTests]
TEST_CASE("ThreePartyHandshakeDeriveMasterSecret and SSL interop") {
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  bssl::SSL_HANDSHAKE hs{ssl.get()};

  const bool is_verifier_null = ssl->verifier == nullptr;
  const bool is_commit_to_key_shares_null =
      ssl->commit_to_key_shares == nullptr;
  REQUIRE(is_verifier_null);
  REQUIRE(is_commit_to_key_shares_null);
  bssl::Array<uint8_t> arr;

  SUBCASE("DSMS does sensible things") {
    SUBCASE("DSMS returns false on nullptr") {
      CHECK(!ThreePartyHandshake::derive_shared_master_secret(nullptr, nullptr,
                                                              arr));
      CHECK(!ThreePartyHandshake::derive_shared_master_secret(nullptr,
                                                              ssl.get(), arr));
      CHECK(
          !ThreePartyHandshake::derive_shared_master_secret(&hs, nullptr, arr));
    }

    SUBCASE("DSMS returns false if verifier is not set") {
      CHECK(!ThreePartyHandshake::derive_shared_master_secret(&hs, ssl.get(),
                                                              arr));
    }

    SUBCASE("DSMS returns false if the size is 0") {
      ssl->verifier = ssl.get();
      REQUIRE(arr.size() == 0);
      CHECK(!ThreePartyHandshake::derive_shared_master_secret(&hs, ssl.get(),
                                                              arr));
    }

    SUBCASE("DSMS returns false if verifier is a server") {
      SSL_set_accept_state(ssl.get());
      ssl->verifier = ssl.get();
      REQUIRE(arr.Init(100));
      CHECK(!ThreePartyHandshake::derive_shared_master_secret(&hs, ssl.get(),
                                                              arr));
    }
  }

  // More fully fledged tests can be found in Server.t.cpp
}
//! [ThreePartyDeriveSharedMasterSecretTests]

//! [ThreePartyHandshakeDeriveHandshakeSecretTests]
TEST_CASE("ThreePartyHandshakeDeriveHandshakeSecret and SSL interop") {
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  bssl::SSL_HANDSHAKE hs{ssl.get()};

  const bool is_verifier_null = ssl->verifier == nullptr;
  const bool is_commit_to_key_shares_null =
      ssl->commit_to_key_shares == nullptr;
  REQUIRE(is_verifier_null);
  REQUIRE(is_commit_to_key_shares_null);
  bssl::Array<uint8_t> arr;

  SUBCASE("DSHS does sensible things") {
    SUBCASE("DSHS returns false on nullptr") {
      CHECK(
          !ThreePartyHandshake::derive_handshake_secret(nullptr, nullptr, arr));
      CHECK(!ThreePartyHandshake::derive_handshake_secret(nullptr, ssl.get(),
                                                          arr));
      CHECK(!ThreePartyHandshake::derive_handshake_secret(&hs, nullptr, arr));
    }

    SUBCASE("DSHS returns false if verifier is not set") {
      CHECK(!ThreePartyHandshake::derive_handshake_secret(&hs, ssl.get(), arr));
    }

    SUBCASE("DSHS returns false if the size is 0") {
      ssl->verifier = ssl.get();
      REQUIRE(arr.size() == 0);
      CHECK(!ThreePartyHandshake::derive_handshake_secret(&hs, ssl.get(), arr));
    }

    SUBCASE("DSHS returns false if verifier is a server") {
      SSL_set_accept_state(ssl.get());
      ssl->verifier = ssl.get();
      REQUIRE(arr.Init(100));
      CHECK(!ThreePartyHandshake::derive_handshake_secret(&hs, ssl.get(), arr));
    }
  }

  // More fully fledged tests can be found in Server.t.cpp
}
//! [ThreePartyHandshakeDeriveHandshakeSecretTests]
