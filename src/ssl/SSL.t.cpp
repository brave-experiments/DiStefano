#include "../doctest.h"
#include "openssl/base.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "ssl/internal.h"

// This file just contains tests for the changes to BoringSSL that we've made
// In particular, this file tests:
// 1) The setters and getters for adding the callback for the key share split.

// N.B this function is used as a function pointer stub.
static bool commit_to_key_shares_test(SSL *, bssl::SSL_HANDSHAKE *) {
  return true;
}

// N.B this function is used as a function pointer stub.
static void thrower_test() {}

// N.B this function is used as a function pointer stub.
static bool send_key_shares_test(SSL *, uint16_t, CBS &) { return true; }

// N.B this function is used as a function pointer stub.
static bool derive_secret_share_test(bssl::SSL_HANDSHAKE *, SSL *,
                                     bssl::Array<uint8_t> &) {
  return true;
}

static bool derive_handshake_key_test(bssl::SSL_HANDSHAKE *, SSL *,
                                      bssl::Array<uint8_t> &) {
  return true;
}

static bool advance_key_schedule_test(bssl::SSL_HANDSHAKE *, SSL *,
                                      bssl::Array<uint8_t> &) {
  return true;
}

TEST_CASE("SSL changes work") {
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  bssl::UniquePtr<SSL> ssl_2(SSL_new(context.get()));
  REQUIRE(ssl);
  REQUIRE(ssl_2);

  REQUIRE(!ssl->verifier);
  REQUIRE(!ssl->commit_to_key_shares);

  SUBCASE("Calling set_verifier with null pointers fails") {
    CHECK(!SSL::set_verifier(nullptr, nullptr));
    CHECK(!SSL::set_verifier(nullptr, ssl.get()));
    CHECK(!SSL::set_verifier(ssl.get(), nullptr));
  }

  SUBCASE("Calling set_verifier with the same object twice fails") {
    CHECK(!SSL::set_verifier(ssl.get(), ssl.get()));
  }

  SUBCASE("Calling set_verifier with different objects passes") {
    CHECK(SSL::set_verifier(ssl.get(), ssl_2.get()));
  }

  SUBCASE("Calling set_commit_to_key_shares with a null pointer fails") {
    CHECK(!SSL::set_commit_to_key_shares(nullptr, nullptr));
  }

  SUBCASE("Calling set_commit_to_key_shares with a null function passes") {
    CHECK(SSL::set_commit_to_key_shares(ssl.get(), nullptr));
    const bool is_null = ssl->commit_to_key_shares == nullptr;
    CHECK(is_null);
  }

  SUBCASE("Calling set_commit_to_key_shares with a real function passes") {
    CHECK(SSL::set_commit_to_key_shares(ssl.get(), &commit_to_key_shares_test));
    const auto set_properly =
        ssl->commit_to_key_shares == &commit_to_key_shares_test;
    CHECK(set_properly);
  }

  SUBCASE("Calling set_commit_to_key_shares on a server fails") {
    SSL_set_accept_state(ssl.get());
    CHECK(
        !SSL::set_commit_to_key_shares(ssl.get(), &commit_to_key_shares_test));
  }

  SUBCASE("Calling set_verifier on a server fails") {
    SSL_set_accept_state(ssl.get());
    CHECK(!SSL::set_verifier(ssl.get(), ssl_2.get()));
  }
}

TEST_CASE("Overriding the thrower works") {
  // This test case checks that setting the thrower works.
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);

  SUBCASE("Calling ssl_set_thrower on a null ssl object fails") {
    CHECK(!SSL::set_throw_function(nullptr, nullptr, 0));
    // The second argument can be null: this just shows it doesn't matter.
    CHECK(!SSL::set_throw_function(nullptr, &thrower_test, 0));
  }

  SUBCASE("Calling ssl_set_thrower on a server object fails") {
    SSL_set_accept_state(ssl.get());
    CHECK(!SSL::set_throw_function(ssl.get(), &thrower_test, 0));
    // Again, the second argument doesn't matter
    CHECK(!SSL::set_throw_function(ssl.get(), nullptr, 0));
  }

  SUBCASE("Calling ssl_set_thrower on a client object works") {

    SUBCASE("Calling ssl_set_thrower with a nullptr func works") {
      CHECK(SSL::set_throw_function(ssl.get(), nullptr, 0));
      const auto is_null = ssl->thrower == nullptr;
      CHECK(is_null);
    }

    SUBCASE("Calling ssl_set_thrower with a non-nullptr func works") {
      CHECK(SSL::set_throw_function(ssl.get(), &thrower_test, 0));
      const auto is_thrower = ssl->thrower == &thrower_test;
      CHECK(is_thrower);
    }
  }

  SUBCASE("Calling ssl_set_thrower on a client object also sets the state") {
    SUBCASE("Calling ssl_set_thrower with a nullptr also sets the state") {
      // I guess this is a nice guarantee, but it isn't actually useful.
      REQUIRE(ssl->throw_state == 0);
      CHECK(SSL::set_throw_function(ssl.get(), nullptr, 1));
      const auto is_null = ssl->thrower == nullptr;
      CHECK(is_null);
      CHECK(ssl->throw_state == 1);
    }
    SUBCASE(
        "Calling ssl_set_thrower with a non-nullptr func also sets the state") {
      REQUIRE(ssl->throw_state == 0);
      CHECK(SSL::set_throw_function(ssl.get(), &thrower_test, 2));
      const auto is_thrower = ssl->thrower == &thrower_test;
      CHECK(is_thrower);
      CHECK(ssl->throw_state == 2);
    }
  }
}

TEST_CASE("Overriding send_key_shares works") {
  // This test case checks that setting the thrower works.
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);

  SUBCASE("Calling set_send_key_shares on a null ssl object fails") {
    CHECK(!SSL::set_send_key_shares(nullptr, nullptr));
    // The second argument can be null: this just shows it doesn't matter.
    CHECK(!SSL::set_send_key_shares(nullptr, &send_key_shares_test));
  }

  SUBCASE("Calling ssl_set_send_key_shares on a server object fails") {
    SSL_set_accept_state(ssl.get());
    CHECK(!SSL::set_send_key_shares(ssl.get(), &send_key_shares_test));
    // Again, the second argument doesn't matter
    CHECK(!SSL::set_send_key_shares(ssl.get(), nullptr));
  }

  SUBCASE("Calling ssl_set_send_key_shares on a client object works") {

    SUBCASE("Calling ssl_set_send_key_shares with a nullptr func works") {
      CHECK(SSL::set_send_key_shares(ssl.get(), nullptr));
      const auto is_null = ssl->send_key_shares == nullptr;
      CHECK(is_null);
    }

    SUBCASE("Calling ssl_send_key_shares with a non-nullptr func works") {
      CHECK(SSL::set_send_key_shares(ssl.get(), &send_key_shares_test));
      const auto is_set = ssl->send_key_shares == &send_key_shares_test;
      CHECK(is_set);
    }
  }
}

TEST_CASE("Overriding send_key_shares works") {
  // This test case checks that setting the derived_secret_share function works.
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);

  SUBCASE("Calling set_derived_secret_share on a null ssl object fails") {
    CHECK(!SSL::set_derive_secret_share(nullptr, nullptr));
    // The second argument can be null: this just shows it doesn't matter.
    CHECK(!SSL::set_derive_secret_share(nullptr, &derive_secret_share_test));
  }

  SUBCASE("Calling ssl_set_derived_secret_shares on a server object fails") {
    SSL_set_accept_state(ssl.get());
    CHECK(!SSL::set_derive_secret_share(ssl.get(), &derive_secret_share_test));
    // Again, the second argument doesn't matter
    CHECK(!SSL::set_derive_secret_share(ssl.get(), nullptr));
  }

  SUBCASE("Calling ssl_set_derived_secret_shares on a client object works") {

    SUBCASE("Calling ssl_set_derived_secret_shares with a nullptr func works") {
      CHECK(SSL::set_derive_secret_share(ssl.get(), nullptr));
      const auto is_null = ssl->derive_shared_secret == nullptr;
      CHECK(is_null);
    }

    SUBCASE("Calling ssl_send_key_shares with a non-nullptr func works") {
      CHECK(SSL::set_derive_secret_share(ssl.get(), &derive_secret_share_test));
      const auto is_set =
          ssl->derive_shared_secret == &derive_secret_share_test;
      CHECK(is_set);
    }
  }
}

TEST_CASE("Overriding derive_handshake_keys works") {
  // This test case checks that setting the derived_secret_share function works.
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);

  SUBCASE("Calling set_derived_handshake_secrets on a null ssl object fails") {
    CHECK(!SSL::set_derive_handshake_keys(nullptr, nullptr));
    // The second argument can be null: this just shows it doesn't matter.
    CHECK(!SSL::set_derive_handshake_keys(nullptr, &derive_handshake_key_test));
  }

  SUBCASE("Calling ssl_set_derived_secret_shares on a server object fails") {
    SSL_set_accept_state(ssl.get());
    CHECK(
        !SSL::set_derive_handshake_keys(ssl.get(), &derive_handshake_key_test));
    // Again, the second argument doesn't matter
    CHECK(!SSL::set_derive_handshake_keys(ssl.get(), nullptr));
  }

  SUBCASE("Calling ssl_set_derived_secret_shares on a client object works") {
    SUBCASE("Calling ssl_set_derived_secret_shares with a nullptr func works") {
      CHECK(SSL::set_derive_handshake_keys(ssl.get(), nullptr));
      const auto is_null = ssl->derive_shared_secret == nullptr;
      CHECK(is_null);
    }

    SUBCASE(
        "Calling ssl_set_derived_secret_shares with a non-nullptr func works") {
      CHECK(SSL::set_derive_handshake_keys(ssl.get(),
                                           &derive_handshake_key_test));
      const auto is_set =
          ssl->derive_handshake_keys == &derive_handshake_key_test;
      CHECK(is_set);
    }
  }
}

TEST_CASE("Overriding advance_key_share works") {
  // This test case checks that setting the advance_key_share function works.
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  REQUIRE(ssl);

  SUBCASE("Calling advance_key_share on a null ssl object fails") {
    CHECK(!SSL::set_advance_key_schedule(nullptr, nullptr));
    // The second argument can be null: this just shows it doesn't matter.
    CHECK(!SSL::set_advance_key_schedule(nullptr, &advance_key_schedule_test));
  }

  SUBCASE("Calling ssl_set_advance_key_schedule on a server object fails") {
    SSL_set_accept_state(ssl.get());
    CHECK(
        !SSL::set_advance_key_schedule(ssl.get(), &advance_key_schedule_test));
    // Again, the second argument doesn't matter
    CHECK(!SSL::set_advance_key_schedule(ssl.get(), nullptr));
  }

  SUBCASE("Calling ssl_set_advance_key_schedule on a client object works") {
    SUBCASE("Calling ssl_set_advance_key_schedule with a nullptr func works") {
      CHECK(SSL::set_advance_key_schedule(ssl.get(), nullptr));
      const auto is_null = ssl->advance_key_schedule == nullptr;
      CHECK(is_null);
    }

    SUBCASE(
        "Calling ssl_set_advance_key_schedule with a non-nullptr func works") {
      CHECK(
          SSL::set_advance_key_schedule(ssl.get(), &advance_key_schedule_test));
      const auto is_set =
          ssl->advance_key_schedule == &advance_key_schedule_test;
      CHECK(is_set);
    }
  }
}

TEST_CASE("Overriding the group works") {
  // This test case checks that overriding the public groups works.
  // For sake of decent testing, we won't actually do a full handshake: we'll
  // create each bit separately.
  bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
  REQUIRE(context);
  bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
  bssl::UniquePtr<SSL> ssl2(SSL_new(context.get()));

  REQUIRE(ssl);
  REQUIRE(ssl2);

  SUBCASE("Calling ssl_set_nist_curves with null pointers fails") {
    CHECK(!bssl::ssl_set_nist_curves(nullptr, nullptr));
    CHECK(!bssl::ssl_set_nist_curves(ssl.get(), nullptr));
    CHECK(!bssl::ssl_set_nist_curves(nullptr, ssl->s3->hs.get()));
  }

  SUBCASE("Calling ssl_set_nist_curves on a server object fails") {
    SSL_set_accept_state(ssl.get());
    CHECK(!bssl::ssl_set_nist_curves(ssl.get(), ssl->s3->hs.get()));
  }

  SUBCASE("Calling ssl_set_nist_curves on a client object with no verifier "
          "does nothing") {
    REQUIRE(ssl->s3->hs->config->supported_group_list.empty());
    REQUIRE(!ssl->verifier);
    // This should return true
    CHECK(bssl::ssl_set_nist_curves(ssl.get(), ssl->s3->hs.get()));
    CHECK(ssl->s3->hs->config->supported_group_list.empty());
  }

  SUBCASE("Calling ssl_set_nist_curves on a valid object succeeds") {
    REQUIRE(SSL::set_verifier(ssl.get(), ssl2.get()));
    REQUIRE(ssl->s3->hs->config->supported_group_list.empty());
    CHECK(bssl::ssl_set_nist_curves(ssl.get(), ssl->s3->hs.get()));
    const auto &group = ssl->s3->hs->config->supported_group_list;
    REQUIRE(group.size() == 3);

    // The order doesn't actually matter so much, so we'll just use find.
    CHECK(std::find(group.begin(), group.end(), SSL_CURVE_SECP256R1) !=
          group.end());
    CHECK(std::find(group.begin(), group.end(), SSL_CURVE_SECP384R1) !=
          group.end());
    CHECK(std::find(group.begin(), group.end(), SSL_CURVE_SECP521R1) !=
          group.end());
  }
}
