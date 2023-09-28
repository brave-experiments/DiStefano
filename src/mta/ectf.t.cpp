#include "../doctest.h"
#include "../ssl/TLSSocket.hpp"
#define SOCKET_SETUP
#include "../ssl/TestUtil.hpp"
#include "../ssl/Util.hpp"
#include "ectf.hpp"
#include <atomic>
#include <iostream>
#include <thread>

//! [ECtFShareInversion]
TEST_CASE("share_inversion") {
  // This function tests that for `x`, `y`, `rho_1` and `rho_2` that
  // the output of both callers is ((x+y)(rho_1+rho_2))^{-1}.

  // We'll use a fixed curve, but there's no real need.
  // constexpr auto curve_id = SSL_CURVE_SECP256R1;
  bssl::UniquePtr<BN_CTX> sbn_ctx(BN_CTX_new());
  REQUIRE(sbn_ctx);

  bssl::UniquePtr<BN_CTX> rbn_ctx(BN_CTX_new());
  REQUIRE(rbn_ctx);

  auto context = CreateContextWithTestCertificate(TLS_method());
  bssl::BN_CTXScope sscope(sbn_ctx.get());
  bssl::BN_CTXScope rscope(rbn_ctx.get());

  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_secp224r1));

  REQUIRE(group);

  const auto *const q = EC_GROUP_get0_order(group.get());
  REQUIRE(q);

  auto build_bn = [&](BN_CTX *ctx) {
    BIGNUM *curr = BN_CTX_get(ctx);
    REQUIRE(curr);
    return curr;
  };

  auto initialise_bn = [&](BN_CTX *ctx) {
    auto curr = build_bn(ctx);
    REQUIRE(BN_rand_range_ex(curr, 1, q));
    return curr;
  };

  auto *x = initialise_bn(rbn_ctx.get());
  auto *y = initialise_bn(sbn_ctx.get());
  auto *rho_1 = initialise_bn(rbn_ctx.get());
  auto *rho_2 = initialise_bn(sbn_ctx.get());

  // Now we'll set up sockets.
  std::unique_ptr<TLSSocket> server, client;
  REQUIRE(setup_sockets(context, server, client));

  // And now we'll run the share inversion.
  BIGNUM *delta_1 = build_bn(rbn_ctx.get());
  BIGNUM *delta_2 = build_bn(sbn_ctx.get());

  auto verifier_code = [&]() {
    REQUIRE(ECtF::share_inversion(delta_1, server->get_ssl_object(), x, rho_1,
                                  q, rbn_ctx.get(), true));
  };

  std::thread verifier(verifier_code);
  REQUIRE(ECtF::share_inversion(delta_2, client->get_ssl_object(), y, rho_2, q,
                                sbn_ctx.get(), false));

  verifier.join();
  CHECK(BN_cmp(delta_1, delta_2) == 0);

  // Check they produce what we'd expect.
  BIGNUM *x_sum = build_bn(sbn_ctx.get());
  BIGNUM *rho_sum = build_bn(sbn_ctx.get());
  BIGNUM *t_delta = build_bn(sbn_ctx.get());
  BIGNUM *inv = build_bn(sbn_ctx.get());
  REQUIRE(BN_mod_add(x_sum, x, y, q, sbn_ctx.get()));
  REQUIRE(BN_mod_add(rho_sum, rho_1, rho_2, q, sbn_ctx.get()));
  REQUIRE(BN_mod_mul(t_delta, x_sum, rho_sum, q, sbn_ctx.get()));
  REQUIRE(BN_mod_inverse(inv, t_delta, q, sbn_ctx.get()));
  CHECK(BN_cmp(inv, delta_1) == 0);
  CHECK(BN_cmp(inv, delta_2) == 0);
}
//! [ECtFShareInversion]

//! [ECtFDryRun]
TEST_CASE("dry_run") {
  // This test checks that we can actually compute the shares
  // of x_1, x_2 without doing the full ectf protocol.
  // This test checks that we can actually output lambda,
  // which is the gradient of points on a curve, as well as gamma.
  // We then manually do the point addition to make sure that this
  // produces the same result as BoringSSL's point arithmetic (without
  // any constant time guarantees -- just for correctness).
  // We'll use a fixed curve, but there's no real need.
  constexpr auto curve_id = SSL_CURVE_SECP256R1;
  bssl::UniquePtr<BN_CTX> sbn_ctx(BN_CTX_new());
  REQUIRE(sbn_ctx);

  bssl::UniquePtr<BN_CTX> rbn_ctx(BN_CTX_new());
  REQUIRE(rbn_ctx);

  auto context = CreateContextWithTestCertificate(TLS_method());
  bssl::BN_CTXScope sscope(sbn_ctx.get());
  bssl::BN_CTXScope rscope(rbn_ctx.get());

  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve_id)));

  REQUIRE(group);

  // In this test function we have two separate primes:
  // q is the characteristic of the field underlying the curve,
  // p is the order of the curve.

  BIGNUM *q = BN_CTX_get(sbn_ctx.get());
  REQUIRE(q);

  REQUIRE(
      EC_GROUP_get_curve_GFp(group.get(), q, nullptr, nullptr, sbn_ctx.get()));
  const auto *const p = EC_GROUP_get0_order(group.get());
  REQUIRE(p);

  auto build_bn = [&](BN_CTX *ctx) {
    BIGNUM *curr = BN_CTX_get(ctx);
    REQUIRE(curr);
    return curr;
  };

  auto initialise_bn = [&](BN_CTX *ctx) {
    auto curr = build_bn(ctx);
    // This is the only place we use `p`.
    REQUIRE(BN_rand_range_ex(curr, 1, p));
    return curr;
  };

  auto negate_bn = [&](const BIGNUM *const elem, BN_CTX *ctx) {
    auto curr = build_bn(ctx);
    auto zero = build_bn(ctx);
    REQUIRE(BN_mod_sub(curr, zero, elem, q, ctx));
    return curr;
  };

  // These are the x-coords.

  // We'll generate elliptic curve points.
  bssl::UniquePtr<EC_POINT> p1_in(EC_POINT_new(group.get())),
      p2_in(EC_POINT_new(group.get()));
  REQUIRE(p1_in);
  REQUIRE(p2_in);

  // Make sure we don't generate the same points for each input.
  do {
    REQUIRE(Util::RandomECPoint(group.get(), p1_in.get(), rbn_ctx.get()));
    REQUIRE(Util::RandomECPoint(group.get(), p2_in.get(), sbn_ctx.get()));
  } while (EC_POINT_cmp(group.get(), p1_in.get(), p2_in.get(), sbn_ctx.get()) ==
           0);
  // And now we'll extract out the affine co-ordinates for the
  // points on the curve.
  auto x_1 = build_bn(rbn_ctx.get());
  auto x_2 = build_bn(sbn_ctx.get());
  auto y_1 = build_bn(rbn_ctx.get());
  auto y_2 = build_bn(sbn_ctx.get());

  REQUIRE(EC_POINT_get_affine_coordinates_GFp(group.get(), p1_in.get(), x_1,
                                              y_1, sbn_ctx.get()));
  REQUIRE(EC_POINT_get_affine_coordinates_GFp(group.get(), p2_in.get(), x_2,
                                              y_2, sbn_ctx.get()));
  // These are the blinding factors for the x-coords.
  auto rho_1 = initialise_bn(rbn_ctx.get());
  auto rho_2 = initialise_bn(sbn_ctx.get());

  // Now we'll set up sockets.
  std::unique_ptr<TLSSocket> server, client;
  REQUIRE(setup_sockets(context, server, client));

  // And now we'll run the share inversion.
  BIGNUM *delta_1 = build_bn(rbn_ctx.get());
  BIGNUM *delta_2 = build_bn(sbn_ctx.get());

  // NOTE: this is different from the other test case. Here we're switching
  // from building an arbitrary inverse to building the inverse of [(x_2 -
  // x_1)(rho_1+rho_2)], which requires a negative x_1.
  BIGNUM *minus_x1 = negate_bn(x_1, rbn_ctx.get());

  auto verifier_code = [&]() {
    REQUIRE(ECtF::share_inversion(delta_1, server->get_ssl_object(), minus_x1,
                                  rho_1, q, rbn_ctx.get(), true));
  };

  std::thread verifier(verifier_code);
  REQUIRE(ECtF::share_inversion(delta_2, client->get_ssl_object(), x_2, rho_2,
                                q, sbn_ctx.get(), false));

  verifier.join();
  // Just to be sure.
  REQUIRE(BN_cmp(delta_1, delta_2) == 0);

  // OK, now we'll compute the eta terms.
  auto *eta_1 = build_bn(rbn_ctx.get());
  auto *eta_2 = build_bn(sbn_ctx.get());
  REQUIRE(BN_mod_mul(eta_1, rho_1, delta_1, q, rbn_ctx.get()));
  REQUIRE(BN_mod_mul(eta_2, rho_2, delta_2, q, sbn_ctx.get()));

  auto *lambda_1 = build_bn(rbn_ctx.get());
  auto *lambda_2 = build_bn(sbn_ctx.get());

  // Again, here we want to have a negative y_1.
  auto minus_y1 = negate_bn(y_1, rbn_ctx.get());
  auto tmp = build_bn(rbn_ctx.get());
  // Just to make sure the negation does what we expected.
  REQUIRE(BN_mod_add(tmp, minus_y1, y_1, q, rbn_ctx.get()));
  REQUIRE(BN_is_zero(tmp));

  auto *gamma_1 = build_bn(rbn_ctx.get());
  auto *gamma_2 = build_bn(sbn_ctx.get());

  // And we'll thread it again.
  auto verifier_lambda_code = [&]() {
    REQUIRE(ECtF::compute_lambda(lambda_1, server->get_ssl_object(), minus_y1,
                                 eta_1, q, rbn_ctx.get(), true));
    REQUIRE(ECtF::compute_gamma(gamma_1, server->get_ssl_object(), lambda_1, q,
                                rbn_ctx.get(), true));
  };

  std::thread verifier_l_thread(verifier_lambda_code);
  REQUIRE(ECtF::compute_lambda(lambda_2, client->get_ssl_object(), y_2, eta_2,
                               q, sbn_ctx.get(), false));
  REQUIRE(ECtF::compute_gamma(gamma_2, client->get_ssl_object(), lambda_2, q,
                              sbn_ctx.get(), false));
  verifier_l_thread.join();

  // The lambda produced here is equivalent to y_2 - y_1 / x_2 - x_1.
  // We'll now check that.
  auto *numerator = initialise_bn(sbn_ctx.get());
  auto *denominator_t = initialise_bn(sbn_ctx.get()),
       *denominator = initialise_bn(sbn_ctx.get());
  auto *comp_lambda = initialise_bn(sbn_ctx.get());
  auto *sum = initialise_bn(sbn_ctx.get());
  REQUIRE(BN_mod_sub(numerator, y_2, y_1, q, sbn_ctx.get()));
  REQUIRE(BN_mod_sub(denominator_t, x_2, x_1, q, sbn_ctx.get()));
  REQUIRE(BN_mod_inverse(denominator, denominator_t, q, sbn_ctx.get()));
  REQUIRE(BN_mod_mul(comp_lambda, numerator, denominator, q, sbn_ctx.get()));
  REQUIRE(BN_mod_add(sum, lambda_1, lambda_2, q, sbn_ctx.get()));
  CHECK(BN_cmp(sum, comp_lambda) == 0);

  // Now we also want to check that the values `gamma` that are produced
  // are the same that we'd expect. Recall that we have `gamma_1 + gamma_2` =
  // lambda_1 * lambda_2.
  auto *prod = build_bn(sbn_ctx.get());
  auto *g_sum = build_bn(sbn_ctx.get());
  REQUIRE(BN_mod_mul(prod, lambda_1, lambda_2, q, sbn_ctx.get()));
  REQUIRE(BN_mod_add(g_sum, gamma_1, gamma_2, q, sbn_ctx.get()));
  CHECK(BN_cmp(g_sum, prod) == 0);

  // With these produced, let's see if we can actually produce useful shares.
  // Recall that the addition formulae are that X((x_1, y_1) + (x_2, y_2)) =
  // lambda^{2} - x_1 - x_2, where lambda = (y_2 - y_1)/(x_2 - x_1) as before.
  // The protocol calls for each party to produce s_i = 2 * gamma_i + lambda_i^2
  // - x[i]. We'll put that into a lambda.
  auto produce_share = [&](const BIGNUM *const gamma,
                           const BIGNUM *const lambda, const BIGNUM *const x) {
    auto sq = build_bn(sbn_ctx.get());
    auto db = build_bn(sbn_ctx.get());
    auto tmp_v = build_bn(sbn_ctx.get());
    auto ret = build_bn(sbn_ctx.get());
    // lambda^2
    REQUIRE(BN_mod_sqr(sq, lambda, q, sbn_ctx.get()));
    // 2 * gamma
    REQUIRE(BN_mod_add(db, gamma, gamma, q, sbn_ctx.get()));
    // 2 * gamma + lambda^2
    REQUIRE(BN_mod_add(tmp_v, db, sq, q, sbn_ctx.get()));
    // 2 * gamma + lambda^2 - x
    REQUIRE(BN_mod_sub(ret, tmp_v, x, q, sbn_ctx.get()));
    return ret;
  };

  auto s1 = produce_share(gamma_1, lambda_1, x_1);
  auto s2 = produce_share(gamma_2, lambda_2, x_2);

  // The share is s1 + s2
  auto s = build_bn(sbn_ctx.get());
  REQUIRE(BN_mod_add(s, s1, s2, q, sbn_ctx.get()));

  // Now we'll also compute the x-coord of the new point.
  auto comp_l = build_bn(sbn_ctx.get());
  REQUIRE(BN_mod_sqr(comp_l, comp_lambda, q, sbn_ctx.get()));

  auto x_t = build_bn(sbn_ctx.get());
  // Compute x_t = -x_1 - x_2
  REQUIRE(BN_mod_sub(x_t, minus_x1, x_2, q, sbn_ctx.get()));

  auto x_3 = build_bn(sbn_ctx.get());
  // Compute x_3 = lambda^2 - x_1 - x_2, which
  // is the co-ordinate of P1 + P2.
  REQUIRE(BN_mod_add(x_3, comp_l, x_t, q, sbn_ctx.get()));

  const auto worked = BN_cmp(x_3, s) == 0;
  CHECK(worked);
  if (worked) {
    // We'll check that it works if we do the addition as EC points.
    // Note: we're making the points separately from before to isolate
    // points of failure.
    bssl::UniquePtr<EC_POINT> p1(EC_POINT_new(group.get())),
        p2(EC_POINT_new(group.get())), p3(EC_POINT_new(group.get()));
    REQUIRE(p1);
    REQUIRE(p2);
    REQUIRE(p3);

    // Now set up each point.
    REQUIRE(EC_POINT_set_affine_coordinates_GFp(group.get(), p1.get(), x_1, y_1,
                                                sbn_ctx.get()));
    REQUIRE(EC_POINT_set_affine_coordinates_GFp(group.get(), p2.get(), x_2, y_2,
                                                sbn_ctx.get()));
    REQUIRE(
        EC_POINT_add(group.get(), p3.get(), p1.get(), p2.get(), sbn_ctx.get()));
    // Now deserialise the x-coord.
    auto x_coord = build_bn(sbn_ctx.get());
    auto y_coord = build_bn(sbn_ctx.get());
    REQUIRE(EC_POINT_get_affine_coordinates_GFp(group.get(), p3.get(), x_coord,
                                                y_coord, sbn_ctx.get()));

    SUBCASE("as ec_point") {
      // Hypothetically, if we set up these points over GF_p, what would happen?
      bssl::UniquePtr<EC_POINT> p4(EC_POINT_new(group.get()));

      REQUIRE(p4);
      auto y_3 = build_bn(sbn_ctx.get());
      // NOTE: this is not the co-ordinate that's used in the construction
      // of the point: it's just a temporary.
      auto x_4 = build_bn(sbn_ctx.get());
      REQUIRE(BN_sub(x_4, x_1, x_3));
      // x_4 = x_1 - x_3 (x_3 is lambda^2 - x_1 - x_2, which is the x-coord of
      // our produced point).
      REQUIRE(BN_mod_sub(x_4, x_1, x_3, q, sbn_ctx.get()));
      auto lambda_x4 = build_bn(sbn_ctx.get());
      // lambda_x4 = lambda * (x_1 - x_4), which is part of the y co-ord.
      REQUIRE(BN_mul(lambda_x4, comp_lambda, x_4, sbn_ctx.get()));
      // y_4 = lambda * (x_1 - diff) - y_1, which is the full y coord of the
      // point.
      REQUIRE(BN_mod_sub(y_3, lambda_x4, y_1, q, sbn_ctx.get()));
      REQUIRE(BN_cmp(y_3, q) < 0);
      REQUIRE(BN_cmp(x_3, q) < 0);

      // Now we'll build the point. NOTE: the parameter here is x_3,
      // because that's the _actual_ x-co ordinate as produced by the shares.
      const auto was_point = EC_POINT_set_affine_coordinates_GFp(
          group.get(), p4.get(), x_3, y_coord, sbn_ctx.get());
      CHECK(was_point);
    }

    SUBCASE("not as ec_point") {
      // And now we'll check the values as if they were bignums.
      CHECK(BN_cmp(x_coord, s) == 0);
      CHECK(BN_cmp(x_coord, x_3) == 0);
    }
  }
}

//! [ECtFectfTests]
TEST_CASE("ectf") {
  constexpr auto curve_id = SSL_CURVE_SECP256R1;
  bssl::UniquePtr<BN_CTX> sbn_ctx(BN_CTX_new());
  REQUIRE(sbn_ctx);

  bssl::UniquePtr<BN_CTX> rbn_ctx(BN_CTX_new());
  REQUIRE(rbn_ctx);

  auto context = CreateContextWithTestCertificate(TLS_method());
  bssl::BN_CTXScope sscope(sbn_ctx.get());
  bssl::BN_CTXScope rscope(rbn_ctx.get());

  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve_id)));

  REQUIRE(group);

  BIGNUM *q = BN_CTX_get(sbn_ctx.get());
  REQUIRE(q);

  REQUIRE(
      EC_GROUP_get_curve_GFp(group.get(), q, nullptr, nullptr, sbn_ctx.get()));

  auto build_bn = [&](BN_CTX *ctx) {
    BIGNUM *curr = BN_CTX_get(ctx);
    REQUIRE(curr);
    return curr;
  };

  bssl::UniquePtr<EC_POINT> receiver_point(EC_POINT_new(group.get())),
      sender_point(EC_POINT_new(group.get()));

  // Make sure we haven't somehow produced an exact pair.
  do {
    REQUIRE(
        Util::RandomECPoint(group.get(), receiver_point.get(), rbn_ctx.get()));
    REQUIRE(
        Util::RandomECPoint(group.get(), sender_point.get(), sbn_ctx.get()));
  } while (EC_POINT_cmp(group.get(), receiver_point.get(), sender_point.get(),
                        sbn_ctx.get()) == 0);

  // We're now going to serialise both co-ordinates from each from their
  // points.
  auto rx = build_bn(rbn_ctx.get()), ry = build_bn(rbn_ctx.get()),
       sx = build_bn(sbn_ctx.get()), sy = build_bn(rbn_ctx.get());
  REQUIRE(EC_POINT_get_affine_coordinates_GFp(group.get(), receiver_point.get(),
                                              rx, ry, rbn_ctx.get()));
  REQUIRE(EC_POINT_get_affine_coordinates_GFp(group.get(), sender_point.get(),
                                              sx, sy, sbn_ctx.get()));

  // Now we have to serialise those points into arrays.
  bssl::Array<uint8_t> s_secret_x, s_secret_y, r_secret_x, r_secret_y;
  const auto size = (EC_GROUP_get_degree(group.get()) + 7) / 8;

  REQUIRE(s_secret_x.Init(size));
  REQUIRE(s_secret_y.Init(size));
  REQUIRE(r_secret_x.Init(size));
  REQUIRE(r_secret_y.Init(size));

  REQUIRE(BN_bn2bin_padded(s_secret_x.data(), s_secret_x.size(), sx));
  REQUIRE(BN_bn2bin_padded(s_secret_y.data(), s_secret_y.size(), sy));
  REQUIRE(BN_bn2bin_padded(r_secret_x.data(), r_secret_x.size(), rx));
  REQUIRE(BN_bn2bin_padded(r_secret_y.data(), r_secret_y.size(), ry));

  // With that we'll set-up a network connection.
  // Now we'll set up sockets.
  std::unique_ptr<TLSSocket> server, client;
  REQUIRE(setup_sockets(context, server, client));

  // And now we'll compute the shares
  // As a note, this uses lambda = r_secret_y - s_secret_y / r_secret_x -
  // s_secret_x. The goal here is to compute sender_point + receiver_point.
  size_t size_of_p_v, size_of_p_p;

  SUBCASE("as bignum") {
    auto rb = build_bn(rbn_ctx.get());
    auto sb = build_bn(sbn_ctx.get());

    auto verifier_code = [&]() {
      REQUIRE(ECtF::ectf_produce_bignum(sb, server->get_ssl_object(),
                                        s_secret_x, s_secret_y, curve_id, true,
                                        &size_of_p_v));
    };

    std::thread verifier(verifier_code);
    REQUIRE(ECtF::ectf_produce_bignum(rb, client->get_ssl_object(), r_secret_x,
                                      r_secret_y, curve_id, false,
                                      &size_of_p_p));
    verifier.join();
    REQUIRE(size_of_p_v == size_of_p_p);

    // And now check that the values add up as we'd expect.
    // To do that, we'll add the receiver and sender's points, extract
    // the x-coordinate, and check that it's the same as rb + sb.
    // The shares should sum to lambda - x_2 - x_1
    auto sum_existing = build_bn(rbn_ctx.get());
    auto sum_produced = build_bn(rbn_ctx.get());
    // With that done, let's check if the additions match up to what we'd
    // expect. To do that, we'll add the receiver and sender's points, extract
    // the x-coordinate, and check that it's the same as r_out + s_out.
    bssl::UniquePtr<EC_POINT> sum(EC_POINT_new(group.get()));
    REQUIRE(sum);
    // Note that this is computing sender_point + receiver_point, as above.
    REQUIRE(EC_POINT_add(group.get(), sum.get(), sender_point.get(),
                         receiver_point.get(), sbn_ctx.get()));

    // We've now got their sums. Let's decompose.
    REQUIRE(EC_POINT_get_affine_coordinates_GFp(
        group.get(), sum.get(), sum_existing, nullptr, sbn_ctx.get()));
    REQUIRE(BN_cmp(sum_existing, q) < 0);

    // Now compute sb + rb.
    REQUIRE(BN_mod_add(sum_produced, sb, rb, q, sbn_ctx.get()));
    CHECK(BN_cmp(sum_produced, sum_existing) == 0);
  }

  SUBCASE("as serialised") {
    bssl::Array<uint8_t> sb;
    bssl::Array<uint8_t> rb;

    auto verifier_code = [&]() {
      REQUIRE(ECtF::ectf(sb, server->get_ssl_object(), s_secret_x, s_secret_y,
                         curve_id, true));
    };

    std::thread verifier(verifier_code);
    REQUIRE(ECtF::ectf(rb, client->get_ssl_object(), r_secret_x, r_secret_y,
                       curve_id, false));
    verifier.join();

    // And now check that the values add up as we'd expect.
    // To do that, we'll add the receiver and sender's points, extract
    // the x-coordinate, and check that it's the same as rb + sb.
    // The shares should sum to lambda - x_2 - x_1
    auto sum_existing = build_bn(rbn_ctx.get());
    auto sum_produced = build_bn(rbn_ctx.get());
    // With that done, let's check if the additions match up to what we'd
    // expect. To do that, we'll add the receiver and sender's points, extract
    // the x-coordinate, and check that it's the same as r_out + s_out.
    bssl::UniquePtr<EC_POINT> sum(EC_POINT_new(group.get()));
    REQUIRE(sum);
    // Note that this is computing sender_point + receiver_point, as above.
    REQUIRE(EC_POINT_add(group.get(), sum.get(), sender_point.get(),
                         receiver_point.get(), sbn_ctx.get()));

    // We've now got their sums. Let's decompose.
    REQUIRE(EC_POINT_get_affine_coordinates_GFp(
        group.get(), sum.get(), sum_existing, nullptr, sbn_ctx.get()));
    REQUIRE(BN_cmp(sum_existing, q) < 0);

    // Now compute sb + rb.
    // To do that, we need to re-convert sb and rb.
    auto sb_b = build_bn(sbn_ctx.get());
    auto rb_b = build_bn(sbn_ctx.get());
    REQUIRE(BN_bin2bn(sb.data(), sb.size(), sb_b));
    REQUIRE(BN_bin2bn(rb.data(), rb.size(), rb_b));

    REQUIRE(BN_mod_add(sum_produced, sb_b, rb_b, q, sbn_ctx.get()));
    CHECK(BN_cmp(sum_produced, sum_existing) == 0);
  }
}
