#include "ectf.hpp"
#include "../ssl/Util.hpp"
#include "MtA.hpp"
#include <cassert>
#include <iostream>

// FILE-wide assumption: the verifier is a sender, and the prover is a receiver.
// This is also set in MtA.hpp too, so this is consistent.

// These structs just allow us to
// retrieve the function to use in MtA in a type-safe way (i.e
// avoiding the fact that these functions have different parameter
// layouts).

// We also only support IKNP extension here.
template <bool verifier> struct MtAFunction {};

template <> struct MtAFunction<true> {
  static constexpr auto func = &MtA::play_sender_inplace_iknp;
};

template <> struct MtAFunction<false> {
  static constexpr auto func = &MtA::play_receiver_inplace_iknp;
};

// This is also more template trickery: this time for building something.
// Because the packs are technically different types, we need to use struct
// metaprogramming to build the types consistently.

template <bool verifier> struct MtABuild {};

template <> struct MtABuild<true> {
  static SenderEntry build(const BIGNUM *const p, BN_CTX *const ctx) noexcept {

    assert(p);
    assert(ctx);
    SenderEntry se;
    [[maybe_unused]] const auto worked =
        MtA::initialise_entries_for_sender(p, se, ctx);
    assert(worked);
    return se;
  }
};

template <> struct MtABuild<false> {
  static ReceiverEntry build(const BIGNUM *const p,
                             BN_CTX *const ctx) noexcept {
    assert(p);
    assert(ctx);
    ReceiverEntry re;
    [[maybe_unused]] const auto worked =
        MtA::initialise_entries_for_receiver(p, re, ctx);
    assert(worked);
    return re;
  }
};

// This function acts as a dispatch for MtA across two values, a1 and a2.
// The produced shares are then added together and stored in `out`.
template <typename F, typename ET, typename OTType>
static bool vector_mta_2(BIGNUM *const out, BIGNUM *const a1, BIGNUM *const a2,
                         const BIGNUM *const first, const BIGNUM *const second,
                         const BIGNUM *const p, BN_CTX *const ctx, OTType &ot,
                         ET &entry, F &&func) noexcept {

  return out && a1 && a2 && first && second && p && ctx &&
         func(a1, ot, first, p, ctx, entry) &&
         func(a2, ot, second, p, ctx, entry) && BN_mod_add(out, a1, a2, p, ctx);
}

// This function takes two secrets (`x_secret`, `y_secret`, and converts them
// into bignums).
static bool serialised_to_bn(BIGNUM *const x, BIGNUM *const y,
                             const bssl::Array<uint8_t> &x_secret,
                             const bssl::Array<uint8_t> &y_secret) noexcept {
  return x && y && BN_bin2bn(x_secret.data(), x_secret.size(), x) &&
         BN_bin2bn(y_secret.data(), y_secret.size(), y);
}

template <bool verifier, typename ET, typename OTType>
static bool
scale_plus_share_impl(BIGNUM *out, OTType &ot, const BIGNUM *const val,
                      const BIGNUM *const blind, BIGNUM *const tmp_1,
                      BIGNUM *const tmp_2, BIGNUM *const tmp_3,
                      const BIGNUM *const p, BN_CTX *ctx, ET &et) noexcept {

  // This function is a small implementation of the main body of
  // the ectf functionality. Essentially, the main body of
  // the ectf algorithm at two steps does something that looks like this:
  // p_i = (val_i) * (blind_i) + (share_i).
  //
  // Since this pops up twice, it makes sense to extract the functionality here.
  // NOTE: this function accepts temporaries as pointer arguments to save on
  // allocations, but also for correctness.

  // These are just generic pre-conditions.
  if (!out || !val || !p || !blind || !ctx || !tmp_1 || !tmp_2 || !tmp_3) {
    return false;
  }

  // This is a type hack: essentially, it generically says "if the player is a
  // verifier, then they play as a sender: otherwise, they play as a receiver".
  // This is just to make it neater further down.
  // This should come at no runtime cost.
  constexpr auto mta_func = MtAFunction<verifier>::func;

  // We also rely upon both parties supplying their inputs in a different order.
  // This is for both masking and correctness: we don't want either party to
  // learn the other parties' share. This should be done at compile-time, so it
  // has no runtime cost.
  const auto *first = (verifier) ? val : blind;
  const auto *second = (verifier) ? blind : val;

  // This is the MtA call.
  if (!vector_mta_2(tmp_1, tmp_2, tmp_3, first, second, p, ctx, ot, et,
                    mta_func)) {
    return false;
  }

  // We now need to compute the aforementioned function:
  // namely, we compute p_i = (val * blind) + share
  return BN_mod_mul(tmp_2, val, blind, p, ctx) &&
         BN_mod_add(out, tmp_1, tmp_2, p, ctx);
}

template <bool verifier, typename ET, typename OTType>
static bool share_inversion_impl(BIGNUM *out, OTType &ot, const BIGNUM *const x,
                                 const BIGNUM *const rho, BIGNUM *const tmp_1,
                                 BIGNUM *const tmp_2, BIGNUM *const tmp_3,
                                 BIGNUM *const tmp_4, const BIGNUM *const p,
                                 BN_CTX *ctx, ET &entry) noexcept {

  // This produces our local delta value, held in `tmp_1`.
  if (!scale_plus_share_impl<verifier>(tmp_1, ot, x, rho, tmp_2, tmp_3, tmp_4,
                                       p, ctx, entry)) {
    return false;
  }

  // We now need to send delta to the other party. They'll also send us
  // their delta. Note that delta is held in tmp1.
  bssl::Array<uint8_t> delta_ser, delta_in;
  const int size_as_int = static_cast<int>(BN_num_bytes(p));
  assert(size_as_int < SSL3_RT_MAX_PLAIN_LENGTH);
  assert(BN_num_bytes(p) >= BN_num_bytes(tmp_1));

  auto *const ssl = ot.io->get_ssl();

  // The reads and writes here shouldn't overlap.
  if (!delta_ser.Init(BN_num_bytes(p)) || !delta_in.Init(BN_num_bytes(p)) ||
      !BN_bn2bin_padded(delta_ser.data(), delta_ser.size(), tmp_1) ||
      SSL_write(ssl, delta_ser.data(), size_as_int) != size_as_int ||
      SSL_read(ssl, delta_in.data(), size_as_int) != size_as_int ||
      !BN_bin2bn(delta_in.data(), delta_in.size(), tmp_2)) {
    return false;
  }

  // Now we'll compute the sum, invert, and return.
  return BN_mod_add(tmp_3, tmp_1, tmp_2, p, ctx) &&
         BN_mod_inverse(out, tmp_3, p, ctx);
}

bool ECtF::share_inversion(BIGNUM *out, SSL *const ssl, const BIGNUM *const x,
                           const BIGNUM *const rho, const BIGNUM *const p,
                           BN_CTX *const ctx, const bool verifier) noexcept {

  EmpWrapper<> wrapper{ssl};
  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
  return share_inversion(out, ot, x, rho, p, ctx, verifier);
}

bool ECtF::share_inversion(BIGNUM *out, emp::IKNP<EmpWrapper<>> &ot,
                           const BIGNUM *const x, const BIGNUM *const rho,
                           const BIGNUM *const p, BN_CTX *const ctx,
                           const bool verifier) noexcept {

  // This is a more friendly wrapper to call into doing share inversion.
  // The share_inversion_inplace function isn't _as_ kind, as it requires you
  // to pass in the temporaries explicitly.
  BIGNUM *delta = BN_CTX_get(ctx);
  BIGNUM *tmp_1 = BN_CTX_get(ctx);
  BIGNUM *tmp_2 = BN_CTX_get(ctx);
  BIGNUM *tmp_3 = BN_CTX_get(ctx);

  if (verifier) {
    // verifier is a sender, so build a sender entry.
    auto entry = MtABuild<true>::build(p, ctx);
    return delta && tmp_1 && tmp_2 && tmp_3 &&
           share_inversion_impl<true>(out, ot, x, rho, delta, tmp_1, tmp_2,
                                      tmp_3, p, ctx, entry);
  } else {
    // prover is a receiver, so build a receiver entry.
    auto entry = MtABuild<false>::build(p, ctx);
    return delta && tmp_1 && tmp_2 && tmp_3 &&
           share_inversion_impl<false>(out, ot, x, rho, delta, tmp_1, tmp_2,
                                       tmp_3, p, ctx, entry);
  }
}

template <bool verifier, typename ET, typename OTType>
static bool compute_lambda_impl(BIGNUM *const out, OTType &ot,
                                const BIGNUM *const x, const BIGNUM *const rho,
                                BIGNUM *const tmp_1, BIGNUM *const tmp_2,
                                BIGNUM *const tmp_3, const BIGNUM *const p,
                                BN_CTX *const ctx, ET &entry) noexcept {
  // It turns out that computing lambda is just the same as computing a scaled
  // share.
  return scale_plus_share_impl<verifier>(out, ot, x, rho, tmp_1, tmp_2, tmp_3,
                                         p, ctx, entry);
}

template <typename OTType>
static bool compute_lambda_use_inplace(
    BIGNUM *out, OTType &ot, const BIGNUM *const x, const BIGNUM *const rho,
    BIGNUM *const tmp_1, BIGNUM *const tmp_2, BIGNUM *const tmp_3,
    const BIGNUM *const p, BN_CTX *const ctx, const bool verifier) noexcept {
  if (verifier) {
    // Build a sender entry and dispatch.
    auto entry = MtABuild<true>::build(p, ctx);
    return compute_lambda_impl<true>(out, ot, x, rho, tmp_1, tmp_2, tmp_3, p,
                                     ctx, entry);
  } else {
    // Build a receiver entry and dispatch.
    auto entry = MtABuild<false>::build(p, ctx);
    return compute_lambda_impl<false>(out, ot, x, rho, tmp_1, tmp_2, tmp_3, p,
                                      ctx, entry);
  }
}

bool ECtF::compute_lambda(BIGNUM *out, SSL *const ssl, const BIGNUM *const x,
                          const BIGNUM *const rho, const BIGNUM *const p,
                          BN_CTX *const ctx, const bool verifier) noexcept {
  // This function is as easy as returning the scaled share,
  // as the work is essentially the same (given the right parameters).
  BIGNUM *tmp_1 = BN_CTX_get(ctx);
  BIGNUM *tmp_2 = BN_CTX_get(ctx);
  BIGNUM *tmp_3 = BN_CTX_get(ctx);

  EmpWrapper<> wrapper{ssl};
  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);

  return tmp_1 && tmp_2 && tmp_3 &&
         compute_lambda_use_inplace(out, ot, x, rho, tmp_1, tmp_2, tmp_3, p,
                                    ctx, verifier);
}

template <bool verifier>
static const BIGNUM *
negate_if_verifier(const BIGNUM *const in, BIGNUM *const tmp_1,
                   const BIGNUM *const tmp_2, const BIGNUM *const p,
                   BN_CTX *const ctx) noexcept {
  if (!verifier) {
    // If we're a prover, just use the existing input.
    return in;
  }

  // Otherwise, we'll use the fact that any of the temporaries are currently
  // zero and use those to store the result.
  // This is (in theory) guaranteed by BoringSSL, but checking is beneficial.
  assert(BN_is_zero(tmp_1) && BN_is_zero(tmp_2));
  if (!BN_mod_sub(tmp_1, tmp_2, in, p, ctx)) {
    return nullptr;
  }
  return tmp_1;
}

template <bool verifier, typename ET, typename OTType>
static bool compute_gamma_internal(BIGNUM *const out, OTType &ot,
                                   const BIGNUM *const lambda,
                                   const BIGNUM *const p, BN_CTX *const ctx,
                                   ET &entry) {
  constexpr auto mta_fn = MtAFunction<verifier>::func;
  return mta_fn(out, ot, lambda, p, ctx, entry);
}

bool ECtF::compute_gamma(BIGNUM *const out, SSL *const ssl,
                         const BIGNUM *const lambda, const BIGNUM *const p,
                         BN_CTX *const ctx, const bool verifier) {

  if (verifier) {
    // Verifier is a sender, so we'll build a sender entry.
    auto entry = MtABuild<true>::build(p, ctx);
    // Make the OT object.
    EmpWrapper<> wrapper(ssl);
    emp::IKNP<EmpWrapper<>> ot(&wrapper, 1);
    return compute_gamma_internal<true>(out, ot, lambda, p, ctx, entry);
  } else {
    // Prover is a receiver, so we'll build a receiver entry.
    auto entry = MtABuild<false>::build(p, ctx);
    // Make the OT object.
    EmpWrapper<> wrapper(ssl);
    emp::IKNP<EmpWrapper<>> ot(&wrapper, 1);
    return compute_gamma_internal<false>(out, ot, lambda, p, ctx, entry);
  }
}

template <bool verifier>
static bool ectf_internal(BIGNUM *const out, SSL *const ssl,
                          const bssl::Array<uint8_t> &x_secret,
                          const bssl::Array<uint8_t> &y_secret,
                          const uint16_t curve_id, size_t *size_of_p,
                          const bool track_bandwidth,
                          uint64_t *const bandwidth) noexcept {

  // Basic pre-conditions on our inputs.
  if (!out || !ssl || x_secret.size() == 0 || y_secret.size() == 0) {
    return false;
  }

  // See Util.hpp for more on this.
  static_assert(Util::only_nist_curves,
                "Error: this function only supports NIST curves");

  // We'll allocate a singular context for all operations,
  // as well as a curve object to make sampling easier.
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(curve_id)));
  if (!group || !bn_ctx) {
    return false;
  }

  // We'll use this modulus a lot, so to save typing we'll extract it out.
  BIGNUM *p = BN_CTX_get(bn_ctx.get());
  if (!p ||
      !EC_GROUP_get_curve_GFp(group.get(), p, nullptr, nullptr, bn_ctx.get())) {
    return false;
  }

  *size_of_p = BN_num_bytes(p);

  // We'll also use the context a lot, with the same justification as above.
  auto *const ctx = bn_ctx.get();

  // Now we're going to use ~~type magic~~ to produce a set of temporaries for
  // the MtA stuff. This is possible because both the verifier and the prover
  // have fixed roles in the MtA.
  // The template here automatically dispatches into the "right" builder, which
  // means that `entry` can be instantiated neatly.
  auto entry = MtABuild<verifier>::build(p, ctx);

  // We also want to do the MtA OT setup exactly once for better efficiency.
  // We'll do that here.
  // Note that we follow the convention of Alice as the sender, and Bob as the
  // receiver. This corresponds to the verifier as Alice and the prover as Bob.
  EmpWrapper<> wrapper(ssl);
  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);

  // We're also going to need lots of temporary variables for this method.
  // This is primarily for speed purposes: we deliberately retain memory,
  // because the individual allocations become quite expensive if we aren't
  // careful.
  // TODO: consider if this can be accelerated by using a stack here.
  auto tmp_1 = BN_CTX_get(ctx), tmp_2 = BN_CTX_get(ctx),
       tmp_3 = BN_CTX_get(ctx), tmp_4 = BN_CTX_get(ctx),
       tmp_5 = BN_CTX_get(ctx), x = BN_CTX_get(ctx), y = BN_CTX_get(ctx),
       rho = BN_CTX_get(ctx), delta = BN_CTX_get(ctx), eta = BN_CTX_get(ctx),
       lambda = BN_CTX_get(ctx), gamma = BN_CTX_get(ctx);

  // Make sure the allocations worked.
  if (!tmp_1 || !tmp_2 || !tmp_3 || !tmp_4 || !tmp_5 || !x || !y || !rho ||
      !delta || !eta || !gamma) {
    return false;
  }

  // We'll now take the serialised points and turn them into useful bignums.
  if (!serialised_to_bn(x, y, x_secret, y_secret)) {
    return false;
  }

  // In debug builds, we should make sure that the deserialisation worked.
  // This is a sensible definition of "worked" here.
  assert(BN_cmp(x, p) < 0);
  assert(BN_cmp(y, p) < 0);

  // As a mask, we need a random value called rho. This is essentially a
  // blinding factor for the MtA. We do this here.
  if (!BN_rand_range_ex(rho, 1, p)) {
    return false;
  }

  // Now we need to work out our inputs for the MtA. If we're the verifier, then
  // we use -x, rho as our inputs. By contrast, if we're
  // the prover then we need to use x, rho as our inputs. The inner routine
  // swaps these for us as necessary when actually calling the MtA, so we don't
  // need to do that: we just need to know if we have to negate `x`.
  const auto x_input = negate_if_verifier<verifier>(x, tmp_5, tmp_4, p, ctx);
  if (!x_input) {
    return false;
  }

  // Note: we use the variable name "delta" here, but this actually contains (a
  // masked version of) delta^{-1}.
  if (!share_inversion_impl<verifier>(delta, ot, x_input, rho, tmp_1, tmp_2,
                                      tmp_3, tmp_4, p, ctx, entry)) {
    return false;
  }

  // Now we've computed delta^{-1}, which is (a blinded) version of (x_p -
  // x_v)^(-1). We'll now compute our share of (y_p - y_v), which has remarkably
  // similiar constraints to computing (x_p - x_v).
  BN_zero(tmp_5);
  BN_zero(tmp_4);
  const auto y_input = negate_if_verifier<verifier>(y, tmp_5, tmp_4, p, ctx);

  // We also need to produce eta, which is a masked version of delta^(-1). This
  // essentially "undoes" our contribution of the masking.
  // Here eta = rho * delta^(-1).  //
  if (!BN_mod_mul(eta, rho, delta, p, ctx)) {
    return false;
  }

  // Now do the MtA.
  if (!compute_lambda_impl<verifier>(lambda, ot, y_input, eta, tmp_1, tmp_2,
                                     tmp_3, p, ctx, entry)) {
    return false;
  }

  // We've now got to run another MtA batch.
  // Note; this selection will be optimised out by the compiler. This is just
  // for consistency.
  if (!compute_gamma_internal<verifier>(gamma, ot, lambda, p, ctx, entry)) {
    return false;
  }

  if (track_bandwidth) {
    assert(bandwidth);
    *bandwidth = wrapper.counter;
  }

  // Now we'll compute the final value. The map for the temporaries is:
  // tmp_1 = 2 * gamma
  // tmp_2 = lambda^2
  // tmp_3 = 2 * gamma + lambda^2
  // out   = tmp_3 - x
  return BN_mod_add(tmp_1, gamma, gamma, p, ctx) &&
         BN_mod_sqr(tmp_2, lambda, p, ctx) &&
         BN_mod_add(tmp_3, tmp_1, tmp_2, p, ctx) &&
         BN_mod_sub(out, tmp_3, x, p, ctx);
}

bool ECtF::ectf_produce_bignum(BIGNUM *const out, SSL *const ssl,
                               bssl::Array<uint8_t> &x_secret,
                               bssl::Array<uint8_t> &y_secret,
                               const uint16_t curve_id, const bool verifier,
                               size_t *const size_of_p,
                               const bool track_bandwidth,
                               uint64_t *const bandwidth) noexcept {

  // N.B this is the only one checked here because this is the only
  // one that isn't checked in ectf_internal (in other places this isn't a user
  // accessible parameter).
  if (!size_of_p) {
    return false;
  }

  if (verifier) {
    return ectf_internal<true>(out, ssl, x_secret, y_secret, curve_id,
                               size_of_p, track_bandwidth, bandwidth);
  } else {
    return ectf_internal<false>(out, ssl, x_secret, y_secret, curve_id,
                                size_of_p, track_bandwidth, bandwidth);
  }
}

bool ECtF::ectf(bssl::Array<uint8_t> &out, SSL *const ssl,
                bssl::Array<uint8_t> &x_secret, bssl::Array<uint8_t> &y_secret,
                const uint16_t curve_id, const bool verifier,
                const bool track_bandwidth,
                uint64_t *const bandwidth) noexcept {
  BIGNUM b1;
  size_t size_of_p;
  BN_init(&b1);
  if (!ectf_produce_bignum(&b1, ssl, x_secret, y_secret, curve_id, verifier,
                           &size_of_p, track_bandwidth, bandwidth)) {
    BN_free(&b1);
    return false;
  }

  const auto worked =
      out.Init(size_of_p) && BN_bn2bin_padded(out.data(), out.size(), &b1);

  BN_free(&b1);
  return worked;
}
