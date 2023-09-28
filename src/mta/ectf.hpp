#ifndef INCLUDED_ECTF_HPP
#define INCLUDED_ECTF_HPP

#include "MtA.hpp"
#include "openssl/base.h" // Needed for BoringSSL things
#include "ssl/internal.h" // Needed for BoringSSL things.

/**
   ECtF. This namespace implements the ECtF protocol (e.g protocol 7) from:

   DECO: Liberating Web Data Using Decentralized Oracles for TLS (the extended
version)

   Fan Zhang, Deepak Maram, Harjasleen Malvai,
   Steven Goldfeder, Ari Juels,
   Originally published at CCS 2020.

   This protocol takes as inputs two elliptic curve points P1 = (x1, y1), P2 =
(x2, y2) over a shared curve and outputs s1, s2 such that s1 + s2 = `x`, where
(x, y) =  P1 + P2. In other words, this protocol decomposes secret shares over
the elliptic curve into secret shares over the base field. This is primarily
useful for doing work with the TLS PRF.

Implementation-wise, this namespace makes heavy use of the MtA implementation in
MtA.hpp. This in turn makes heavy use of the oblivious transfer features
provided by emp-ot. We also make use of the MtA optimisations provided by using
inplace storage, which in turn allows for slightly faster runtimes.

@remarks There's two unusual aspects of this namespace:
1. This namespace breaks down the various functions
presented in the original algorithm into named functionality. This matches the
earlier descriptions in the paper, but it also allows for a more logical and
coherent understanding of what the algorithm is doing. The main entry point for
any caller should be the ectf function.

2. This namespace takes advantage of the inplace storage for the MtA functions
wherever possible. In practice, this means that there's a slight speed-up
compared to naively calling the non-inplace functions. This means that the
implementation file has many templates and static functions in it.
**/
namespace ECtF {

/**
   share_inversion. This function models a protocol between two parties
 (P and V). Given as input a two secrets `x`, `y` this protocol computes [x *
 y]^-1 jointly without leaking any additional information. This function returns
 true in case of success and false otherwise.

 This function returns false if:
 1. Any of the arguments are null.
 2. allocating via `ctx` fails.
 3. doing the OT fails.
 4. any modular reductions fail.
 5. using `ssl` fails.

 This function does not throw.
 @snippet ectf.t.cpp ECtFShareInversion

 @param[in] out: the location to write the produced inverse.
 @param[in] ot: the OT wrapper to use.
 @param[in] x: the `x` share.
 @param[in] rho: the `rho` value, used for randomness.
 @param[in] p: the modulus of the group.
 @param[in] ctx: the context to use for bignum arithmetic.
 @param[in] verifier: true if the caller is a verifier, false otherwise.
**/
bool share_inversion(BIGNUM *out, emp::IKNP<EmpWrapper<>>& ot, const BIGNUM *const x,
                     const BIGNUM *const rho, const BIGNUM *const p,
                     BN_CTX *const ctx, const bool verifier) noexcept;

/**
   share_inversion. This function models a protocol between two parties
 (P and V). Given as input a two secrets `x`, `y` this protocol computes [x *
 y]^-1 jointly without leaking any additional information. This function returns
 true in case of success and false otherwise.

 This function returns false if:
 1. Any of the arguments are null.
 2. allocating via `ctx` fails.
 3. doing the OT fails.
 4. any modular reductions fail.
 5. using `ssl` fails.

 This function does not throw.
 @snippet ectf.t.cpp ECtFShareInversion

 @param[in] out: the location to write the produced inverse.
 @param[in] ssl: the connection to use.
 @param[in] x: the `x` share.
 @param[in] rho: the `rho` value, used for randomness.
 @param[in] p: the modulus of the group.
 @param[in] ctx: the context to use for bignum arithmetic.
 @param[in] verifier: true if the caller is a verifier, false otherwise.
**/
bool share_inversion(BIGNUM *out, SSL * const ssl, const BIGNUM *const x,
                     const BIGNUM *const rho, const BIGNUM *const p,
                     BN_CTX *const ctx, const bool verifier) noexcept;

/**
   compute_lambda. This function computes `lambda` for each party, as described
   in the ectf protocol. This is used for computing shares of the gradient of
the curve for the elliptic curve point addition.
   @param[out] out: the location to write the produced share.
   @param[in] ssl: the ssl connection to use.
   @param[in] rho: the blinding factor to use.
   @param[in] p: the characteristic of the base field.
   @param[in] ctx: the bignum context to use.
   @param[in] verifier: true if the caller is a verifier, false otherwise.
**/
bool compute_lambda(BIGNUM *const out, SSL *const ssl, const BIGNUM *const x,
                    const BIGNUM *const rho, const BIGNUM *const p,
                    BN_CTX *const ctx, const bool verifier) noexcept;

/**
   ectf_produce_bignum. This function runs the ECtF protoocl
   described in the namespace-level documentation to produce
   additive shares of the `x` co-ordinate of the combined point.

   In particular, this function operates across two parties, P1 and P2.
   Suppose P1 holds Pp = (x_secret_1, y_secret_1) and P2 holds Pv = (x_secret_2,
y_secret_2). For each party this function writes a value `x_{i}` (i == 1 or i ==
2) to `out`, such that `x_{1} + x_{2}` == x, where (x,y) = Pp + Pv over the
underlying elliptic curve (as identified by `curve_id`).

   This function returns true if successful or false otherwise. Specifically,
this function returns false if:

 1. Any of the pointer parameters are null.
 2. x_secret.size() or y_secret.size() == 0.
 3. any allocations fail.
 4. negating any inputs fail (if appropriate).
 5. any modular operations fail.

 This function does not throw.
 @snippet ectf.t.cpp ECtFectfTests
 @param[out] out: the location to write the share.
 @param[in] ssl: the ssl connection to use.
 @param[in] x_secret: the x co-ordinate of the point, serialised.
 @param[in] y_secret: the y co-ordinate of the point, serialised.
 @param[in] curve_id: the ID of the underlying curve.
 @param[in] verifier: true if this player is a verifier, false otherwise.
 @param[out] size_of_p: the size of the characteristic of the underlying field
in bytes.
 @param[in] track_bandwidth: true if this function should record the used bandwidth for this
 function, false otherwise.
 @param[in] bandwidth: the location to store the bandwidth. Can be nullptr if
 track_bandwidth is false.

**/
bool ectf_produce_bignum(BIGNUM *const out, SSL *const ssl,
                         bssl::Array<uint8_t> &x_secret,
                         bssl::Array<uint8_t> &y_secret,
                         const uint16_t curve_id, const bool verifier,
                         size_t *const size_of_p, const bool track_bandwidth = false,
                         uint64_t* const bandwidth = nullptr) noexcept;

/**
   compute_gamma. This function computes the `gamma` term from the ECtF protocol
   as mentioned above. Specifically, this protocol computes additive shares
`gamma_1, gamma_2` such that `gamma_1` + `gamma_2` == `lambda_1` * `lambda_2` as
produced by the compute_lambda function.

   This function returns true on success and false on failure. This function
returns false if the underlying MtA fails.

   This function does not throw.

   @snippet ectf.t.cpp ECtFDryRun
   @param[out] out: the location to write the share.
   @param[in] ssl: the ssl connection to use.
   @param[in] p: the characteristic of the underlying field.
   @param[in] ctx: the bignum context to use for allocations.
   @param[in] verifier: true if the player is a verifier, false otherwise.
**/
bool compute_gamma(BIGNUM *const out, SSL *const ssl,
                   const BIGNUM *const lambda, const BIGNUM *const p,
                   BN_CTX *const ctx, const bool verifier);

/**
   ectf. This function runs the ECtF protoocl
   described in the namespace-level documentation to produce
   additive shares of the `x` co-ordinate of the combined point.
   The difference between this function and ectf_produce_bignum is that this
   function serialises the produced point into the `out` argument.

   In particular, this function operates across two parties, P1 and P2.
   Suppose P1 holds Pp = (x_secret_1, y_secret_1) and P2 holds Pv = (x_secret_2,
y_secret_2). For each party this function writes a value `x_{i}` (i == 1 or i ==
2) to `out`, such that `x_{1} + x_{2}` == x, where (x,y) = Pp + Pv over the
underlying elliptic curve (as identified by `curve_id`).

   This function returns true if successful or false otherwise. Specifically,
this function returns false if:

 1. Any of the pointer parameters are null.
 2. x_secret.size() or y_secret.size() == 0.
 3. any allocations fail.
 4. negating any inputs fail (if appropriate).
 5. any modular operations fail.

 This function does not throw.
 @snippet ectf.t.cpp ECtFectfTests
 @param[out] out: the location to write the serialised share.
 @param[in] ssl: the ssl connection to use.
 @param[in] x_secret: the x co-ordinate of the point, serialised.
 @param[in] y_secret: the y co-ordinate of the point, serialised.
 @param[in] curve_id: the ID of the underlying curve.
 @param[in] verifier: true if this player is a verifier, false otherwise.
 @param[in] track_bandwidth: true if this function should record the used bandwidth for this
 function, false otherwise.
 @param[in] bandwidth: the location to store the bandwidth. Can be nullptr if
 track_bandwidth is false.
**/
bool ectf(bssl::Array<uint8_t> &out, SSL *const ssl,
          bssl::Array<uint8_t> &x_secret, bssl::Array<uint8_t> &y_secret,
          const uint16_t curve_id, const bool verifier, const bool track_bandwidth = false,
          uint64_t* const bandwidth = nullptr) noexcept;

} // namespace ECtF
#endif
