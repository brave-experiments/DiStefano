#ifndef INCLUDED_MTA_HPP
#define INCLUDED_MTA_HPP

#include "EmpBlockSpan.hpp" // Needed for sane use of emp::block.
#include "openssl/base.h"   // Needed for BoringSSL things
#include "ssl/internal.h"   // Needed for BoringSSL things.
#include <emp-ot/emp-ot.h> // Needed for oblivious transfer, and a whole host of other things.

#include "PackArray.hpp"     // Needed for aligned arrays.
#include "ReceiverEntry.hpp" // Needed for neater packaging of receiver entries.
#include "SenderEntry.hpp"   // Needed for neater packaging of sender entries.
#include "../ssl/EmpWrapper.hpp" // Needed for EmpWrapper. 

/**
   MtA. This namespace implements the OT-based multiplication protocol from
[HKRT22]:

   Highly Efficieny OT-Based Multiplication Protocols,
   Haitner, Makriyannis, Ranellucci, Tsfadia,
   Eurocrypt 2022.

   The details of this protocol can be found at (paper:
https://eprint.iacr.org/2021/1373), (video:
https://www.youtube.com/watch?v=f9QyAk5f7uM).

   More precisely, this namespace implements Protocol 4.10 from the
aforementioned paper. We use the aformentioned protocol as it requires 2x less
bandwidth than other approaches, but it is almost as fast as Gilboa's
semi-honest protocol.

   The raison d'etre for this protocol is as follows.
   Suppose P1 and P2 each hold a secret point (label them as `a`
and `b` respectively) in ZZ_{q}. This protocol allows P1 and P2 to compute two
shares `alpha`, `beta` such that `alpha` + `beta` = `a * b`, where all
operations are modulo `q`. The key aspect of this is that the operation should
be done in a secretive fashion: neither P1 nor P2 should learn anything about
the other parties' input.

We use emp-ot for the oblivious transfer implementation. Precisely, this
namespace supports both the active IKNP extension and Ferret, both provided
by emp-ot. We stress that IKNP should be preferred, as the number of OTs is relatively
small. 

@remarks This namespace has some weird implementation quirks.

1. Oblivious transfers in this namespace are "padded". Essentially, emp
   regards all oblivious transfers as fixed width: a singular sizeof(emp::block)
message is chosen for each oblivious transfer. This is not suitable for our
workload, where we may regularly encounter bignums that require more than
sizeof(emp::block) to be serialised. We deal with this by padding the bignum
representations to a multiple of sizeof(emp::block) (by left padding with zeros)
and by duplicating the choice bits to select the entire representation.
Concretely, suppose that sizeof(emp::block) is 16-bytes (so 128-bits), that each
bignum is represented in 230 bits, and that `t` (our choice bits) contains
exactly 100 entries. We pad each bignum into 256 bits in size (since 256 = 2 *
128) and double the size of `t` to represent this change. In practice, we have
that t[i] = t[i+1] for all even `i`. Note that normal usage of emp treats each
block as a singular bit: this seems to imply that we would need to use many more
emp::blocks than are actually necessary in this case.

2. This namespace has to deal with aligned pointers for templating purposes.
   Essentially, C++ doesn't support name mangling based on
   the use of (say) GCC or Clang attributes. This would normally be fine,
   except there's a usage problem of this for this namespace, because
emp::blocks are explicitly aligned (the alignment itself depends on the
platform). This causes all sorts of errors, because the types used in emp
expect this alignment: however, when the templates are actually
instantiated, the types aren't necessarily aligned as expected. To get around
this, we use the EmpBlockOwningSpan type, which allows us to circumvent this
issue whilst still maintaining nice code. See EmpBlockSpan.hpp for more details
on this.

3. This namespace allows you to pass in pre-allocated arrays to save on repeated
   allocations. It's more than possible that you'll want to do many MtAs in a
single go, and the cost of constantly re-allocating this can be high. These
functions are referred to by the suffix "inplace".

4. This namespace does not implement the batched multiplication described in the
aforementioned paper. The reason for this is because the batched multiplication
requires one party to use only a single value (e.g P1 has one value `a`, whereas
P2 has `b1, b2,..., bm`). This is not useful for us.

5. This namespace makes use of a special array type, called PackArray. This is
to make it possible to cast between treating the array as a sequence of bytes
and a sequence of blocks. This is a feature that may be removed later, depending
on stability.
**/
namespace MtA {

/**
   k. This is the statistical security parameter used in the aforementioned
paper. This is primarily to pad out the number of oblivious transfers.

The paper claims that the security is around 2^(-k/4) in the ROM. We hence set
k to be 512, so that we can achieve 2^-128 bits of entropy.
**/
constexpr unsigned k = 512;

/**
   generate_random_vector. This function generates a random vector of integers
modulo `q` of length `vector_size`. This function returns true in case of
success and false otherwise.

   This function returns false if:
   1. Allocating the `out` array fails.
   2. Allocating any element of the `out` array fails.
   3. Setting any entry of the `out` array fails.

   This function does not throw.
   @snippet MtA.t.cpp MtAGenerateRandomVectorTests
   @param[out] out: the location to write the random vector.
   @param[in] vector_size: the number of elements in `out`.
   @param[in] q: the modulus.
   @param[in] ctx: the bignum ctx to use.
**/
bool generate_random_vector(bssl::Array<BIGNUM *> &out,
                            const uint64_t vector_size, const BIGNUM &q,
                            BN_CTX &ctx) noexcept;

/**
 generate_random_vector_inplace. This function generates a random vector of
integers modulo `q` of length `vector_size`. This function returns true in case
of success and false otherwise.

 This function returns false if:
 1. Setting any entry of the `out` array fails.

 This function does not throw.
 @snippet MtA.t.cpp MtAGenerateRandomVectorTests
 @param[out] out: the location to write the random vector. Note that `out` must
refer to a valid array.
 @param[in] q: the modulus.
**/
bool generate_random_vector_inplace(bssl::Array<BIGNUM *> &out,
                                    const BIGNUM &q) noexcept;

/**
   round_up_to_block. This function rounds `size` up to the nearest multiple of
   sizeof(emp::block). This uses a relatively fast algorithm that depends on
   sizeof(emp::block) being a power of 2.

   This function is primarily used for padding out blocks in this namespace. For
simplicity, most functions here expect their size parameters to be multiples of
sizeof(emp::block): these requirements are documented on a function-by-function
basis.

   This function does not throw.
   @snippet MtA.t.cpp MtARoundUp
   @param[in] size: the size to round up.
   @return `size` rounded up to the nearest multiple of sizeof(emp::block).
**/
constexpr unsigned round_up_to_block(const unsigned size) noexcept;

/**
   expand_t_to_ot_width. This function takes an array of choice booleans `t` and
expands each choice `t[i]` into `out`. This is because each OT will transfer
exactly sizeof(emp::block) bytes per message, but we require `max_bytes` to
represent each bignum. As a result, we expand `t` such that each t[i]
corresponds to E = max_bytes / sizeof(emp::block) many booleans. Mathematically,
you can view this as applying a function F : {0, 1} -> {0, 1} ^{E} , F(t[i]) =
{t[i], t[i], ... t[i]}.

   This function returns true in case of success and false otherwise. This
function will return false if:

   1. `max_bytes` == 0.
   2. `t.size()` == 0.
   3. allocating the `out` array fails.

   This function does not throw any exceptions.

   @snippet MtA.t.cpp MtAExpandToOtWidthTests

   @param[in] max_bytes: the maximum number of bytes needed to represent each
bignum. Note that `max_bytes % sizeof(emp::block) == 0` must be true, otherwise
this function's behaviour is undefined.
   @param[in] t: the array of choice bits to expand.
   @param[out] out: an uninitialised array where the choice bits are written.
   @return true in case of success, false otherwise.
**/
bool expand_t_to_ot_width(const unsigned max_bytes, const bssl::Array<bool> &t,
                          bssl::Array<bool> &out) noexcept;

/**
 expand_t_to_ot_width. This function takes an array of choice booleans `t` and
expands each choice `t[i]` into `out`. This is because each OT will transfer
exactly sizeof(emp::block) bytes per message, but we require `max_bytes` to
represent each bignum. As a result, we expand `t` such that each t[i]
corresponds to E = max_bytes / sizeof(emp::block) many booleans. Mathematically,
you can view this as applying a function F : {0, 1} -> {0, 1} ^{E} , F(t[i]) =
{t[i], t[i], ... t[i]}.

 This function returns true in case of success and false otherwise. This
function will return false if:

 1. `max_bytes` == 0.
 2. `t.size()` == 0.

 This function does not throw any exceptions.

 @snippet MtA.t.cpp MtAExpandToOtWidthTests

 @param[in] max_bytes: the maximum number of bytes needed to represent each
bignum. Note that `max_bytes % sizeof(emp::block) == 0` must be true, otherwise
this function's behaviour is undefined.
 @param[in] t: the array of choice bits to expand.
 @param[out] out: an initialised array where the choice bits are written. This
array must contain exactly ots_per_bignum * t.size() entries.
 @return true in case of success.
 @remarks this function differs from expand_t_to_ot_width because it requires
`out` to be pre-allocated.
**/
bool expand_t_to_ot_width_inplace(const size_t ots_per_bignum,
                                  const bssl::Array<bool> &t,
                                  bssl::Array<bool> &out) noexcept;

/**
   generate_t_and_v_inplace. This function generates the terms `t` and `v` as
per Protocol 4.10 of [HKRT21] in Step 1(a) and Step 2 respectively. Precisely,
this function generates `t` and `v` such that `t <- {-1, 1}` and `v` such that
<v, t> (mod q) == `b`. You can view this as computing a subset-sum for `b` where
we get to choose the values `t`.

This function differs from generate_t_and_v in that it uses pre-allocated arrays
`t` and `v`.

Note that the actual implementation of this function is different from the
paper's description. This is because we represent `t` as {0, 1}, whereas the
paper represents `t` as {-1, 1}. We do this for compatibility with emp. To
circumvent this problem, we implicitly map 0 to -1 where necessary: all of the
code in this namespace follows this convention.

This function returns true in case of success and false otherwise.
This function returns false if:

1. modular addition or subtraction fails.

This function does not throw.
@snippet MtA.t.cpp MtAGenerateTandVTests
@param[in] b: the value to use for the knapsack.
@param[in] q: the prime for the modular arithmetic.
@param[out] t: an initialised array to hold `t`.
@param[out] v: an initialised array to hold `v`.
@param[out] ctx: the bignum context to use.
@return true in case of success, false otherwise.
**/
bool generate_t_and_v_inplace(const BIGNUM &b, const BIGNUM &q,
                              bssl::Array<bool> &t, bssl::Array<BIGNUM *> &v,
                              BN_CTX &ctx) noexcept;

/**
   generate_t_and_v. This function generates the terms `t` and `v` as per
Protocol 4.10 of [HKRT21] in Step 1(a) and Step 2 respectively. Precisely, this
function generates `t` and `v` such that `t <- {-1, 1}` and `v` such that
<v, t> (mod q) == `b`. You can view this as computing a subset-sum for `b` where
we get to choose the values `t`.

Note that the actual implementation of this function is different from the
paper's description. This is because we represent `t` as {0, 1}, whereas the
paper represents `t` as {-1, 1}. We do this for compatibility with emp. To
circumvent this problem, we implicitly map 0 to -1 where necessary: all of the
code in this namespace follows this convention.

This function returns true in case of success and false otherwise.
This function returns false if:

1. generating the random vector `v` fails.
2. allocating bignums via `ctx` fails.
3. modular addition or subtraction fails.

This function does not throw.
@snippet MtA.t.cpp MtAGenerateTandVTests
@param[in] b: the value to use for the knapsack.
@param[in] q: the prime for the modular arithmetic.
@param[out] t: an uninitialised array to hold `t`.
@param[out] v: an uninitialised array to hold `v`.
@param[out] ctx: the bignum context to use.
@return true in case of success, false otherwise.
**/
bool generate_t_and_v(const BIGNUM &b, const BIGNUM &q, bssl::Array<bool> &t,
                      bssl::Array<BIGNUM *> &v, BN_CTX &ctx) noexcept;

/**
   convert_arr_to_block. This function accepts an array `arr` of uint8_t and
 copies them to a newly allocated EmpBlockOwningSpan. This function requires
 allocating a new block of memory because otherwise we would have undefined
 behaviour.

 This function returns an empty span if `arr`.size() == 0.
 This function does not throw.

 @snippet MtA.t.cpp MtAConversionTests.

   @param[in] arr: the array of bytes to convert. Note that arr.size() %
 sizeof(emp::block) == 0 must be true (i.e the size of arr must be a multiple of
 sizeof(emp::block)).
   @return an EmpBlockOwningSpan.
 **/
EmpBlockOwningSpan convert_arr_to_block(const PackArray &arr) noexcept;

/**
 convert_arr_to_block_inplace. This function accepts an array `arr` of uint8_t
and copies them to the `blocks` parameter. This function requires that `block`
holds exactly arr.size() / sizeof(emp::block) entries.

This function returns true on success and false otherwise. This function returns
false if `arr`.size() == 0.
This function does not throw.

@snippet MtA.t.cpp MtAConversionInplaceTests.
@param[in] arr: the array of bytes to convert. Note that arr.size() %
sizeof(emp::block) == 0 must be true (i.e the size of arr must be a multiple of
sizeof(emp::block)).
@param[out] blocks: the blocks to write the bytes to.
@return an EmpBlockOwningSpan.
**/
bool convert_arr_to_block_inplace(const PackArray &arr,
                                  EmpBlockOwningSpan &blocks) noexcept;

/**
   convert_block_to_arr. This function accepts a span of `blocks` uint8_t and
 copies them to a newly allocated `arr`. This function requires
 allocating a new block of memory because otherwise we would have undefined
 behaviour. This function returns true on success and false otherwise.
 This function returns false if:

 1. `blocks.size()` == 0.
 2. allocating `out` fails.
 This function does not throw.

 @snippet MtA.t.cpp MtAConversionTests.

   @param[in] block: the blocks to convert.
   @param[out] arr: the array to write the new blocks into.
   @return true in case of success, false otherwise.
**/
bool convert_block_to_arr(const EmpBlockOwningSpan &blocks,
                          PackArray &arr) noexcept;

/**
 convert_block_to_arr_inplace. This function accepts a span of `blocks` uint8_t
and copies them to `arr`. This function does not require require allocating new
memory: the caller _must_ ensure that arr.size() == sizeof(emp::block) *
blocks.size(). This function returns true on success and false otherwise. This
function returns false if:

1. `blocks.size()` == 0.

This function does not throw.

 @snippet MtA.t.cpp MtAConversionInplaceTests.
 @param[in] block: the blocks to convert.
 @param[out] arr: the array to write the new blocks into.
 @return true in case of success, false otherwise.
**/
bool convert_block_to_arr_inplace(const EmpBlockOwningSpan &blocks,
                                  PackArray &arr) noexcept;

/**
   produce_sender_pairs. This function produces the sender's oblivious transfer
entries for the protocol. Concretely, this computes `delta[i] - a`, `delta[i] +
a` for random values of `delta[i]`. The results of these computations are then
serialised and stored in `sub_pack` and `add_pack` respectively. This function
returns true in case of success and false otherwise.

This function returns false if:

1. delta.size() == 0.
2. any of `a`, `q`, or `ctx` are null.
3. allocating bignums via `ctx` fails.
4. allocating `add_pack` or `sub_pack` fails.

This function does not throw.

@snippet MtA.t.cpp MtAProduceSenderPairs
@param[in] delta: the array of `deltas` to use to produce the pairs.
@param[in] a: the bignum to use in the computations.
@param[in] size_of_each: the size of the serialised representation of each
`delta[i] +- a`.
@param[out] add_pack: an uninitialised array, used to store `delta[i] + a`.
@param[out] sub_pack: an uninitialised array, used to store `delta[i] - a`.
@param[in] q: the modulus for the operations.
@param[in] ctx: the bignum context for operations.
@return true in case of success, false otherwise.
**/
bool produce_sender_pairs(const bssl::Array<BIGNUM *> &delta,
                          const BIGNUM *const a, const unsigned size_of_each,
                          PackArray &add_pack, PackArray &sub_pack,
                          const BIGNUM *const q, BN_CTX *const ctx) noexcept;

/**
 produce_sender_pairs_inplace. This function produces the sender's oblivious
transfer entries for the protocol. Concretely, this computes `delta[i] - a`,
`delta[i] + a` for random values of `delta[i]`. The results of these
computations are then serialised and stored in `sub_pack` and `add_pack`
respectively. This function returns true in case of success and false otherwise.

This function returns false if:

1. delta.size() == 0.
2. any of `a`, `q`, or `ctx` are null.
3. allocating bignums via `ctx` fails.

Note that this function requires add_pack and sub_pack to be of the correct
size. This function does not throw.

@snippet MtA.t.cpp MtAProduceSenderPairs
@param[in] delta: the array of `deltas` to use to produce the pairs.
@param[in] a: the bignum to use in the computations.
@param[in] size_of_each: the size of the serialised representation of each
`delta[i] +- a`.
@param[out] add_pack: an initialised array, used to store `delta[i] + a`.
@param[out] sub_pack: an initialised array, used to store `delta[i] - a`.
@param[in] q: the modulus for the operations.
@param[in] ctx: the bignum context for operations.
@return true in case of success, false otherwise.
**/
bool produce_sender_pairs_inplace(const bssl::Array<BIGNUM *> &delta,
                                  const BIGNUM *const a,
                                  const unsigned size_of_each,
                                  PackArray &add_pack, PackArray &sub_pack,
                                  const BIGNUM *const q,
                                  BN_CTX *const ctx) noexcept;

/**
   deserialise_inner_product. This function computes the inner product (mod `q`)
 of `lhs` and `rhs`. More precisely, this function deserialises `lhs` into
 bignums (one element at a time) and computes the inner product between it and
 `rhs` (mod `q`). The result of the inner product is stored in `out`. This
 function returns true if successful and false otherwise.

   This function returns false if:
   1. `out`, `q` or `ctx` are null.
   2. `size_of_each` is 0.
   3. allocation via `ctx` fails.
   4. lhs.size() == 0.
   5. if rhs and lhs do not contain the same number of bignums.

   This function does not throw.
   @snippet MtA.t.cpp MtASerialiseDeserialisedPreReqs
   @snippet MtA.t.cpp MtASerialiseBignumTests
   @param[out] out: the location to store the inner product.
   @param[in] lhs: the representation of bignums to be serialised.
   @param[in] rhs: the bignums to be included in the inner product.
   @param[in] size_of_each: the number of bytes needed to represent each bignum.
   @param[in] q: the prime modulus for the operations.
   @param[in] ctx: the bignum context to use.
   @return true in case of success, false otherwise.
 **/
bool deserialise_inner_product(BIGNUM *const out, const PackArray &lhs,
                               const bssl::Array<BIGNUM *> &rhs,
                               const unsigned size_of_each,
                               const BIGNUM *const q, BN_CTX *const ctx);
/**
   deserialise_inner_product. This function computes the inner product (mod `q`)
 of `lhs` and `rhs`. More precisely, this function deserialises `lhs` into
 bignums (one element at a time) and computes the inner product between it and
 `rhs` (mod `q`). The result of the inner product is stored in `out`. This
 function returns true if successful and false otherwise.

   This function returns false if:
   1. `out`, `q` or `ctx` are null.
   2. `size_of_each` is 0.
   3. allocation via `ctx` fails.
   4. lhs.size() == 0.
   5. if rhs and lhs do not contain the same number of bignums.

   This function does not throw.
   @snippet MtA.t.cpp MtASerialiseDeserialisedPreReqs
   @snippet MtA.t.cpp MtASerialiseBignumTests
   @param[out] out: the location to store the inner product.
   @param[in] lhs: the representation of bignums to be serialised.
   @param[in] rhs: the bignums to be included in the inner product.
   @param[in] size_of_each: the number of bytes needed to represent each bignum.
   Note that size_of_each must be a multiple of sizeof(emp::block).
   @param[in] q: the prime modulus for the operations.
   @param[in] ctx: the bignum context to use.
   @return true in case of success, false otherwise.
 **/
bool deserialise_inner_product(BIGNUM *const out, const EmpBlockOwningSpan &lhs,
                               const bssl::Array<BIGNUM *> &rhs,
                               const unsigned size_of_each,
                               const BIGNUM *const q,
                               BN_CTX *const ctx) noexcept;

/**
     serialise_bignums_inplace. This function accepts an array of bignums (`in`)
and serialises them to `out`. `out` must be pre-allocated and contain exactly
`size_of_each` * `in`.size() bytes.

     This function returns true in case of success and false otherwise.
     Specifically, this function returns false if:

     1. in.size() == 0, or size_of_each == 0.
     2. any serialisations fail.

     This function does not throw.
     @snippet MtA.t.cpp MtASerialiseDeserialisedPreReqs
     @snippet MtA.t.cpp MtASerialiseBignumTests
     @param[out] out: an initialised array where the serialised bignums are
written. Must contain exactly size_of_each * in.size() entries.
     @param[in] in: the array of bignums to serialise.
     @param[in] size_of_each: the number of bytes used to represent each bignum.
Note that size_of_each must be a multiple of sizeof(emp::block).
     @return true in case of success, false otherwise.
**/
bool serialise_bignums_inplace(PackArray &out, const bssl::Array<BIGNUM *> &in,
                               const unsigned size_of_each) noexcept;

/**
     serialise_bignums. This function accepts an array of bignums (`in`) and
     serialises them to `out`. Each bignum in `out` is guaranteed to take up
     exactly `size_of_each` bytes.

     This function returns true in case of success and false otherwise.
     Specifically, this function returns false if:

     1. in.size() == 0, or size_of_each == 0.
     2. allocating `out` fails.
     3. any serialisations fail.

     This function does not throw.
     @snippet MtA.t.cpp MtASerialiseDeserialisedPreReqs
     @snippet MtA.t.cpp MtASerialiseBignumTests
     @param[out] out: an uninitialised array where the serialised bignums are
written.
     @param[in] in: the array of bignums to serialise.
     @param[in] size_of_each: the number of bytes used to represent each bignum.
Note that size_of_each must be a multiple of sizeof(emp::block).
     @return true in case of success, false otherwise.
**/
bool serialise_bignums(PackArray &out, const bssl::Array<BIGNUM *> &in,
                       const unsigned size_of_each) noexcept;
/**
   sender_ot. This function contains the logic for the `sender` in the oblivious
   transfer. Concretely, this function simply calls into emp-ot, supplying `b0`
 and `b1` as the messages for a choice bit of 0 or ` respectively. This function
 returns true in case of success and false otherwise.

   This function returns false if:
   
   1. b0.size() != b1.size().
   2. b0.size() == 0 or b1.size() == 0.

   This function does not throw.
   @snippet MtA.t.cpp MtAOtPreReqs
   @snippet MtA.t.cpp MtASenderOT
   @param[in] ot: the OT wrapper to use.
   @param[in] b0: the blocks to be chosen if the choice bit is 0.
   @param[in] b1: the blocks to be chosen if the choice bit is 1.
   @return true in case of success, false otherwise.
 **/
bool sender_ot(emp::IKNP<EmpWrapper<>>& ot, const EmpBlockOwningSpan &b0,
               const EmpBlockOwningSpan &b1) noexcept;

/**
   sender_ot. This function contains the logic for the `sender` in the oblivious
   transfer. Concretely, this function simply calls into emp-ot, supplying `b0`
 and `b1` as the messages for a choice bit of 0 or ` respectively. This function
 returns true in case of success and false otherwise.

   This function returns false if:
   
   1. b0.size() != b1.size().
   2. b0.size() == 0 or b1.size() == 0.

   This function does not throw.
   @snippet MtA.t.cpp MtAOtPreReqs
   @snippet MtA.t.cpp MtASenderOT
   @param[in] ot: the OT wrapper to use.
   @param[in] b0: the blocks to be chosen if the choice bit is 0.
   @param[in] b1: the blocks to be chosen if the choice bit is 1.
   @return true in case of success, false otherwise.
 **/
bool sender_ot(emp::FerretCOT<EmpWrapper<>>& ot, const EmpBlockOwningSpan &b0,
               const EmpBlockOwningSpan &b1) noexcept;

/**
   receiver_ot. This function contains the logic for the `receiver` in the
   oblivious transfer. Concretely, this function simply calls into emp-ot,
   supplying `r` as the location for the received messages and `choices` as the
   choice bits. This function returns true in case of success and false
otherwise.

   This function returns false if:
   1. r.size() != choices.size().
   2. r.size() == 0 or choices.size() == 0.

   This function does not throw.
   @snippet MtA.t.cpp MtAOtPreReqs
   @snippet MtA.t.cpp MtASenderOT
   @param[in] ot: the OT wrapper to use.
   @param[in] b0: the blocks to be chosen if the choice bit is 0.
   @param[in] b1: the blocks to be chosen if the choice bit is 1.
   @return true in case of success, false otherwise.
**/
bool receiver_ot(emp::IKNP<EmpWrapper<>>& ot, EmpBlockOwningSpan &r,
                 const bssl::Array<bool> &choices) noexcept;

/**
   receiver_ot. This function contains the logic for the `receiver` in the
   oblivious transfer. Concretely, this function simply calls into emp-ot,
   supplying `r` as the location for the received messages and `choices` as the
   choice bits. This function returns true in case of success and false
otherwise.

   This function returns false if:
   1. r.size() != choices.size().
   2. r.size() == 0 or choices.size() == 0.

   This function does not throw.
   @snippet MtA.t.cpp MtAOtPreReqs
   @snippet MtA.t.cpp MtASenderOT
   @param[in] ot: the OT wrapper to use.
   @param[in] b0: the blocks to be chosen if the choice bit is 0.
   @param[in] b1: the blocks to be chosen if the choice bit is 1.
   @return true in case of success, false otherwise.
**/
bool receiver_ot(emp::FerretCOT<EmpWrapper<>>& ot, EmpBlockOwningSpan &r,
                 const bssl::Array<bool> &choices) noexcept;


/**
   receiver_ot. This function contains the logic for the `receiver` in the
   oblivious transfer. Concretely, this function simply calls into emp-ot,
   supplying `r` as the location for the received messages and `choices` as the
   choice bits. This function returns true in case of success and false
otherwise.

   This function returns false if:
   1. ssl is null.
   2. r.size() != choices.size().
   3. r.size() == 0 or choices.size() == 0.

   This function does not throw.
   @snippet MtA.t.cpp MtAOtPreReqs
   @snippet MtA.t.cpp MtASenderOT
   @param[in] ssl: the SSL connection to use.
   @param[in] b0: the blocks to be chosen if the choice bit is 0.
   @param[in] b1: the blocks to be chosen if the choice bit is 1.
   @return true in case of success, false otherwise.
**/
bool receiver_ot(SSL *  const ssl, EmpBlockOwningSpan &r,
                 const bssl::Array<bool> &choices) noexcept;

/**
   sender_ot. This function contains the logic for the `sender` in the oblivious
   transfer. Concretely, this function simply calls into emp-ot, supplying `b0`
 and `b1` as the messages for a choice bit of 0 or ` respectively. This function
 returns true in case of success and false otherwise.

   This function returns false if:

   1. ssl is null.
   2. b0.size() != b1.size().
   3. b0.size() == 0 or b1.size() == 0.

   This function does not throw.
   @snippet MtA.t.cpp MtAOtPreReqs
   @snippet MtA.t.cpp MtASenderOT
   @param[in] ssl: the SSL connection to use. 
   @param[in] b0: the blocks to be chosen if the choice bit is 0.
   @param[in] b1: the blocks to be chosen if the choice bit is 1.
   @return true in case of success, false otherwise.
 **/
bool sender_ot(SSL * const ssl, const EmpBlockOwningSpan &b0,
               const EmpBlockOwningSpan &b1) noexcept;
  
/**
     play_sender. This function runs the MtA protocol from the perspective of
the `sender`. Concretely, the `sender` inputs `a`, an element mod `q`, and
receives a share `alpha`. The `receiver` inputs `b` (another element mod `q`)
and receives `beta`, such that `alpha` + `beta` = `a` * `b` (mod `q`). The
`alpha` value here is written to `out`.

     This function returns true in case of success and false otherwise.
     This function returns false if:
     1. any of the parameters are null.
     1. generating the random vector `delta` fails.
     2. producing the sender's pairs fails.
     3. converting the sender's pairs to blocks fails.
     4. the OT fails.
     5. reading the messages from the `receiver` fails.
     6. deserialising the `receiver's` messages fails.
     7. any modular reduction fails.

     This function does not throw.
     @snippet MtA.t.cp MtADoOT
     @snippet MtA.t.cpp MtAFullOT

     @param[out] out: the location to store the `alpha` share.
     @param[in] ot: the OT wrapper to use.
     @param[in] a: the secret value to use.
     @param[in] q: the modulus of the group to use.
     @param[in] ctx: the bignum ctx to use.
     @return true in case of success, false otherwise.
**/
bool play_sender(BIGNUM *const out, emp::IKNP<EmpWrapper<>>& ot, const BIGNUM *const a,
                 const BIGNUM *const q, BN_CTX *const ctx) noexcept;

  /**
     play_sender. This function runs the MtA protocol from the perspective of
the `sender`. Concretely, the `sender` inputs `a`, an element mod `q`, and
receives a share `alpha`. The `receiver` inputs `b` (another element mod `q`)
and receives `beta`, such that `alpha` + `beta` = `a` * `b` (mod `q`). The
`alpha` value here is written to `out`.

     This function returns true in case of success and false otherwise.
     This function returns false if:
     1. any of the parameters are null.
     1. generating the random vector `delta` fails.
     2. producing the sender's pairs fails.
     3. converting the sender's pairs to blocks fails.
     4. the OT fails.
     5. reading the messages from the `receiver` fails.
     6. deserialising the `receiver's` messages fails.
     7. any modular reduction fails.

     This function does not throw.
     @snippet MtA.t.cp MtADoOT
     @snippet MtA.t.cpp MtAFullOT

     @param[out] out: the location to store the `alpha` share.
     @param[in] ot: the OT wrapper to use.
     @param[in] a: the secret value to use.
     @param[in] q: the modulus of the group to use.
     @param[in] ctx: the bignum ctx to use.
     @return true in case of success, false otherwise.
**/
bool play_sender(BIGNUM *const out, emp::FerretCOT<EmpWrapper<>>& ot, const BIGNUM *const a,
                 const BIGNUM *const q, BN_CTX *const ctx) noexcept;

/**
   play_sender_inplace_iknp. This function runs the MtA protocol from the perspective
   of the `sender`. Concretely, the `receiver` inputs `b` (an element mod `q`)
and receives a share `beta`. The `sender` inputs `a` (another element mod `q`)
and receives `alpha` such that `alpha` + `beta` = `a` * `b` (mod `q`). The
 `beta` value here is written to `out`.

 This function returns true in case of success and false otherwise.
 This function returns false if:

 1. any of the parameters are null.
 2. generating `t` or `v` fails.
 3. generating `sigma` fails.
 3. serialising `v` or `sigma` fails.
 4. the OT fails.
 5. writing `v` or `sigma` fails.
 6. allocating from `ctx` fails.
 7. the inner product fails.

 This function does not throw. Note that the parameters passed in here should be
 initialised using initialise_entries_for_sender.

 @param[out] out: the location to write the produced share.
 @param[in] ot: the ot wrapper to use.
 @param[in] a: the secret value to use.
 @param[in] q: the modulus.
 @param[out] se: the sender entries to use.
 @return true if successful, false otherwise.
**/
bool play_sender_inplace_iknp(BIGNUM *const out, emp::IKNP<EmpWrapper<>>& ot,
                         const BIGNUM *const a, const BIGNUM *const q,
                         BN_CTX *const ctx, SenderEntry &se) noexcept;
  
/**
   play_sender_inplace. This function runs the MtA protocol from the perspective
   of the `sender`. Concretely, the `receiver` inputs `b` (an element mod `q`)
and receives a share `beta`. The `sender` inputs `a` (another element mod `q`)
and receives `alpha` such that `alpha` + `beta` = `a` * `b` (mod `q`). The
 `beta` value here is written to `out`.

 This function returns true in case of success and false otherwise.
 This function returns false if:

 1. any of the parameters are null.
 2. generating `t` or `v` fails.
 3. generating `sigma` fails.
 3. serialising `v` or `sigma` fails.
 4. the OT fails.
 5. writing `v` or `sigma` fails.
 6. allocating from `ctx` fails.
 7. the inner product fails.

 This function does not throw. Note that the parameters passed in here should be
 initialised using initialise_entries_for_sender.

 @param[out] out: the location to write the produced share.
 @param[in] ot: the ot wrapper to use.
 @param[in] a: the secret value to use.
 @param[in] q: the modulus.
 @param[out] se: the sender entries to use.
 @return true if successful, false otherwise.
**/
bool play_sender_inplace(BIGNUM *const out, emp::IKNP<EmpWrapper<>>& ot,
                         const BIGNUM *const a, const BIGNUM *const q,
                         BN_CTX *const ctx, SenderEntry &se) noexcept;

/**
   play_sender_inplace. This function runs the MtA protocol from the perspective
   of the `sender`. Concretely, the `receiver` inputs `b` (an element mod `q`)
and receives a share `beta`. The `sender` inputs `a` (another element mod `q`)
and receives `alpha` such that `alpha` + `beta` = `a` * `b` (mod `q`). The
 `beta` value here is written to `out`.

 This function returns true in case of success and false otherwise.
 This function returns false if:

 1. any of the parameters are null.
 2. generating `t` or `v` fails.
 3. generating `sigma` fails.
 3. serialising `v` or `sigma` fails.
 4. the OT fails.
 5. writing `v` or `sigma` fails.
 6. allocating from `ctx` fails.
 7. the inner product fails.

 This function does not throw. Note that the parameters passed in here should be
 initialised using initialise_entries_for_sender.

 @param[out] out: the location to write the produced share.
 @param[in] ot: the ot wrapper to use.
 @param[in] a: the secret value to use.
 @param[in] q: the modulus.
 @param[out] se: the sender entries to use.
 @return true if successful, false otherwise.
**/
bool play_sender_inplace(BIGNUM *const out, emp::FerretCOT<EmpWrapper<>>& ot,
                         const BIGNUM *const a, const BIGNUM *const q,
                         BN_CTX *const ctx, SenderEntry &se) noexcept;

/**
 play_receiver_inplace_iknp. This function runs the MtA protocol from the perspective of
the `receiver`. Concretely, the `receiver` inputs `b` (an element mod `q`) and
 receives a share `beta`. The `sender` inputs `a` (another element mod `q`)
and receives `alpha` such that `alpha` + `beta` = `a` * `b` (mod `q`). The
 `beta` value here is written to `out`.

 This function returns true in case of success and false otherwise.
 This function returns false if:
 1. any of the parameters are null.
 2. generating `t` or `v` fails.
 3. generating `sigma` fails.
 4. serialising `v` or `sigma` fails.
 5. the OT fails.
 6. writing `v` or `sigma` fails.
 7. allocating from `ctx` fails.
 8. the inner product fails.

 This function does not throw. Note that this function expects the parameters to
be initialised as if they were passed to initialise_entries_for_receiver.

 @snippet MtA.t.cp MtADoOT
 @snippet MtA.t.cpp MtAFullOT
 @param[out] out: the location to write `beta`.
 @param[in] ot: the ot wrapper to use.
 @param[in] b: the secret value to use.
 @param[in] q: the modulus of the group to use.
 @param[in] ctx: the bignum ctx to use.
 @param[in] entry: the receiver entry to use.
 @return true in case of success, false otherwise.
**/
bool play_receiver_inplace_iknp(BIGNUM *const out, emp::IKNP<EmpWrapper<>>& ot,
                           const BIGNUM *const b, const BIGNUM *const q,
                           BN_CTX *const ctx, ReceiverEntry &entry) noexcept;
  
/**
 play_receiver_inplace. This function runs the MtA protocol from the perspective of
the `receiver`. Concretely, the `receiver` inputs `b` (an element mod `q`) and
 receives a share `beta`. The `sender` inputs `a` (another element mod `q`)
and receives `alpha` such that `alpha` + `beta` = `a` * `b` (mod `q`). The
 `beta` value here is written to `out`.

 This function returns true in case of success and false otherwise.
 This function returns false if:
 1. any of the parameters are null.
 2. generating `t` or `v` fails.
 3. generating `sigma` fails.
 4. serialising `v` or `sigma` fails.
 5. the OT fails.
 6. writing `v` or `sigma` fails.
 7. allocating from `ctx` fails.
 8. the inner product fails.

 This function does not throw. Note that this function expects the parameters to
be initialised as if they were passed to initialise_entries_for_receiver.

 @snippet MtA.t.cp MtADoOT
 @snippet MtA.t.cpp MtAFullOT
 @param[out] out: the location to write `beta`.
 @param[in] ot: the ot wrapper to use.
 @param[in] b: the secret value to use.
 @param[in] q: the modulus of the group to use.
 @param[in] ctx: the bignum ctx to use.
 @param[in] entry: the receiver entry to use.
 @return true in case of success, false otherwise.
**/
bool play_receiver_inplace(BIGNUM *const out, emp::IKNP<EmpWrapper<>>& ot,
                           const BIGNUM *const b, const BIGNUM *const q,
                           BN_CTX *const ctx, ReceiverEntry &entry) noexcept;

/**
 play_receiver. This function runs the MtA protocol from the perspective of
the `receiver`. Concretely, the `receiver` inputs `b` (an element mod `q`) and
 receives a share `beta`. The `sender` inputs `a` (another element mod `q`)
and receives `alpha` such that `alpha` + `beta` = `a` * `b` (mod `q`). The
 `beta` value here is written to `out`.

 This function returns true in case of success and false otherwise.
 This function returns false if:
 1. any of the parameters are null.
 2. generating `t` or `v` fails.
 3. generating `sigma` fails.
 4. serialising `v` or `sigma` fails.
 5. the OT fails.
 6. writing `v` or `sigma` fails.
 7. allocating from `ctx` fails.
 8. the inner product fails.

 This function does not throw. Note that this function expects the parameters to
be initialised as if they were passed to initialise_entries_for_receiver.

 @snippet MtA.t.cp MtADoOT
 @snippet MtA.t.cpp MtAFullOT
 @param[out] out: the location to write `beta`.
 @param[in] ot: the ot wrapper to use.
 @param[in] b: the secret value to use.
 @param[in] q: the modulus of the group to use.
 @param[in] ctx: the bignum ctx to use.
 @param[in] entry: the receiver entry to use.
 @return true in case of success, false otherwise.
**/
bool play_receiver_inplace(BIGNUM *const out, emp::FerretCOT<EmpWrapper<>>& ot,
                           const BIGNUM *const b, const BIGNUM *const q,
                           BN_CTX *const ctx, ReceiverEntry &entry) noexcept;

/**
   play_receiver. This function runs the MtA protocol from the perspective of
the `receiver`. Concretely, the `receiver` inputs `b` (an element mod `q`) and
   receives a share `beta`. The `sender` inputs `a` (another element mod `q`)
and receives `alpha` such that `alpha` + `beta` = `a` * `b` (mod `q`). The
   `beta` value here is written to `out`.

   This function returns true in case of success and false otherwise.
   This function returns false if:
   1. any of the parameters are null.
   2. generating `t` or `v` fails.
   3. generating `sigma` fails.
   4. serialising `v` or `sigma` fails.
   5. the OT fails.
   6. writing `v` or `sigma` fails.
   7. allocating from `ctx` fails.
   8. the inner product fails.

   This function does not throw.
   @snippet MtA.t.cp MtADoOT
   @snippet MtA.t.cpp MtAFullOT
   @param[out] out: the location to write `beta`.
   @param[in] ot: the OT wrapper to use. 
   @param[in] b: the secret value to use.
   @param[in] q: the modulus of the group to use.
   @param[in] ctx: the bignum ctx to use.
   @return true in case of success, false otherwise.
**/
bool play_receiver(BIGNUM *const out, emp::IKNP<EmpWrapper<>>& ot, const BIGNUM *const b,
                   const BIGNUM *const q, BN_CTX *const ctx) noexcept;

/**
   play_receiver. This function runs the MtA protocol from the perspective of
the `receiver`. Concretely, the `receiver` inputs `b` (an element mod `q`) and
   receives a share `beta`. The `sender` inputs `a` (another element mod `q`)
and receives `alpha` such that `alpha` + `beta` = `a` * `b` (mod `q`). The
   `beta` value here is written to `out`.

   This function returns true in case of success and false otherwise.
   This function returns false if:
   1. any of the parameters are null.
   2. generating `t` or `v` fails.
   3. generating `sigma` fails.
   4. serialising `v` or `sigma` fails.
   5. the OT fails.
   6. writing `v` or `sigma` fails.
   7. allocating from `ctx` fails.
   8. the inner product fails.

   This function does not throw.
   @snippet MtA.t.cp MtADoOT
   @snippet MtA.t.cpp MtAFullOT
   @param[out] out: the location to write `beta`.
   @param[in] ot: the OT wrapper to use. 
   @param[in] b: the secret value to use.
   @param[in] q: the modulus of the group to use.
   @param[in] ctx: the bignum ctx to use.
   @return true in case of success, false otherwise.
**/
bool play_receiver(BIGNUM *const out, emp::FerretCOT<EmpWrapper<>>& ot, const BIGNUM *const b,
                   const BIGNUM *const q, BN_CTX *const ctx) noexcept;

/**
   initialise_entries_for_receiver. This function initialises all passed in
   parameters for use in the play_receiver_inplace function. This function
   is primarily intended to be called by callers from outside of this
namespace, so that they may use play_receiver.

   This function returns true in case of success and false otherwise. This
function does not throw.

   @snippet MtA.t.cpp MtAIEFR

   @param[in] q: the modulus to use.
   @param[out] entries: the entry object to initialise.
   @param[in] ctx: the bignum context.
   @return true in case of success, false otherwise.
**/
bool initialise_entries_for_receiver(const BIGNUM *const q,
                                     ReceiverEntry &entry,
                                     BN_CTX *const ctx) noexcept;

/**
     initialise_entries_for_sender. This function initialises all passed in
     parameters for use in the play_sender_inplace function. This function is
primarily intended to be called by callers from outside of this namespace, so
that they may use play_sender.

     This function returns true in case of success and false otherwise. This
function does not throw.

     @snippet MtA.t.cpp MtAIEFS

     @param[in]  n: the number of OTs that will be used.
     @param[in]  q: the modulus used in computation.
     @param[in] ctx: the bignum context to use.
     @param[out] se: the sender entries to initialise.
     @return true if successful, false otherwise.
**/
bool initialise_entries_for_sender(const unsigned n, const BIGNUM *const q,
                                   SenderEntry &se, BN_CTX *const ctx) noexcept;

/**
   initialise_entries_for_sender. This function initialises all passed in
   parameters for use in the play_sender_inplace function. This function is
primarily intended to be called by callers from outside of this namespace, so
that they may use play_sender.

   This function returns true in case of success and false otherwise. This
function does not throw.

   @snippet MtA.t.cpp MtAIEFS

   @param[in]  q: the modulus used in computation.
   @param[in] ctx: the bignum context to use.
   @param[out] se: the sender entries to initialise.
   @return true if successful, false otherwise.
**/
bool initialise_entries_for_sender(const BIGNUM *const q, SenderEntry &se,
                                   BN_CTX *const ctx) noexcept;

/**
     get_role. This function returns emp::ALICE for verifier == true and emp::BOB otherwise.
     This corresponds to denoting that the verifier plays the role of the sender in our MtA and
     the prover plays the role of the receiver. This function does not throw.
     @param[in] verifier: true if the caller is a verifier, false otherwise.
     @return emp::ALICE if verifier == true, emp::BOB otherwise.
**/     
constexpr int get_role(const bool verifier) noexcept;
} // namespace MtA

// Inline definitions live here.
#include "MtA.inl"

#endif
