#ifndef INCLUDED_F2128MTA_HPP
#define INCLUDED_F2128MTA_HPP

#include "../emp-ot/emp-ot/emp-ot.h"
#include "../ssl/EmpWrapper.hpp"
#include "../ssl/Util.hpp"
#include "EmpBlockSpan.hpp"
#include <array>
#include <cstdint>

/**
   F2128_MTA. This namespace implements two multiplicative-to-additive secret
   sharing schemes. In particular, we implement the unbatched scheme from:

   Secure Two-party Threshold ECDSA from ECDSA Assumptions,
   Jack Doerner and Yashvanth Kondi and Eysa Lee and abhi shelat,
   S&P 2018,

   and the batched scheme from

   Threshold ECDSA from ECDSA Assumptions: The Multiparty Case
   Jack Doerner and Yashvanth Kondi and Eysa Lee and abhi shelat,
   S&P 2019.

   Note that this namespace is deliberately separate from the other MtA code
because the other MtA code is not secure over fields of characteristic 2.

   This particular namespace is restricted to the use of operations
   over GF(2^128): we gain tremendous speedups by based on treating
   operations over GF(2^128) as native operations. This, of course,
   restricts the generality of our implementation somewhat.

   There are some remarks to bear in mind about this namespace. The
   namespace itself deals with emp's OT API directly. Because
   emp OT's API traffics almost exclusively in emp blocks (which are 128 bit
data types) we end up needing to do practically more OTs than the proof
describes. This has the impact of needing expansion around choice bits etc. We
also produce extra pads too, which is important from a randomness perspective.

   Please note that this namespace also contains an as-yet unpublished
optimisation for the unbatched scheme that was kindly shared with us by the
authors of the aforementioned work. All credit of orginality goes to the
original authors. The batched scheme does not contain this optimisation.

   The unbatched scheme can be accessed via the "_repeated" functions, whereas
the batched scheme can be accessed via the "_batched" functions.

   @remarks Please note that most of the batched functions return unique_ptrs to
types, rather than the types themselves. This is because the structs are
   typically large (i.e the largest is around 12MB), which can cause stack
overflows.
  @remarks You can customise if IKNP or Ferret is used by setting the
"use_ferret" bool in this header.
**/
namespace F2128_MTA {

/**
   use_ferret. If this is true, then the OT uses the actively secure Ferret
implementation. If false, then the OT uses the actively secure IKNP extension.
**/
inline constexpr bool use_ferret = false;

/**
     use_multiplicative_shares. If this is true, then the batched OT expects
     the input shares to be multiplicative shares of `h`. If this is false,
     the batched OT assumes additive shares of `h`. This is an optimisation.
**/
inline constexpr bool use_multiplicative_shares = true;

/**
   k. k is the dimension of the field.
**/
inline constexpr auto k = 128;

/**
   s. s is the statistical security parameter. This is set to 128 bits to match
the security of the rest of the protocol.
**/
inline constexpr auto s = 128;

/**
     l. We do this many multiplications per batch for the batched
     multiplication. If `use_multiplicative_shares` is true, then this is
     halved, but with an extra one to convert the first element too.
**/
inline constexpr auto l =
    (use_multiplicative_shares) + 1022 / (use_multiplicative_shares + 1);

/**
   batch_size. This is the number of "half" oblivious transfers that we do. For
example, this is the parameter `l` supplied to FCOTLE in the original paper.
**/
inline constexpr auto batch_size = 2 * (s + k);

/**
   gadget_elements. This is the number of elements in the gadget vector g (see
the original paper). Each element is an emp::block.
**/
inline constexpr auto gadget_elements = k + 2 * s;

/**
     eta. This is the number of elements transferred in the batched version of
the protocol.
**/
inline constexpr auto eta = gadget_elements * l;

// This is just here to make sure that everything fits nicely into emp's
// worldview.
static_assert(eta % sizeof(emp::block) == 0);

/**
   number_of_ots. This is the number of oblivious transfers that are carried out
 during the protocol. The reason for the factor of 2 is that emp's fundamental
 unit of abstraction for OT is the block, which exactly matches our element
 size. Since the protocol requires extra bits for commitments, we need twice as
 many OTs.
 **/
inline constexpr auto number_of_ots = 2 * batch_size;

/**
   number_of_batched_ots. This is the number of oblivious transfers carried out
   during the batched protocol. The reasoning for the factor of 2 is the same as
for th e unbatched protocol.
**/
inline constexpr auto number_of_batched_ots = 2 * eta;

/**
   InnerType. This struct is used to provide aligned elements with struct
semantics. The reason why this exists as a struct (and not, say, std::array) is
because std::array doesn't necessarily recognise explicit alignment.
   @tparam len: the number of elements in the struct.
**/
template <unsigned long len> struct InnerType {
  /**
     elem. This is the underlying array of emp blocks.
  **/
  emp::block elem[len];

  /**
     size. This function returns the `len` parameter that is passed into the
  object. This function does not throw.
     @return the number of elements in the type.
  **/
  static constexpr unsigned size() noexcept;
  /**
     operator[]. This function returns a const reference to elem[index].
     This function does not modify this object and does not throw.
     @param[in] index: the index.
     @return elem[index].
  **/
  inline const emp::block &operator[](const unsigned index) const noexcept;
  /**
     operator[]. This function returns a reference to elem[index].
     This function does not throw.
     @param[in] index: the index.
     @return elem[index].
  **/
  inline emp::block &operator[](const unsigned index) noexcept;

  /**
     data(). This function returns a pointer to elem[0].
     This function does not throw.
     @return a pointer to elem[0].
  **/
  inline emp::block *data() noexcept;
  /**
     data. This function returns a const pointer to elem[0].
     This function does not throw or modify this object.
     @return a const pointer to elem[0].
  **/
  inline const emp::block *data() const noexcept;
};

/**
   EncodeType. This is the type for the encoding used to represent a noisy
version of `beta`. See Algorithm 4 of the original paper. This is used to hold
the initial choice bits for OT.
**/
using EncodeType = InnerType<4>;

/**
   GadgetType. This is the type for the vector g^r. See Algorithm 4 of the
original paper. This is used to supply the extra noisy encoding. This is chosen
by the receiver party.
**/
using GadgetType = InnerType<gadget_elements>;

/**
   TType. This is the type for the pads vector. This is used to produce pairs
for the oblivious transfer.
**/
using TType = InnerType<number_of_ots>;
/**
   BatchedTType. This is the type for the pads vector in the batched protocol.
This is used for pairs for the OT.
**/

using BatchedTType = InnerType<number_of_batched_ots>;

/**
   OTType. This is the type used in the oblivious transfer. OTType[0] contains
the choices for a choice bit of 0, whereas OTType[1] contains the choices for a
choice bit of 1.
**/
using OTType = std::array<TType, 2>;
/**
   BatchedOTType. This is the type used in the OT for the batched protocol.
BatchedOTType[0] contains the choices for a choice bit of 0, whereas OTType[1]
contains the choices for a choice bit of 1.
**/
using BatchedOTType = std::array<BatchedTType, 2>;

/**
   OTOutType. This is the type that is output by oblivious transfer.
OTOutType[0] contains the "first half" of the output from the OT, whereas
OTOutType[1] contains the "second half" of the output from the OT.
**/
using OTOutType = std::array<InnerType<batch_size>, 2>;
/**
   BatchedOTOutType. This is the type that is output by the OT for the batched
protocol. BatchedOTOutType[0] contains the "first half" of the output from the
OT, whereas BatchedOTOutType[1] contains the "second half".
**/
using BatchedOTOutType = std::array<InnerType<number_of_batched_ots / 2>, 2>;

/**
   RandomType. This is the type used for the Chi and Chi hat values from the
multiplication protocol.
**/
using RandomType = InnerType<2>;
/**
   RType. This is the type used to contain the values of `r` from the
multiplication protocol.
**/
using RType = InnerType<batch_size>;
/**
   GType. This is the type used for the general vector `g`. In particular, the
first 128 elements are powers of 2 i.e GType[i] = 2^i. The rest are the elements
from the gadget type.
**/
using GType = InnerType<batch_size>;
/**
   ChoiceBitType. This is the type that's used for the extended OT choice bits.
Essentially, because of emp's API, we need to turn the bits in the encoded type
(i.e EncodeType) into an array of bools.
**/
using ChoiceBitType = std::array<bool, number_of_ots>;
/**
   BatchedChoiceBitType. This is the type that's used for the extended OT choice
bits in the batched protocol. Essentially, because of emp's API, we need to turn
the bits in the encoded type (i.e BetaType) into an array of bools.
**/
using BatchedChoiceBitType = std::array<bool, number_of_batched_ots>;

/**
   ShareType. This is the type used to return the AES-GCM shares. Each position
corresponds to the power of the share: for example, ShareType[0] contains the
initial shares, whereas ShareType[2] contains the shares of h^2 etc etc.
**/
using ShareType = InnerType<1024>;

/**
    block_to_arr. This function is a helper for taking an emp `block` and
turning it into a std::array. This function does not throw.
    @param[in] in: the block to convert.
    @return `in` as an array.
**/
inline std::array<uint8_t, 16> block_to_arr(const emp::block in) noexcept;

/**
   arr_to_block. This function is a helper for taking an array and converting it
to an emp::block. This function does not throw.
   @param[in] in: the array to convert.
   @return `in` as an emp::block.
**/
inline emp::block arr_to_block(const std::array<uint8_t, 16> &in) noexcept;

/**
   dot_product. This function computes an inner product between `gamma` and
`gadget`, returning the result. This function does not throw.
   @param[in] gamma: a non-null pointer to 3 emp::blocks.
   @param[in] gadget: a reference to the gadget vector.
   @return the inner product of `gamma` and `gadget`.
   @remarks
   Warning: this is a utility function that requires quite careful usage.
   In particular, `gamma` is interpreted as a pointer to 3 emp::blocks (in
particular, containing 384 entries) and `gadget` is interpreted as a full gadget
type. This inner product is interpreted as a bit-wise multiplication (e.g we
include gadget[i] if the `ith` bit of gamma is set).
**/
inline emp::block dot_product(const emp::block *const gamma,
                              const GadgetType &gadget) noexcept;

/**
   AType. This is the type that is used to represent "A's" pads in the batched
protocol. These are later input to the batched OT.
**/
using AType = InnerType<l>;
/**
   AlphaType. This is the type that is used to represent the packed values
a_tilde and a_hat in the batched protocol. These are later input to the batched
OT.
**/
using AlphaType = InnerType<2 * eta>;
/**
   BetaType. This is the type that is used for the choice bits in the batched
protocol. This features a division to ensure we have exactly `eta` bits of
input.
**/
using BetaType = InnerType<eta / (CHAR_BIT * sizeof(emp::block))>;
/**
   BType. This is the type used for the `b` pads in the batched protocol.
**/
using BType = InnerType<l>;
/**
   ChiType. This is the type that is used for the randomness generated in the
batched protocol.
**/
using ChiType = std::array<InnerType<l>, 2>;
/**
   BatchedRType. This is the type that is used for the bit commitments in the
batched protocol.
**/
using BatchedRType = InnerType<2 * gadget_elements>;

/**
   generate_a. This function generates the random values `a` from the batched
multiplication protocol. In practice, this function just returns an
appropriately-sized random vector of elements in GF(2^128). This function can be
used to generate `a_tilde` and `a_hat`. This function does not throw.
   @return a random `a` vector.
**/
inline std::unique_ptr<AType> generate_a() noexcept;

/**
   produce_alpha. This function double packs a_tilde and a_hat, c.f line 2 of
   the batched multiplication protocol. In particular, this function returns an
array containing 2*l elements, with a_tilde at the even positions and a_hat at
the odd positions e.g alpha[2*i] = a_tilde, alpha[2*i+1] = a_hat. This function
does not throw.
   @param[in] a_tilde: a reference to the a_tilde object.
   @param[in] a_hat: a reference to the a_hat object.
   @return an array containing `a_tilde` and `a_hat`.
**/
inline std::unique_ptr<AlphaType> produce_alpha(const AType &a_tilde,
                                                const AType &a_hat) noexcept;

/**
   generate_beta. This function generates a random set of bits (c.f Line 1 of
the batched multiplication protocol) containing `eta` bits. This is divided up
into emp::blocks exactly.
   @return a set of `eta` random bits in the form of emp::blocks.
**/
inline BetaType generate_beta() noexcept;

/**
   produce_b. This function takes a publicly available gadget vector `gadget`
and a set of random choice bits (`beta`), returning the vector of pads `b`. This
   function implements the RHS of line 1 of the batched multiplication protocol.
   This function does not throw.
   @param[in] gadget: the random gadget vector to use.
   @param[in] beta: the set of random choice bits to use.
   @return the set of pads to use.
**/
inline BType produce_b(const GadgetType &gadget, const BetaType &beta) noexcept;

/**
   generate_gadget_r. This function returns a random vector `g^r` used to mask
the `beta` input. This function does not throw.
   @snippet F2128MtA.t.cpp F2128MtAGenerateGadgetR
   @return a new random vector.
**/
inline GadgetType generate_gadget_r() noexcept;
/**
   generate_g. This function accepts a gadget vector `g^r` and produces the
general vector `g`. This vector has powers of 2 in the first 128 elements and
then `g^r` in the rest of the elements. This function does not throw.
   @param[in] g_r: the gadget vector to pack.
   @return a new vector `g`.
**/
inline GType generate_g(const GadgetType &g_r) noexcept;

/**
   encode. This function accepts a block `in`, a gadget vector `gadget`
   and produces a vector as specified by Algorithm 4 of the original paper.
   This is later to be used for choice bits in the OT. This function does not
throw
   @snippet F2128MtA.t.cpp F2128MtAEncode
   @param[in] in: the input to encode.
   @param[in] gadget: the gadget vector to encode.
   @return an encoding of `in`.
**/
inline EncodeType encode(const emp::block in,
                         const GadgetType &gadget) noexcept;

/**
   shift_left_bits. This function shifts `in` to the left by `bits`, shifting in
zeroes. This function does not throw.
   @tparam bits: the number of bits to shift by.
   @param[in] in: the block to shift.
   @return in << bits
**/

template <int bits>
inline emp::block shift_left_bits(const emp::block in) noexcept;
/**
 shift_right_bits. This function shifts `in` to the right by `bits`, shifting in
zeroes. This function does not throw.
 @tparam bits: the number of bits to shift by.
 @param[in] in: the block to shift.
 @return in >> bits
**/

template <int bits>
inline emp::block shift_right_bits(const emp::block in) noexcept;

/**
   generate_pads. This function generates the pads supplied by the sender for
the oblivious transfer. In particular, this function returns randomly
cryptograpically generated values with enough space for a full OT. This function
does not throw.
   @return a vector of pads.
**/
inline TType generate_pads() noexcept;

/**
   generate_batched_pads. This function generates the pads supplied by the
sender for the batched OT. In particular, this function returns
cryptographically random values with enough space for a full batched OT. This
function does not throw.
   @return a vector of pads for the batched OT.
**/
inline std::unique_ptr<BatchedTType> generate_batched_pads() noexcept;

/**
     mul. This function multiplies `a` and `b` over F_{2^128} with reduction.
     This implementation uses the Intel GCM reference implementation from the
GCM manual.
     @param[in] a: the lhs.
     @param[in] b: the rhs.
     @return a * b.
**/
inline emp::block mul(const emp::block a, const emp::block b) noexcept;

/**
   inv. This function computes `a^-1` over F_{2^128}, returning the result.
   This implementation uses a naive square-and-multiply approach. This function
does not throw.
   @param[in] a: the value to invert.
   @return a^-1.
**/
inline emp::block inv(const emp::block a) noexcept;

/**
   generate_alpha_hat. This function returns a randomly sampled value
`\hat{alpha}` from F_{2^128}. This function does not throw.
   @return a random element of F_{2^128}.
**/
inline emp::block generate_alpha_hat() noexcept;

/**
   prepare_pairs. This function prepares the input to the OT from the
perspective of the sender. In particular, this function outputs a 2D array. The
first array contains the pads from `ts`. The second array contains `alpha-ts[i]`
at the event positions and `alpha_hat-ts[i]` at the odd positions. This function
does not throw.
   @param[in] alpha: the alpha parameter.
   @param[in] alpha_hat: the randomly sampled extra position.
   @param[in] ts: the pads.
   @return an array of pairs to be used for the OT.
**/
inline OTType prepare_pairs(const emp::block alpha, const emp::block alpha_hat,
                            const TType &ts) noexcept;

/**
     prepare_batched_pairs. This function prepares the input to the OT from the
  perspective of the sender. In particular, this function outputs a 2D array.
     The first array contains the pads from `ts`.
     The second array contains `alpha[i]-ts[i]`.
     @param[in] alpha: the alpha parameter (see Line 2 of the batched
  algorithm).
     @param[in] a_hat: the a_hat parameter.
     @param[in] ts: the pads.
     @return an array of pairs to be used for the batched OT.
  **/
inline std::unique_ptr<BatchedOTType>
prepare_batched_pairs(const AlphaType &alpha,
                      const BatchedTType &batched_ts) noexcept;
/**
   get_sender_out. This function returns the output from the sender's OT. In
particular, `ts` is split into two arrays, with the first array containing
elements from ts[0], ts[2],... and the second array containing ts[1], ts[3], ...
This function does not throw.
   @param[in] ts: the array of pads.
   @return the output of the sender's OT protocol.
**/
inline OTOutType get_sender_out(const TType &ts) noexcept;

/**
   get_sender_batched_out. This function returns the output from the sender's
OT. In particular, `ts` is split into two arrays, with the first array
containing elements from ts[0], ts[2],... and the second array containing ts[1],
ts[3],.... This function does not throw.
   @param[in] ts: the array of pads.
   @return the output of the sender's batched OT protocol.
**/
inline std::unique_ptr<BatchedOTOutType>
get_sender_batched_out(const BatchedTType &ts) noexcept;

/**
   play_batched_sender. This function carries out the batched OT on behalf of
the sender. This function supplies th e elements of `alpha` for the OT to be
carried out over `socket`. This function does not throw.
   @tparam OTSocket: the type of OT. Must be an emp OT type.
   @param[in] socket: the OT socket.
   @param[in] alpha: the arguments to the OT. alpha[0] is supplied for choice
bits 0, whereas alpha[1] is supplied for choice bits 1.
**/
template <typename OTSocket>
void play_batched_sender(OTSocket &socket, const BatchedOTType &alpha) noexcept;

/**
   play_sender. This function carries out the OT on behalf of the sender. This
function supplies the elements of `alpha` to the oblivious transfer to be
carried out over `socket`. This function does not throw.
   @tparam OTSocket: the type to be used for the OT. Must be an emp oblivious
transfer type.
   @param[in] socket: the socket to use for oblivious transfer.
   @param[in] alpha: the sender's input to the oblivious transfer.
**/
template <typename OTSocket>
inline void play_sender(OTSocket &socket, const OTType &alpha) noexcept;

/**
   get_choice_bits. This function takes `omega` and extracts each individual bit
as a bool, returning the result as an array. This is typically only useful just
before the emp OT is carried out. This function does not throw.
   @param[in] omega: the bits to split.
   @return an array of bools containing the expanded variant of `omega`.
**/
inline ChoiceBitType get_choice_bits(const EncodeType &omega) noexcept;

/**
   get_batched_choice_bits. This function takes `beta` and extracts each
individual bit as a bool, returning the result. This is useful when decisions
need to be made based on individual bits (i.e inside emp's OT). This function
does not throw.
   @param[in] beta: the bits to split.
   @return an array of bools containing the expanded variant of `beta`.
**/
inline std::unique_ptr<BatchedChoiceBitType>
get_batched_choice_bits(const BetaType &beta) noexcept;

/**
   play_batched_receiver. This function carries out the batched OT from the
perspective of the receiver, returning the result.
   @tparam OTSocket: the type to be used for the OT on behalf of the receiver.
This must be an emp OT type.
   @param[in] socket: the socket to use for the OT.
   @param[in] omega: the choice bits.
   @return the output of the batched OT.
**/
template <typename OTSocket>
inline std::unique_ptr<BatchedOTOutType>
play_batched_receiver(OTSocket &socket,
                      const BatchedChoiceBitType &omega) noexcept;

/**
    play_batched_receiver. This function carries out the batched OT from the
 perspective of the receiver, returning the result.
    @tparam OTSocket: the type to be used for the OT on behalf of the receiver.
 This must be an emp OT type.
    @param[in] socket: the socket to use for the OT.
    @param[in] omega: the choice bits.
    @return the output of the batched OT.
 **/
template <typename OTSocket>
inline std::unique_ptr<BatchedOTOutType>
play_batched_receiver(OTSocket &socket, const BetaType &omega) noexcept;

/**
   play_receiver. This function takes `omega` and carries out the OT from the
receiver's perspective, returning the result. This function does not throw.
   @tparam OTSocket: the type to be used for the OT on behalf of the receiver.
This must be an emp OT type.
   @param[in] socket: the socket to use for the OT.
   @param[in] omega: the choice bits input.
   @return the output of the oblivious transfer.
**/
template <typename OTSocket>
inline OTOutType play_receiver(OTSocket &socket,
                               const EncodeType &omega) noexcept;

/**
   play_receiver. This function takes `omega` and carries out the OT from the
receiver's perspective, returning the result. This function does not throw.
   @tparam OTSocket: the type to be used for the OT on behalf of the receiver.
This must be an emp OT type.
   @param[in] socket: the socket to use for the OT.
   @param[in] omega: the choice bits input.
   @return the output of the oblivious transfer.
**/
template <typename OTSocket>
inline OTOutType play_receiver(OTSocket &socket,
                               const ChoiceBitType &omega) noexcept;

/**
   prove_consistency. This function proves the consistency of the oblivious
transfer from the perspective of the sender. In particular, the sender generates
a series of bitwise commitments and sends those to the receiver. The receiver
then checks the commitments and returns true to this party if the action
succeeds and false otherwise. Accordingly, this function returns true if the
consistency checks pass and false otherwise. This function does not throw.
   @param[in] socket: the SSL socket to use.
   @param[in] alpha: the value of alpha supplied during the original OT.
   @param[in] alpha_hat: the random value supplied during the original OT.
   @param[in] t_a: the output of the sender's OT.
   @param[in] chi: the randomness generated during the call to
generate_randomness.
   @return true if the consistency checks pass, false otherwise.
**/
inline bool prove_consistency(SSL &socket, const emp::block alpha,
                              const emp::block alpha_hat, const OTOutType &t_a,
                              const RandomType &chi) noexcept;

/**
   prove_consistency_batched. This function proves the consistency of the inputs
for the batched OT protocol, returning true on success and false otherwise. This
function acts similarly to prove_consistency. This function does not throw.
   @param[in] ssl: the SSL connection to use.
   @param[in] a_tilde: the a_tilde value used during the OT.
   @param[in] a_hat: the a_hat value used during the OT.
   @param[in] t_a: the sender's output of the batched OT.
   @param[in] chi: the randomness produced during the protocol.
   @return true on success, false otherwise.
**/
inline bool prove_consistency_batched(SSL &ssl, const AType &a_tilde,
                                      const AType &a_hat,
                                      const BatchedOTOutType &t_a,
                                      const ChiType &chi) noexcept;
/**
 generate_batched_randomness. This function generates the shared randomness
across both parties for the batched protocol, returning the result. This
function does not throw.
 @param[in] ssl: the connection to use.
 @param[in] sender: true if the caller plays the sender, false otherwise.
 @return the produced randomness.
**/
ChiType generate_batched_randomness(SSL &ssl, const bool sender) noexcept;

/**
   generate_randomness. This function generates randomness for the OT
consistency checks. Here, the receiver first generates some randomness and sends
it to the sender, who then also generates some randomness and sends it to the
   receiver. Both parties output the same randomness.
   @param[in] ssl: the connection to use for the sending.
   @param[in] sender: true if the party is the sender, false otherwise.
   @return the randomness generated by both parties.
**/
inline RandomType generate_randomness(SSL &ssl, const bool sender) noexcept;
/**
   checks_consistency. This function proves the consistency of the oblivious
transfer from the perspective of the receiver. In particular, the sender
generates a series of bitwise commitments and sends those to the receiver. The
receiver then checks the commitments and returns true to this party if the
action succeeds and false otherwise. Accordingly, this function returns true if
the consistency checks pass and false otherwise. This function does not throw.
   @param[in] socket: the SSL socket to use.
   @param[in] t_b: the output of the original OT.
   @param[in] chi: the randomness generated during the call to
generate_randomness.
   @param[in] omega: the choice bits sampled during the
   @return true if the consistency checks pass, false otherwise.
**/
inline bool check_consistency(SSL &ssl, const OTOutType &t_b,
                              const RandomType &chi,
                              const ChoiceBitType &omega) noexcept;

/**
   checks_consistency. This function proves the consistency of the oblivious
transfer from the perspective of the receiver. In particular, the sender
generates a series of bitwise commitments and sends those to the receiver. The
receiver then checks the commitments and returns true to this party if the
action succeeds and false otherwise. Accordingly, this function returns true if
the consistency checks pass and false otherwise. This function does not throw.
   @param[in] socket: the SSL socket to use.
   @param[in] t_b: the output of the original OT.
   @param[in] chi: the randomness generated during the call to
generate_randomness.
   @param[in] omega: the choice bits sampled during the
   @return true if the consistency checks pass, false otherwise.
**/
inline bool check_consistency(SSL &ssl, const OTOutType &t_b,
                              const RandomType &chi,
                              const EncodeType &omega) noexcept;

/**
   check_consistency_batched. This function checks the consistency of the
batched OT from the perspective of the receiver, returning the result. This
function operates similarly to the other consistency check. This function does
not throw.
   @param[in] socket: the SSL socket to use.
   @param[in] t_b: the output of the original OT.
   @param[in] chi: the randomness generated during the call to
generate_randomness.
   @param[in] beta: the choice bits sampled during the
   @return true if the consistency checks pass, false otherwise.
**/
inline bool
check_consistency_batched(SSL &ssl, const BatchedOTOutType &t_b,
                          const ChiType &chi,
                          const BatchedChoiceBitType &beta) noexcept;
/**
   check_consistency_batched. This function checks the consistency of the
batched OT from the perspective of the receiver, returning the result. This
function operates similarly to the other consistency check. This function does
not throw.
   @param[in] socket: the SSL socket to use.
   @param[in] t_b: the output of the original OT.
   @param[in] chi: the randomness generated during the call to
generate_randomness.
   @param[in] beta: the choice bits sampled during the
   @return true if the consistency checks pass, false otherwise.
**/
inline bool check_consistency_batched(SSL &ssl, const BatchedOTOutType &t_b,
                                      const ChiType &chi,
                                      const BetaType &beta) noexcept;

/**
   compute_share. This function computes an inner product between `t[0:upper]`
and `g[0:upper]`, returning the result. This function does not throw.
   @param[in] upper: the upper bound for the multiplication.
   @param[in] t: the `t` vector.
   @param[in] g: the `g` vector.
   @return the inner product of t[0:upper] and g[0:upper].
**/
inline emp::block compute_share(const unsigned upper,
                                const InnerType<batch_size> &t,
                                const GType &g) noexcept;

/**
   generate_and_send_gadget. This function generates the gadget vector `g_r` and
sends it to the other party, returning the result. This function should be
called by the receiver in the OT.
   @param[in] ssl: the SSL connection to use.
   @return the generated gadget vector.
**/
inline GadgetType generate_and_send_gadget(SSL &ssl) noexcept;
/**
   receive_gadget. This function receives the gadget vector `g_r` from the other
party, returning the result. This function should be called by the sender in the
OT.
   @param[in] ssl: the SSL connection to use.
   @return the generated gadget vector.
**/
inline GadgetType receive_gadget(SSL &ssl) noexcept;

/**
   single_iter. This function carries out a single OT-based multiplication. In
particular, this function carries out an OT using `socket` and `ssl`, producing
the result in `out`. This function returns true on success and false otherwise.
The function does not throw.
   @tparam is_receiver: true if the caller is the receiver in the OT, false
otherwise.
   @tparam OTType: the type of OT to use.
   @param[in] socket: the socket to use.
   @param[in] ssl: the SSL connection to use.
   @param[in] in: the input to the OT multiplication.
   @param[out]: out: the output of the OT multiplication.
   @return true if successful, false otherwise.
**/
template <bool is_receiver, typename OTType>
inline bool single_iter(OTType &socket, SSL &ssl, const emp::block in,
                        emp::block &out) noexcept;

/**
   generate_shares. This function generates the entire series of additive shares
for `in`. In particular, assuming that `h = in_v + in_p`, then this function
generates additive shares of all powers of h through to h^1024, returning the
result. This function does not throw.
   @tparam is_verifier; true if the caller is the verifier, false otherwise.
   @tparam OTType: the type of oblivious transfer class to use.
   @param[in] socket: the OT wrapper to use.
   @param[in] ssl: the SSL wrapper to use.
   @param[in] in: the additive share of `h` that is held by this party.
   @return the shares of `h`.
**/
template <bool is_verifier, typename OTType>
inline ShareType generate_shares_repeated(OTType &socket, SSL &ssl,
                                          const emp::block in) noexcept;

/**
   generate_shares_verifier_repeated. This function simply calls generate_shares
from the perspective of the verifier, returning the result.
   @tparam OTType: the type of oblivious transfer class to use.
   @param[in] socket: the OT wrapper to use.
   @param[in] ssl: the SSL wrapper to use.
   @param[in] in: the additive share of `h` that is held by this party.
   @return the shares of `h`.
**/
template <typename OTType>
inline ShareType
generate_shares_verifier_repeated(OTType &socket, SSL &ssl,
                                  const emp::block in) noexcept;

/**
   generate_shares_prover. This function simply calls generate_shares from the
perspective of the prover, returning the result.
   @tparam OTType: the type of oblivious transfer class to use.
   @param[in] socket: the OT wrapper to use.
   @param[in] ssl: the SSL wrapper to use.
   @param[in] in: the additive share of `h` that is held by this party.
   @return the shares of `h`.
**/
template <typename OTType>
inline ShareType generate_shares_prover_repeated(OTType &socket, SSL &ssl,
                                                 const emp::block in) noexcept;
/**
    generate_shares_verifier_repeated. This function simply calls
 generate_shares from the perspective of the verifier, returning the result.
    @param[in] ssl: the SSL wrapper to use.
    @param[in] in: the additive share of `h` that is held by this party.
    @return the shares of `h`.
 **/
inline ShareType
generate_shares_verifier_repeated(SSL &ssl, const emp::block in) noexcept;
/**
   generate_shares_prover. This function simply calls generate_shares from the
perspective of the prover, returning the result.
   @param[in] ssl: the SSL wrapper to use.
   @param[in] in: the additive share of `h` that is held by this party.
   @return the shares of `h`.
**/
inline ShareType generate_shares_prover_repeated(SSL &ssl,
                                                 const emp::block in) noexcept;

// These classes exist only to make it easier to write the batched
// multiplication code. There is no functionality in either class that is not
// explained elsewhere.
class ReceiverType {
public:
  explicit ReceiverType(const GadgetType &gadget) noexcept;

  template <typename OTType> void do_ot(OTType &ot) noexcept;
  void generate_batched_randomness(SSL &ssl) noexcept;
  bool is_consistent(SSL &ssl) noexcept;

  // Used to compute a share of a single element. Used with additive shares.
  template <typename F>
  emp::block compute_share(SSL &ssl, const unsigned i, const emp::block in,
                           const emp::block other_in,
                           F &&compute_share_of) noexcept;

  // Used to compute shares of all powers. Used with multiplicative shares.
  template <typename F>
  void compute_mult_shares(SSL &ssl, ShareType &out,
                           F &&compute_share_of) noexcept;

private:
  BetaType beta;
  BType b;
  std::unique_ptr<BatchedChoiceBitType> omega;
  std::unique_ptr<BatchedOTOutType> t_b;
  ChiType chi;
};

class SenderType {
public:
  explicit SenderType(const GadgetType &) noexcept;

  template <typename OTType> void do_ot(OTType &ot) noexcept;
  void generate_batched_randomness(SSL &ssl) noexcept;
  bool is_consistent(SSL &ssl) noexcept;

  // Used to compute a share of a single element. Used with additive shares.
  template <typename F>
  emp::block compute_share(SSL &ssl, const unsigned i, const emp::block in,
                           const emp::block other_in,
                           F &&compute_share_of) noexcept;

  // Used to compute shares of all powers. Used with multiplicative shares.
  template <typename F>
  void compute_mult_shares(SSL &ssl, ShareType &out,
                           F &&compute_share_of) noexcept;

private:
  std::unique_ptr<AType> a_tilde;
  std::unique_ptr<AType> a_hat;
  std::unique_ptr<AlphaType> alpha;
  std::unique_ptr<BatchedTType> pads;
  std::unique_ptr<BatchedOTType> pairs;
  std::unique_ptr<BatchedOTOutType> t_a;
  ChiType chi;
};

/**
   generate_shares_batched. This function carries out the batched OT
multiplication protocol with `in` as input, returning the result. This function
does not throw.
   @tparam is_verifier: true if the caller is the verifier, false otherwise.
   @tparam OTType: the type of OT to be used. Must be an emp type.
   @param[in] socket: the OT wrapper to use.
   @param[in] ssl: the SSL connection to use.
   @param[in] in: the input share of `h` to the OT.
   @return the shares of the OT.
**/
template <bool is_verifier, typename OTType>
inline ShareType generate_shares_batched(OTType &socket, SSL &ssl,
                                         const emp::block in,
                                         uint64_t &bandwidth) noexcept;

/**
   generate_shares_prover_batched. This function carries out the batched OT
multiplication protocol from the perspective of the prover. This function uses
`in` as input, returning the result. This function does not throw.
   @param[in] ssl: the SSL connection to use.
   @param[in] in: the input share of `h` to the OT.
   @return the shares of the OT.
**/
inline ShareType generate_shares_prover_batched(SSL &ssl, const emp::block in,
                                                uint64_t &bandwidth) noexcept;
/**
   generate_shares_prover_batched. This function carries out the batched OT
multiplication protocol from the perspective of the prover. This function uses
`in` as input, returning the result. This function does not throw.
   @tparam OTType: the type of OT to use.
   @param[in] socket: the OT wrapper to use.
   @param[in] ssl: the SSL connection to use.
   @param[in] in: the input share of `h` to the OT.
   @return the shares of the OT.
**/
template <typename OTType>
inline ShareType generate_shares_prover_batched(OTType &socket, SSL &ssl,
                                                const emp::block in,
                                                uint64_t &bandwidth) noexcept;
/**
 generate_shares_verifier_batched.
 This function carries out the batched OT multiplication protocol
 from the perspective of the verifier. This function uses `in` as input,
returning the result. This function does not throw.
 @param[in] ssl: the SSL connection to use.
 @param[in] in: the input share of `h` to the OT.
 @return the shares of the OT.
**/
inline ShareType generate_shares_verifier_batched(SSL &ssl, const emp::block in,
                                                  uint64_t &bandwidth) noexcept;
/**
 generate_shares_verifier_batched. This function carries out the batched OT
multiplication protocol from the perspective of the verifier. This function uses
`in` as input, returning the result. This function does not throw.
 @tparam OTType: the type of OT to use.
 @param[in] socket: the OT wrapper to use.
 @param[in] ssl: the SSL connection to use.
 @param[in] in: the input share of `h` to the OT.
 @return the shares of the OT.
**/
template <typename OTType>
inline ShareType generate_shares_verifier_batched(OTType &socket, SSL &ssl,
                                                  const emp::block in,
                                                  uint64_t &bandwidth) noexcept;

/**
   generate_shares_prover_batched. This function carries out the batched OT
multiplication protocol from the perspective of the prover. This function uses
`in` as input, returning the result. This function does not throw.
   @param[in] ssl: the SSL connection to use.
   @param[in] in: the input share of `h` to the OT.
   @return the shares of the OT.
**/
inline ShareType
generate_shares_prover_batched(SSL &ssl, const std::array<uint8_t, 16> &in,
                               uint64_t &bandwidth) noexcept;

/**
 generate_shares_verifier_batched.
 This function carries out the batched OT multiplication protocol
 from the perspective of the verifier. This function uses `in` as input,
returning the result. This function does not throw.
 @param[in] ssl: the SSL connection to use.
 @param[in] in: the input share of `h` to the OT.
 @return the shares of the OT.
**/
inline ShareType
generate_shares_verifier_batched(SSL &ssl, const std::array<uint8_t, 16> &in,
                                 uint64_t &bandwidth) noexcept;

} // namespace F2128_MTA

// Inline defintions live here.
#include "F2128MtA.inl"

#endif
