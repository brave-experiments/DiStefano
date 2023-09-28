#ifndef INCLUDED_UTIL_HPP
#define INCLUDED_UTIL_HPP

#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "openssl/rand.h" // Needed for random number generation.
#include "ssl/internal.h" // This contains the declaration for Array.
#include <array>          // Needed for C++'s std::array.
#include <cassert>
#include <climits>
#include <cstdint>
#include <functional>

/**
   @brief Util. This namespace contains a series of utility functions for
interacting neatly with various parts of BoringSSL. This is primarily to make it
easier to write code that abstracts out some of the harder details around how
data is packed and transferred.

This namespace also contains some useful utility functions for other parts
of the project. These primarily relate to data conversions.
**/
namespace Util {

/**
   only_nist_curves. This public boolean is here to make it easier for us to
 easily detect where we might need to add Curve25519 support later. Essentially:
   1. Each function that makes the choice to only use NIST curves should have a
 static assert against this field.
   2. Then when this is set to false, the code will fail to compile.

   This is just to make it easier to detect exactly where our code will break.

   NOTE: the BoringSSL functions (e.g ssl_set_nist_curves) cannot "opt-in" to
 this. To get around this, this check will be in the ThreePartyHandshake
 functions too.
 **/
static constexpr bool only_nist_curves = true;

/**
 not_cryptographically_random. This public boolean is here to make it easier for
us to easily detect where we might need to change random number generators
later. Essentially:
 1. Each function that generates random elements without a cryptographically
secure RNG should static assert against this field.
 2. Then when this is set to false, the code will fail to compile.

 This is just to make it easier to detect exactly where our code will break.
**/
static constexpr bool not_cryptographically_random = true;

/**
   get_nid_from_uint16_t. This function accepts a group ID as a 16-bit unsigned
integer and returns the group ID as a NIST ID. This is primarily useful for
operating over NIST curves. If the group id does not match a specified NIST
curve, then this function returns 0. This is because 0 is defined as the
undefined NIST curve in most settings (see e.g
https://github.com/google/boringssl/blob/44872e1c74cbac6a0772dd588a7693bffbdade17/include/openssl/nid.h#L85).

   Please note that this function will only return the NIDs for actively
supported NIST curves. You can find a list of these in SSLKeyShare::Create (see
e.g https://github.com/google/boringssl/blob/master/ssl/ssl_key_share.cc#L308).


   @snippet Util.t.cpp UtilGetNidFromUint16tTests
   @param group_id The identifier of the group.
   @return the integer corresponding to the group_id.
**/
constexpr int get_nid_from_uint16(const uint16_t group_id) noexcept;

/**
   is_nist_curve. This function accepts a 16-bit unsigned integer as a
`curve_id` and returns true if `curve_id` corresponds to a NIST curve and false
otherwise. This function does not throw.

   @snippet Util.t.cpp UtilIsNistCurveTests
   @param[in] curve_id: the ID of the curve.
   @return true if curve_id corresponds to a NIST curve, false otherwise.
**/
constexpr bool is_nist_curve(const uint16_t curve_id) noexcept;

/**
 RandomECPoint. This function randomly generates a point on an elliptic curve
 whose base group is `group`. The randomly sampled point is then written to
 `out`. Note that `ctx` is used for computations.

 This function returns true in case of success and false otherwise. This
function returns false if: 1) Any of `group`, `ctx`, `out` are
null. 2) If the `group` is not initialised. 3) If an internal operation fails.

 @snippet Util.t.cpp UtilRandomECPointTests


 @param[in] group: the group used to generate the elliptic curve.
 @param[out] out: the location to write the produced point.
 @param ctx: a bignum ctx used for computations.
 @return true in case of success, false otherwise.
**/
bool RandomECPoint(const EC_GROUP *const group, EC_POINT *const out,
                   BN_CTX *const ctx) noexcept;

/**
   EC_point_addition. This function converts `a` and `b` to points on the
 elliptic curve `group` and then computes `c = a + b`, writing
 the result to `out`.

 This function returns true in case of success and false in case of error.
 This function will return false if:
 1) Any of `out`, `group`, `bn_ctx` or `out->get()` are null.
 2) `a` or `b` do not represent elliptic curve points.
 3) `a` or `b` are different sizes.
 4) `a` and `b` belong to different elliptic curves.

 @snippet Util.t.cpp UtilECPointAdditionTests

 @param[in] group: the group.
 @param[out] out: the location to write the produced point.
 @param[in] a: one of the two elliptic curve points in serialised format.
 @param[in] b: one of the two elliptic curve points in serialised format.
 @param[in] ctx: the big num context to use.
 @return true in case of success, false otherwise.
 **/
bool EC_point_addition(EC_GROUP *const group,
                       bssl::UniquePtr<EC_POINT> *const out,
                       const bssl::Array<uint8_t> &a,
                       const bssl::Array<uint8_t> &b, BN_CTX *bn_ctx) noexcept;

/**
   ECPointToCBB. This function converts a `point` on an elliptic curve over
   `group` (with ID `group_id`) to a (point uncompressed) serialised
representation, writing the result to `out`. Note that `ctx` is used internally
for some computations. This function returns true in case of success and false
otherwise.

   This function will return false when:
   1) Any of `group`, `point`, `ctx` are null.
   2) An internal conversion error occurs. This normally occurs if `point` is
not well-formed.

   @snippet Util.t.cpp UtilECPointToCBBTests

   @param[in] group_id: the identifier of the group.
   @param[in] group: the group over which the elliptic curve exists.
   @param[in] point: the point to be serialised.
   @param[out] out: the array to write the serialised representation.
   @param[in] ctx: a bignum context used for computations.
   @return true in case of success, false otherwise.

   @remarks  Please note that this function does not explicitly check that
`point` is a member of the curve over `group`: it is the caller's responsibility
to make sure that `point` is on a curved generated by `group`. It is possible
that the internal functions called by this function may check that `point` is a
member of the curve over `group`, but this should not be relied upon (This note
is a defence against Hyrum's law).
**/
bool ECPointToCBB(const uint16_t group_id, const EC_GROUP *const group,
                  const EC_POINT *const point, bssl::Array<uint8_t> &out,
                  BN_CTX *const ctx) noexcept;

/**
   CBBToECPoint. This function converts a serialised representation of an
elliptic curve point `in` to an elliptic curve point on the curve over `group`.
The group ID of the point is written to `group_id`, and the resulting point is
written to `out`. This function uses `ctx` in some internal computations.

   This function returns true in case of success and false otherwise. This
function will return false if:

   1) Any of `group`, `out`, `out->get()`, `ctx`, `group_id` are null.
   2) The `in` array is too small (e.g less than 3 bytes).
   3) The third byte of `in` is not POINT_CONVERSION_UNCOMPRESSED.
   4) `in` is not well-formed in another way not covered by points 2 and 3.

   @snippet Util.t.cpp UtilCBBToECPointTests

   @param[in] group: the group over which the elliptic curve exists.
   @param[out] out: the location to write the produced point.
   @param[out] group_id: the location to write the (recovered) group ID.
   @param[in] in: the array containing the compressed representation.
   @param[in] ctx: the bignum context used for computations.
   @return true in case of success, false otherwise.
**/
bool CBBToECPoint(EC_GROUP *const group, bssl::UniquePtr<EC_POINT> *const out,
                  uint16_t *const group_id, const bssl::Array<uint8_t> &in,
                  BN_CTX *const ctx) noexcept;

/**
   initialise_cbb_for_ec_point_data. This function accepts a `group_id`, a
 parent CBB `in`, and a CBB `out`. This function then sets `in` up to accept
 elliptic curve data from BoringSSL. It does this by initialising `in` to a
 fixed size (64), adding the `group_id` to the beginning of `in`, and then
 setting up `out` as a child of `in`. This function returns true on success and
 false on error. Note that both `in` and  `out` must be non-null, or this
 function will return false.

   @snippet Util.t.cpp UtilInitialiseCBBForEcTests

   @param[in] group_id: the ID of the group.
   @param in: the parent CBB.
   @param out: the new child CBB.
   @return true on success, false on an error.
 **/
bool initialise_cbb_for_ec_point_data(const uint16_t group_id, CBB *const in,
                                      CBB *const out) noexcept;

/**
   deinitialise_cbb_for_ec_point_data. This function accepts a CBS `in` and
checks the early formatting of `in`. If the early formatting of `in` is as
expected, then the `out` is added as a child to `in` and true is returned.
Otherwise, false is returned. The group id is also written to `group_id` in case
of success.

   This function will return false if any of `in`, `out` or `group_id` are null.
It will also return false if `in` == `out`. Please note that `in` must have been
initialised via `CBS_init`. Otherwise, the results are undefined (in general it
isn't possible to check this).

   @snippet Util.t.cpp UtilDeInitialiseCBBForEcTests

   @param group_id: the output group_id.
   @param in: the input CBS.
   @param out: the child CBS.
   @return true on success, false on error.

   @remarks The behaviour of this function is undefined if `in` was not
initialised via `CBS_init`. It is not possible to check this in general, as the
values inside `in` are not default initialised.
**/
bool deinitialise_cbb_for_ec_point_data(uint16_t *const group_id, CBS *const in,
                                        CBS *const out) noexcept;

/**
   compute_premaster_secret. This function is a wrapper over the Finish method
 of the `client`. This function also removes any point formatting from the
 elliptic curve functions generated by BoringSSL.

   In particular, this function accepts a `client` and a shared key `in` as
 input and computes the DH shared key between `client` and `in`. The secret key
 is written into `out`. In cases of failure this function returns false:
 otherwise, it returns true. Any TLS errors are written into `alert`.

   @snippet Util.t.cpp UtilComputePremasterSecretTests

   @param client: the key share whose private key is used.
   @param in: the public key.
   @param alert: the out parameter for any TLS errors.
   @param out_x: the shared secret's x-coordinate.
   @param out_y: the shared secret's y-coordinate.
   @return true in case of success, false otherwise.
 **/
bool compute_premaster_secret(bssl::SSLKeyShare &client,
                              bssl::Array<uint8_t> &in, uint8_t &alert,
                              bssl::Array<uint8_t> &out_x,
                              bssl::Array<uint8_t> &out_y) noexcept;

/**
   compute_premaster_secret. This function is a wrapper over the Finish method
 of the `client`. This function also removes any point formatting from the
 elliptic curve functions generated by BoringSSL.

   In particular, this function accepts a `client` and a shared key `in` as
 input and computes the DH shared key between `client` and `in`. The secret key
 is written into `out`. In cases of failure this function returns false:
 otherwise, it returns true. Any TLS errors are written into `alert`.

   @snippet Util.t.cpp UtilComputePremasterSecretTests

   @param client: the key share whose private key is used.
   @param in: the public key.
   @param alert: the out parameter for any TLS errors.
   @param out_x: the shared secret's x-coordinate.
   @return true in case of success, false otherwise.
   @remarks The only difference between this and the other pre-master secret
   function is that this one doesn't write out a `y` co-ordinate.
 **/
bool compute_premaster_secret(bssl::SSLKeyShare &client,
                              bssl::Array<uint8_t> &in, uint8_t &alert,
                              bssl::Array<uint8_t> &out_x) noexcept;

/**
   generate_public_key. This function accepts a key share `client` and generates
 a public key from `client`, writing the public key to `out`. This function is
 meant to hide some of the complexities regarding how BoringSSL formats some of
 its points. This function returns true on success and false on error.

   @snippet Util.t.cpp UtilGeneratePublicKeyTests

   @param client: the key share who generates the key. Note that `client` must
 be an ECKeyShare here. Furthermore, note that this modifies `client`.
   @param[out] out: the array where the public key is written.
   @return true on success, false on error.
 **/
bool generate_public_key(bssl::SSLKeyShare &client,
                         bssl::Array<uint8_t> &out) noexcept;

/**
   is_valid_filepath. This function returns true if `filepath` corresponds
   to a valid file and false otherwise. This function does not throw.


   This function is primarily useful when dealing with e.g interactions with emp
toolkit.
   @snippet Util.t.cpp UtilIsValidFilepath
   @param[in] filepath: the path to the file. Must not be null: in debug builds
this is asserted to.
   @return true if filepath refers to a valid file, false otherwise.
   @remarks This function does not modify the file referred to by filepath in
any way.
**/
bool is_valid_filepath(const char *const filepath) noexcept;

/**
   convert_bool_to_uint8. This function accepts a std::array of bools and
   converts each element to a uint8_t. This works similarly to how
   std::vector<bool> works: we interpret each entry of the input array
   as a singular bit, and then append that to the output array. This function
does not throw.

   @snippet Util.t.cpp UtilConvertBoolToUint8
   @param[in] in: the array of bools to convert.
   @return an array of uint8s with the same bit pattern as `in`.
   @remarks This function explicitly assumes that `size` is a multiple of 8.
   @remarks This function explicitly assumes that `CHAR_BIT` == 8.
**/

template <size_t size>
constexpr std::array<uint8_t, size / 8>
convert_bool_to_uint8(const std::array<bool, size> &in) noexcept;

/**
   convert_uint8_to_bool. This function accepts a pointer to a sequence of
uint8_ts, `in`, and converts each entry (up to `size`) to a bool, storing the
result in `out`. Similarly to in convert_bool_to_uint8, here we treat each bit
of the entry as a bool, which we then feed into the output array. This function
does not throw.

   @snippet Util.t.cpp UtilConvertUint8ToBool
   @tparam size: the number of elements to copy.
   @param[in] in: the input pointer. Not modified. Must not be null.
   @param[out] out: the output pointer. Must not be null.
   @remarks `in` must point to a sequence of at least `size` entries. Similarly,
`out` must point to an array of at least `size * 8` entries.
   @remarks This function assumes that CHAR_BIT == 8.
**/
template <size_t size>
constexpr void convert_uint8_to_bool(const uint8_t *in, bool *out) noexcept;

/**
   process_data. This function is a generic wrapper around doing I/O operations
using an ssl connection. This exists to allow a caller to send or receive data
   in a generic way without worrying about the confines of
SSL3_RT_MAX_PLAIN_LENGTH in either direction. This function does not throw.
   @tparam RT: The type of the buffer to use. Must be char * of some kind.
   @tparam F: The function to use.
   @param[in] ssl: the SSL connection to use.
   @param[in] data: the buffer to use.
   @param[in] nbyte: the number of bytes to read or write.
   @param[in] F: the operation to use.
**/
template <typename RT, typename F>
void process_data(SSL *const in, RT *const data, const std::size_t nbyte,
                  F &&func) noexcept(noexcept(func));

/**
     get_hash. This function extracts the hash from `transcript` and returns the
     output bytes in `out`. This function does not throw. This function returns
true on success and false otherwise.

     This function will return false if:
     1. Transcript is null.
     2. The digest length of transcript's hash is not 32 (corresponding to 256
bits).

     @snippet Util.t.cpp UtilGetHash
     @param[in] transcript: the SSL transcript from which to get the hash. Must
not be null.
     @param[out] out: the location to write the hashed bytes. Only valid if this
function returns true.
     @return true if successful, false otherwise.
     @remarks This function takes `transcript` as a pointer because
bssl::SSLTranscript does not have a copy constructor.
**/
bool get_hash(bssl::SSLTranscript *const transcript,
              std::array<uint8_t, 32> &out) noexcept;

/**
   generate_random_bytes. This function calls the OpenSSL `RAND_bytes` function
   to produce `size` bytes of randomness, returning the result in `out`. This
function does not throw. This function returns 1 if the call was successful.
   @tparam size: the number of random bytes to generate.
   @param[out] out: the location to write the randomly generated bytes.
   @return 1 if successful.
   @remarks If the internal call to get randomness fails, this function will
call std::abort.
**/
template <unsigned long size>
int generate_random_bytes(std::array<uint8_t, size> &out) noexcept;

/**
   generate_random_bytes. This function calls the OpenSSL `RAND_bytes` function
   to produce `size` bytes of randomness, returning the result in `data`. This
function does not throw. This function returns 1 if the call was successful.
   @tparam T: the type of the parameter being passed in. T must be a C++ trivial
type for this function to make much sense (see
en.cppreference.com/w/cpp/named_req/TrivialType).
   @tparam size: the number of random bytes to generate.
   @param[out] data: the location to write the randomly generated bytes. Must
not be null and must point to a buffer containing at least `size` bytes.
   @return 1 if successful.
   @remarks If the internal call to get randomness fails, this function will
call std::abort.
**/
template <unsigned long size, typename T>
int generate_random_bytes(T *const data) noexcept;
} // namespace Util

// Inline definitions go here.
#include "Util.inl"

#endif
