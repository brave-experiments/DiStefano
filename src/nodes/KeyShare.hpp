#ifndef INCLUDED_KEYSHARE_HPP
#define INCLUDED_KEYSHARE_HPP

#include "crypto/internal.h"
#include "openssl/mem.h"
#include "openssl/ssl.h"
#include "ssl/internal.h"

class KeyShare {
public:
  KeyShare() : additive_share{}, share_public_key{}, share{} {}

  /**
  get_public_key. This function writes a copy of `this` shares's public
  key to the `arr` parameter. This function returns `true` if the write is
 successful and false otherwise.

  This function will fail if:
  1. resizing the input `arr` fails.

  This function will return true even if a public key has not yet been
 generated. This will manifest as `arr` being an array of size 0.

  This function does not modify `this` object and does not throw.
  @snippet KeyShares.t.cpp  KeyShareGetPublicKeyTests

  @param[out] arr: the array to overwrite. This will throw away any previous
  data in the array.
  @return true in case of success, false otherwise.
 **/
  bool get_public_key(bssl::Array<uint8_t> &arr) const noexcept;

  /**
   create_new_public_key. This function accepts a `curve_id` corresponding
   to an elliptic curve and generates a new public key for `this` share
   using the curve. This function returns true on success and false otherwise.

   This function fails if:
   1) `curve_id` doesn't correspond to a valid elliptic curve.
   2) generating the public key somehow fails.

   This function does not throw.

   @snippet KeyShare.t.cpp KeyShareCreatePublicKeyTests

   @param[in] curve_id: the identifier for the curve.
   @return true in case of success, false otherwise.
   @remarks At present we do not support the non-NIST curves. This may change
in future.
**/
  bool create_new_public_key(const uint16_t curve_id) noexcept;

  /**
   get_additive_shares. This function writes a copy of `this` share's
additive share to the `arr` parameter. This function returns `true` if the
write is successful and false otherwise.

   This function will fail if:
   1. resizing the input `arr` fails.


   This function will return true even if an additive share has not yet been
generated. This will manifest as `arr` being an array of size 0.

   This function does not modify `this` object and does not throw.
   @snippet KeyShare.t.cpp KeyShareGetAdditiveShareTests

   @param[out] arr: the array to overwrite. This will throw away any previous
   data in the array.
   @return true in case of success, false otherwise.
**/
  bool get_additive_share(bssl::Array<uint8_t> &arr) const noexcept;

  /**
   create_new_share. This function accepts a `curve_id` and a public key
corresponding to another node (`other_key_bytes`) and computes the sum of
`other_key_bytes` and a newly generated public key. This corresponds to adding
two points together on an elliptic curve.

   Please note that calling this function causes a new public key to be
generated for `this` share.

   This function returns false if:
   1. `curve_id` doesn't correspond to a valid elliptic curve.
   2. the call to Share::create_new_public_key fails.
   3. adding the two public keys together fails.
   4. exporting the public keys fails as a series of bytes fails.

   This function does not throw.
   @snippet KeyShare.t.cpp KeyShareCreateNewShareTests
   @param[in] curve_id: the identifier for the elliptic curve.
   @param[in] other_key_bytes: the public key of the other node.
   @return true in case of success, false otherwise.
**/
  bool create_new_share(const uint16_t curve_id,
                        const bssl::Array<uint8_t> &arr) noexcept;

  /**
     create_new_share. This function accepts a `curve_id` and a public key
corresponding to another node (`other_key_bytes`) and computes the sum of
`other_key_bytes` and a newly generated public key. This corresponds to adding
two points together on an elliptic curve.

   Please note that calling this function causes a new public key to be
generated for `this` share.

   This function returns false if:
   1. `curve_id` doesn't correspond to a valid elliptic curve.
   2. the call to Share::create_new_public_key fails.
   3. adding the two public keys together fails.
   4. exporting the public keys fails as a series of bytes fails.

   This function does not throw.
   @snippet KeyShare.t.cpp KeyShareCreateNewShareTests
   @param[in] curve_id: the identifier for the elliptic curve.
   @param[in] other_key_bytes: the public key of the other node.
   @return true in case of success, false otherwise.
   **/
  bool create_new_share(const uint16_t curve_id,
                        bssl::Span<const uint8_t> peer_key) noexcept;

  /**
     get_group_id. This function returns the group_id of the underlying key
  share. This function does not modify this object and does not throw. This
  function returns 0 in case of error. This is not a valid group ID.

     @snippet KeyShare.t.cpp KeyShareRetrieveGroupIDTests
     @return the group ID of the underlying key share.
  **/
  uint16_t get_group_id() const noexcept;

  /**
     finish. This function calls the underlying `finish` function for this key
  share. This function excepts the same input structure as bssl::SSLKeyShare
  (e.g this function expects there to be no GroupID or length prefix.
     @param[in] CBS: the location of the key bytes.
     @return true in case of success, false otherwise.
  **/
  bool finish(CBS &in) noexcept;

  /**
     secret_to_ec_point. This function converts `this` keyshare's secrets into
     a single EC point. This function returns a valid pointer on success and a
  null pointer otherwise. This function will return a null pointer if:

     1. The secrets do not represent a valid EC point in the group.
     2. Converting either secret to a bignum fails.
     3. The group share does not correspond to a valid group.

     This function does not throw.
     @return a valid pointer to an EC_POINT, or a null pointer in case of
  failure.
  **/
  bssl::UniquePtr<EC_POINT> secret_to_ec_point() noexcept;

  /**
     get_y_point. This function converts `this` keyshare's other_y_secret into
     a BIGNUM. This function returns a valid pointer on success and a null
  pointer on failure. This function will return a null pointer if converting to
  a bignum fails. This function does not throw.

     @return a pointer to a valid bignum on success or a nullptr on failure.
  **/
  bssl::UniquePtr<BIGNUM> get_y_point() noexcept;

  /**
     get_x_secret. This function returns a mutable (!!) reference to `this` key
  share's x_secret. This function does not throw.

     @return a reference to `this` key share's x secret.
  **/
  bssl::Array<uint8_t> &get_x_secret() noexcept;
  /**
     get_y_secret. This function returns a mutable (!!) reference to `this` key
  share's y_secret. This function does not throw.

     @return a reference to `this` key share's y secret.
  **/
  bssl::Array<uint8_t> &get_y_secret() noexcept;

private:
  /**
     additive_share. This contains `this` key shares's additive share of the 3
  party handshake key. This will be empty in some circumstances.
  **/
  bssl::Array<uint8_t> additive_share;
  /**
     share_public_key. This contains the public key of `this` share in a
   serialised format. This will be empty in some circumstances.
   **/
  bssl::Array<uint8_t> share_public_key;

  /**
     share. This is the underlying key share object. This will get replaced as
  new connections come in.
  **/
  bssl::UniquePtr<bssl::SSLKeyShare> share;

  /**
     out_secret. This contains the produced secret from the key exchange. You
  can view this as the `x` co-ordinate of the elliptic curve point.
  **/
  bssl::Array<uint8_t> out_secret;

  /**
     out_other_secret. This contains the "other" produced secret from the key
  exchange. You can view this as the `y` co-ordinate of the elliptic curve
  point.
  **/
  bssl::Array<uint8_t> out_other_secret;
};

#endif
