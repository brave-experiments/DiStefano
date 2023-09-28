#include "KeyShare.hpp"
#include "../ssl/Util.hpp"
#include <iostream>

static bssl::UniquePtr<BIGNUM>
convert_secret_to_bignum(bssl::Array<uint8_t> &arr) {
  return bssl::UniquePtr<BIGNUM>(BN_bin2bn(arr.data(), arr.size(), nullptr));
}

bssl::UniquePtr<BIGNUM> KeyShare::get_y_point() noexcept {
  return bssl::UniquePtr<BIGNUM>(
      BN_bin2bn(out_other_secret.data(), out_other_secret.size(), nullptr));
}

bssl::UniquePtr<EC_POINT> KeyShare::secret_to_ec_point() noexcept {
  // See Util.hpp for this.
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // Get the group ID and build a group.
  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(share->GroupID())));
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  if (!group || !bn_ctx) {
    return nullptr;
  }

  auto x_point = convert_secret_to_bignum(out_secret);
  auto y_point = convert_secret_to_bignum(out_other_secret);
  if (!x_point || !y_point) {
    return nullptr;
  }

  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
  if (!point) {
    return nullptr;
  }

  if (!EC_POINT_set_affine_coordinates_GFp(group.get(), point.get(),
                                           x_point.get(), y_point.get(),
                                           bn_ctx.get())) {
    return nullptr;
  }

  return point;
}

bool KeyShare::finish(CBS &in) noexcept {
  uint8_t alert;
  return (this->share &&
          this->share->Finish(&out_secret, &alert, in, &out_other_secret));
}

uint16_t KeyShare::get_group_id() const noexcept {
  if (!share) {
    return 0;
  }

  return share->GroupID();
}

bool KeyShare::get_public_key(bssl::Array<uint8_t> &arr) const noexcept {
  return arr.CopyFrom(share_public_key);
}

bool KeyShare::get_additive_share(bssl::Array<uint8_t> &arr) const noexcept {
  return arr.CopyFrom(additive_share);
}

bool KeyShare::create_new_public_key(const uint16_t curve_id) noexcept {
  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // Right now we don't support the non-NIST curves.
  if (curve_id == SSL_CURVE_CECPQ2 || curve_id == SSL_CURVE_X25519) {
    return false;
  }

  this->share = bssl::SSLKeyShare::Create(curve_id);
  if (!this->share) {
    return false;
  }

  return Util::generate_public_key(*share, share_public_key);
}

bool KeyShare::create_new_share(const uint16_t curve_id,
                                const bssl::Array<uint8_t> &arr) noexcept {
  return create_new_share(curve_id, bssl::MakeSpan(arr.data(), arr.size()));
}

bssl::Array<uint8_t> &KeyShare::get_y_secret() noexcept {
  return this->out_other_secret;
}

bssl::Array<uint8_t> &KeyShare::get_x_secret() noexcept {
  return this->out_secret;
}

bool KeyShare::create_new_share(const uint16_t curve_id,
                                bssl::Span<const uint8_t> peer_key) noexcept {
  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // If creating the public key fails, then we'll have to exit.
  if (!create_new_public_key(curve_id)) {
    return false;
  }

  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(Util::get_nid_from_uint16(share->GroupID())));
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  if (!bn_ctx) {
    return false;
  }

  bssl::BN_CTXScope scope(bn_ctx.get());
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
  if (!point) {
    return false;
  }

  bssl::UniquePtr<EC_POINT> peer_point(EC_POINT_new(group.get()));
  bssl::UniquePtr<EC_POINT> result(EC_POINT_new(group.get()));

  if (!peer_point || !result) {
    return false;
  }

  if (peer_key.empty() || peer_key[0] != POINT_CONVERSION_UNCOMPRESSED ||
      !EC_POINT_oct2point(group.get(), peer_point.get(), peer_key.data(),
                          peer_key.size(), bn_ctx.get())) {
    return false;
  }

  // We now need to unpack our own public key and convert it into an EC point.
  bssl::UniquePtr<EC_POINT> our_pk(EC_POINT_new(group.get()));
  uint16_t our_curve_id;
  if (!our_pk ||
      !Util::CBBToECPoint(group.get(), &our_pk, &our_curve_id, share_public_key,
                          bn_ctx.get()) ||
      our_curve_id != curve_id) {
    return false;
  }

  // Now we can add them.
  if (!EC_POINT_add(group.get(), result.get(), our_pk.get(), peer_point.get(),
                    bn_ctx.get())) {
    return false;
  }

  // And finally we'll write it out.
  return Util::ECPointToCBB(our_curve_id, group.get(), result.get(),
                            additive_share, bn_ctx.get());
}
