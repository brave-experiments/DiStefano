#include "Util.hpp"
#include "crypto/internal.h"
#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "openssl/ssl.h"
#include "ssl/internal.h"
#include "ssl/internal.h" // This contains the declaration for Array.
#include <iostream>
#include <sstream>

bool Util::ECPointToCBB(const uint16_t group_id, const EC_GROUP *const group,
                        const EC_POINT *const point, bssl::Array<uint8_t> &out,
                        BN_CTX *const ctx) noexcept {
  if (!group || !point || !ctx) {
    return false;
  }

  bssl::ScopedCBB active_scbb;
  CBB cbb;
  if (!Util::initialise_cbb_for_ec_point_data(group_id, active_scbb.get(),
                                              &cbb) ||
      !EC_POINT_point2cbb(&cbb, group, point, POINT_CONVERSION_UNCOMPRESSED,
                          ctx) ||
      !CBBFinishArray(active_scbb.get(), &out)) {
    return false;
  }

  return true;
}

bool Util::CBBToECPoint(EC_GROUP *const group,
                        bssl::UniquePtr<EC_POINT> *const out,
                        uint16_t *const group_id,
                        const bssl::Array<uint8_t> &in,
                        BN_CTX *const ctx) noexcept {
  // Pre-conditions: check that the pointers are all valid.
  if (!group || !out || !out->get() || !group_id || !ctx) {
    return false;
  }

  // We need to turn the `in` array into a CBS to be consistent with
  // the BoringSSL functions. This also requires us to place the output into
  // a CBS.
  CBS in_cbs, out_cbs;
  CBS_init(&in_cbs, in.data(), in.size());
  if (!deinitialise_cbb_for_ec_point_data(group_id, &in_cbs, &out_cbs)) {
    return false;
  }

  // Everything on from here expects a span, so we'll make one.
  auto point_span = bssl::MakeSpan(CBS_data(&out_cbs), CBS_len(&out_cbs));
  if (point_span.empty() || point_span[0] != POINT_CONVERSION_UNCOMPRESSED) {
    return false;
  }

  if (!EC_POINT_oct2point(group, out->get(), point_span.data(),
                          point_span.size(), ctx)) {
    return false;
  }

  return true;
}

bool Util::RandomECPoint(const EC_GROUP *const group, EC_POINT *const out,
                         BN_CTX *const ctx) noexcept {
  if (!group || !out || !ctx) {
    return false;
  }

  // NOTE: this cannot be a unique_ptr.
  // The reason for this is because the context
  // is managed externally, and because the bignum
  // context does some book-keeping that (for some reason) isn't
  // updated when x_1 goes out of scope. As a result, if x_1 were a unique_ptr,
  // we would end up with a double free (once when x_1 is freed, and once when
  // ctx scopes out of scope). This is a bug that manifests only under certain
  // situations: for example, if you were to run this with AddressSanitizer
  // enabled then the bug is hidden (i.e it doesn't manifest here). However, if
  // you run this without AddressSanitizer then this will crash on some
  // machines. This is an insidious bug :)

  BIGNUM *const x_1 = BN_CTX_get(ctx);

  if (!x_1) {
    return false;
  }

  if (!BN_rand_range_ex(x_1, 1, EC_GROUP_get0_order(group)) ||
      !EC_POINT_mul(group, out, x_1, nullptr, nullptr, ctx)) {
    return false;
  }

  return true;
}

bool Util::EC_point_addition(EC_GROUP *const group,
                             bssl::UniquePtr<EC_POINT> *const out,
                             const bssl::Array<uint8_t> &a,
                             const bssl::Array<uint8_t> &b,
                             BN_CTX *bn_ctx) noexcept {
  if (!out || !out->get() || !bn_ctx || !group || a.size() != b.size()) {
    return false;
  }

  bssl::UniquePtr<EC_POINT> point_a(EC_POINT_new(group)),
      point_b(EC_POINT_new(group));

  if (!point_a || !point_b) {
    return false;
  }

  uint16_t group_id_a, group_id_b;
  if (!Util::CBBToECPoint(group, &point_a, &group_id_a, a, bn_ctx) ||
      !Util::CBBToECPoint(group, &point_b, &group_id_b, b, bn_ctx) ||
      group_id_a != group_id_b) {
    return false;
  }

  if (!EC_POINT_add(group, out->get(), point_a.get(), point_b.get(), bn_ctx)) {
    return false;
  }

  return true;
}

bool Util::initialise_cbb_for_ec_point_data(const uint16_t group_id,
                                            CBB *const in,
                                            CBB *const out) noexcept {
  if (!in || !out) {
    return false;
  }

  // 64 here comes from ssl_setup_key_shares.
  if (!CBB_init(in, 64) || !CBB_add_u16(in, group_id) ||
      !CBB_add_u16_length_prefixed(in, out)) {
    return false;
  }

  return true;
}

bool Util::deinitialise_cbb_for_ec_point_data(uint16_t *const group_id,
                                              CBS *const in,
                                              CBS *const out) noexcept {
  if (!in || !out || !group_id || in == out) {
    return false;
  }

  if (!CBS_get_u16(in, group_id) || !CBS_get_u16_length_prefixed(in, out) ||
      CBS_len(in) != 0) {
    return false;
  }

  return true;
}

bool Util::generate_public_key(bssl::SSLKeyShare &client,
                               bssl::Array<uint8_t> &out) noexcept {
  // We have to serialise this into a buffer.
  // BoringSSL has a byte string class that's just for this.
  bssl::ScopedCBB cbb;
  CBB key_exchange;
  if (!Util::initialise_cbb_for_ec_point_data(client.GroupID(), cbb.get(),
                                              &key_exchange)) {
    return false;
  }

  // Now we'll generate some key shares.
  if (!client.Offer(&key_exchange)) {
    return false;
  }
  return CBBFinishArray(cbb.get(), &out);
}

static bool compute_premaster_secret_impl(
    bssl::SSLKeyShare &client, bssl::Array<uint8_t> &in, uint8_t &alert,
    bssl::Array<uint8_t> &out_x, bssl::Array<uint8_t> *out_y) noexcept {
  // This implementation is broken out so that "real" clients can supply
  // a null pointer for `out_y` if they so choose.
  // NOTE: the code in this function is inspired by
  // the code from:
  // https://github.com/google/boringssl/blob/50e7ea5f09d15a65f5dd0b63b64504d6d4815001/ssl/extensions.cc#L2350
  //
  // It turns out that BoringSSL has lots of code for parsing keys, but the link
  // above appears to be the one that's used for TLS1.3.

  // Anyway: the KeyShares only accept a CBS as input, so we need to turn the
  // `in` reference into a CBS. This is fairly easy.
  CBS in_cbs;
  CBS_init(&in_cbs, in.data(), in.size());

  // And we'll also need places to keep the group id and the
  // peer key.
  CBS peer_key;
  uint16_t group_id;
  if (!Util::deinitialise_cbb_for_ec_point_data(&group_id, &in_cbs,
                                                &peer_key) ||
      // N.B the CBS implicitly converts to a span.
      !client.Finish(&out_x, &alert, peer_key, out_y)) {
    return false;
  }

  return true;
}

bool Util::compute_premaster_secret(bssl::SSLKeyShare &client,
                                    bssl::Array<uint8_t> &in, uint8_t &alert,
                                    bssl::Array<uint8_t> &out_x,
                                    bssl::Array<uint8_t> &out_y) noexcept {
  return compute_premaster_secret_impl(client, in, alert, out_x, &out_y);
}

bool Util::compute_premaster_secret(bssl::SSLKeyShare &client,
                                    bssl::Array<uint8_t> &in, uint8_t &alert,
                                    bssl::Array<uint8_t> &out_x) noexcept {
  return compute_premaster_secret_impl(client, in, alert, out_x, nullptr);
}

bool Util::is_valid_filepath(const char *const filepath) noexcept {
  assert(filepath);
  FILE *f = std::fopen(filepath, "r");
  if (f != nullptr) {
    // Can only close if the file is valid: otherwise, this is
    // the same as freeing a nullptr.
    std::fclose(f);
    return true;
  }
  return false;
}

bool Util::get_hash(bssl::SSLTranscript *const transcript,
                    std::array<uint8_t, 32> &out) noexcept {

  if (!transcript || transcript->DigestLen() != 32)
    return false;
  size_t out_size;
  return transcript->GetHash(out.data(), &out_size) && out.size() == out_size;
}
