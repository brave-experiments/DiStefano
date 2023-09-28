#include "ThreePartyHandshake.hpp"
#include "../mta/F2128MtA.hpp"
#include "../mta/ectf.hpp"
#include "Messaging.hpp"
#include "Util.hpp"
#include "openssl/ssl.h"
#include "ssl/internal.h"
#include <tuple>

// Macros rarely help readability. Here, though, it makes life a lot easier.
#define RETURN_FALSE_IF_SSL_FAILED(ssl_size, target_size)                      \
  do {                                                                         \
    if (ssl_size <= 0 || static_cast<unsigned>(ssl_size) != target_size)       \
      return false;                                                            \
  } while (0)

template <Messaging::MessageHeaders target_header>
static bool is_correct_header(SSL *ssl) noexcept {
  // This function just reads a single header from `ssl` and checks that it is
  // the one that was expected. This can return false if reading fails too.
  static_assert(sizeof(target_header) == sizeof(uint8_t),
                "is_correct_header assumes sizeof(target_header) == 1");
  uint8_t header_buf;
  const auto amount_read = SSL_read(ssl, &header_buf, sizeof(header_buf));
  RETURN_FALSE_IF_SSL_FAILED(amount_read, sizeof(header_buf));

  // We now need to convert out of the serialisation format. This is likely a
  // big endian value, so we need to explicitly undo that conversion.
  CBS in_cbs;
  CBS_init(&in_cbs, &header_buf, sizeof(header_buf));

  uint8_t in_header;
  if (!CBS_get_u8(&in_cbs, &in_header) ||
      !Messaging::is_valid_header(in_header)) {
    return false;
  }

  return static_cast<Messaging::MessageHeaders>(in_header) == target_header;
}

static void delete_circuits(SSL *ssl) noexcept {
  // This is just a helper function to minimise code duplication.
  delete ssl->ks_circuit;
  delete ssl->handshake_circuit_a;
  delete ssl->handshake_circuit_b;
  delete ssl->traffic_circuit;
  delete ssl->aes_split_circuit;
  delete ssl->aes_joint_circuit;
  delete ssl->gcm_circuit;
}

bool ThreePartyHandshake::three_party_handshake_send_received_key_shares(
    SSL *ssl, uint16_t group_id, CBS &in_cbs) {
  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // If there's no verifier, then we have to bail.
  if (!ssl || ssl->verifier == nullptr) {
    return false;
  }

  // Similarly, if the array is empty then it doesn't make any sense: what would
  // we be sending?
  const auto size = CBS_len(&in_cbs);
  if (size == 0) {
    return false;
  }

  // And finally, if the SSL connection is a server then this makes no sense.
  if (SSL_is_server(ssl)) {
    return false;
  }

  // The CBS input isn't in exactly the right format for the receiver,
  // so we'll convert it here.
  bssl::ScopedCBB scbb;
  CBB out;
  bssl::Array<uint8_t> arr;
  const auto *const data = CBS_data(&in_cbs);

  if (!CBB_init(scbb.get(), 64) || !CBB_add_u16(scbb.get(), group_id) ||
      !CBB_add_u16_length_prefixed(scbb.get(), &out) ||
      !CBB_add_bytes(&out, data, sizeof(uint8_t) * size) ||
      !CBBFinishArray(scbb.get(), &arr)) {
    return false;
  }

  // Now arr holds everything in the right format, so we'll just write it
  bssl::Array<uint8_t> key_share_packed;
  if (!Messaging::pack_key_bytes(Messaging::MessageHeaders::SERVER_KEY_SHARE,
                                 arr, key_share_packed)) {
    return false;
  }

  // This is just an abbreviation.
  auto verifier = ssl->verifier;

  // NOTE: this cast is fine. This is because:
  // 1) SSL3_RT_MAX_PLAIN_LENGTH is much less than the maximum positive value
  // stored in an int on all systems. See
  // https://www.open-std.org/JTC1/SC22/WG14/www/docs/n1256.pdf for INT_MAX.
  // Whilst this is from the C standard, C++ draws on this fact. 2) We know that
  // SSL3_RT_MAX_PLAIN_LENGTH is the maximum value we'll pass here because of
  // the check above.
  const auto amount_written =
      SSL_write(verifier, key_share_packed.data(),
                static_cast<int>(key_share_packed.size()));

  // It is, of course, possible this write will fail.
  // However, if there's a handshake on the verifier that has yet to go through
  // this will still work: the handshake will go through in the background.
  RETURN_FALSE_IF_SSL_FAILED(amount_written, key_share_packed.size());

  // We expect the resulting message from the server to be a single
  // header in size.
  // To guard against problems we re-use the key_share_packed array though.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // We've now just read a single header into the key_share_packed array.
  if (!is_correct_header<Messaging::MessageHeaders::HS_RECV>(verifier)) {
    return false;
  }

  // NOTE: in some testing situations we want to bail here.
  // We'll do that if the "thrower" is set.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::HS_RECV)) {
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::three_party_handshake_comm(SSL *ssl,
                                                     bssl::SSL_HANDSHAKE *hs) {

  // See Util.hpp for this
  static_assert(
      Util::only_nist_curves,
      "Error: code now supports Curve25519: have you updated this function?");

  // If there's no verifier, then we have to bail.
  if (!ssl || ssl->verifier == nullptr || !hs) {
    return false;
  }

  // Similarly, we shouldn't expect this code to run on a server.
  if (SSL_is_server(ssl)) {
    return false;
  }

  // This is primarily because later on we'll overwrite these key bytes without
  // overwriting the other parts of the key.
  ssl->key_store.CopyFrom(hs->key_share_bytes);

  // By the time this function has been called the key shares are already in an
  // array format that can be used and serialised: so, we'll just use that.
  bssl::Array<uint8_t> key_share_packed;
  if (!Messaging::pack_key_bytes(Messaging::MessageHeaders::COLLECT,
                                 hs->key_share_bytes, key_share_packed)) {
    return false;
  }

  auto verifier = ssl->verifier;
  // NOTE: this cast is fine. This is because:
  // 1) SSL3_RT_MAX_PLAIN_LENGTH is much less than the maximum positive value
  // stored in an int on all systems. See
  // https://www.open-std.org/JTC1/SC22/WG14/www/docs/n1256.pdf for INT_MAX.
  // Whilst this is from the C standard, C++ draws on this fact. 2) We know that
  // SSL3_RT_MAX_PLAIN_LENGTH is the maximum value we'll pass here because of
  // the check above.
  const auto amount_written =
      SSL_write(verifier, key_share_packed.data(),
                static_cast<int>(key_share_packed.size()));
  // It is, of course, possible this write will fail.
  // However, if there's a handshake on the verifier that has yet to go through
  // this will still work: the handshake will go through in the background.
  RETURN_FALSE_IF_SSL_FAILED(amount_written, key_share_packed.size());

  // Before we do anything else, we may need to do some circuit setup. This is
  // done here because it makes the online time during the handshake lower.
  // However, we allow this to be turned off during testing.
  if (ssl->should_make_circuits) {
    // We just read the group IDs straight from the HS.
    // If one is not set, then the group id is 0.
    uint16_t group[2]{};
    if (hs->key_shares[0]) {
      group[0] = hs->key_shares[0]->GroupID();
    }

    if (hs->key_shares[1]) {
      group[1] = hs->key_shares[1]->GroupID();
    }

    // We'll dispatch to the generic builder function to get the right type.
    ssl->handshake_circuit_a = EmpWrapperAG2PC::build_derive_hs_circuit(
        verifier, group[0], emp::ALICE,
        EmpWrapperAG2PCConstants::HANDSHAKE_CIRCUIT_TAG_A);
    if (ssl->handshake_circuit_a) {
      ssl->handshake_circuit_a->do_preproc();
    }

    ssl->handshake_circuit_b = EmpWrapperAG2PC::build_derive_hs_circuit(
        verifier, group[1], emp::ALICE,
        EmpWrapperAG2PCConstants::HANDSHAKE_CIRCUIT_TAG_B);
    if (ssl->handshake_circuit_b) {
      ssl->handshake_circuit_b->do_preproc();
    }

    ssl->traffic_circuit = EmpWrapperAG2PC::build_derive_ts_circuit(
        verifier, emp::ALICE, EmpWrapperAG2PCConstants::TRAFFIC_CIRCUIT_TAG);
    if (ssl->traffic_circuit) {
      ssl->traffic_circuit->do_preproc();
    }

    ssl->aes_joint_circuit = EmpWrapperAG2PC::build_joint_aes_circuit(
        verifier, emp::ALICE, EmpWrapperAG2PCConstants::AES_JOINT_CIRCUIT_TAG);
    if (ssl->aes_joint_circuit) {
      ssl->aes_joint_circuit->do_preproc();
    }

    ssl->gcm_circuit = EmpWrapperAG2PC::build_gcm_circuit(
        verifier, emp::ALICE, EmpWrapperAG2PCConstants::GCM_CIRCUIT_TAG);
    if (ssl->gcm_circuit) {
      ssl->gcm_circuit->do_preproc();
    }
  }

  // Now we'll need to read the response from the verifier.
  // We re-use the packed array for this, so we'll stash the size.
  const auto expected_size = key_share_packed.size();
  const auto amount_read = SSL_read(verifier, key_share_packed.data(),
                                    static_cast<int>(expected_size));
  RETURN_FALSE_IF_SSL_FAILED(amount_read, expected_size);

  bssl::Array<uint8_t> new_key_bytes;
  Messaging::MessageHeaders header;
  if (!Messaging::unpack_key_bytes(header, key_share_packed, new_key_bytes)) {
    return false;
  }

  if (header != Messaging::MessageHeaders::OK) {
    return false;
  }

  // new_key_bytes is in exactly the format we want for sending on to the
  // server. So, we just copy it over.
  if (!hs->key_share_bytes.CopyFrom(new_key_bytes)) {
    return false;
  }

  // NOTE: in some testing situations we want to bail here.
  // We'll do that if the "thrower" is set.
  if (ssl->thrower &&
      ssl->throw_state == static_cast<uint8_t>(Messaging::MessageHeaders::OK)) {
    // Tidy up the used memory.
    delete_circuits(ssl);
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::derive_handshake_secret(
    bssl::SSL_HANDSHAKE *hs, SSL *ssl, bssl::Array<uint8_t> &secret) {
  if (!hs || !ssl || secret.size() == 0 || SSL_is_server(ssl) ||
      !ssl->verifier) {
    return false;
  }

  // All we have to do here is the regular ECtF functionality.
  // This is already provided for us in the ECtF namespace: all we really need
  // to do is to send a message saying that we're ready, and then we can call
  // into the ECtF routines.
  // Note: we have the secrets stored in `secret` (the x secret) and
  // `y_key_store` of the ssl object.

  // This is just an abbreviation.
  auto verifier = ssl->verifier;

  // We just write the header as a single value.
  constexpr static auto header = Messaging::MessageHeaders::DO_ECTF;
  // We expect the messages here to be a single
  // header in size.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // We have to make the header a big-endian value. You know, for compatibility.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!write_to.Init(sizeof(uint8_t))) {
    return false;
  }

  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }

  // Now just write it.
  const auto amount_written =
      SSL_write(verifier, write_to.data(), sizeof(uint8_t));
  // We should check that it went well.
  RETURN_FALSE_IF_SSL_FAILED(amount_written, sizeof(uint8_t));

  // Now we'll drop right into the ECtF functionality. We'll play the prover.
  if (!ECtF::ectf(ssl->x_key_store, verifier, secret, ssl->y_key_store,
                  hs->new_session->group_id, false)) {
    return false;
  }

  // As a side effect, we'll now mark which of the circuits we've set up is
  // actually the correct one. We delete the incorrect one, freeing any memory.
  if (ssl->should_make_circuits) {
    if (hs->new_session->group_id == SSL_CURVE_SECP256R1) {
      std::swap(ssl->ks_circuit, ssl->handshake_circuit_a);
      delete ssl->handshake_circuit_b;
    } else if (hs->new_session->group_id == SSL_CURVE_SECP384R1) {
      std::swap(ssl->ks_circuit, ssl->handshake_circuit_b);
      delete ssl->handshake_circuit_a;
    } else {
      return false;
    }
  }

  // Now we can just check that it worked via the header we receive.
  if (!is_correct_header<Messaging::MessageHeaders::ECTF_DONE>(verifier)) {
    return false;
  }

  // And now check if we need to bail.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::ECTF_DONE)) {
    delete_circuits(ssl);
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::derive_shared_master_secret(
    bssl::SSL_HANDSHAKE *hs, SSL *ssl, bssl::Array<uint8_t> &secret) {
  if (!hs || !ssl || secret.size() == 0 || SSL_is_server(ssl) ||
      !ssl->verifier) {
    return false;
  }
  return true;
}

bool ThreePartyHandshake::commit_to(
    SSL *const ssl, const bssl::Array<uint8_t> &blocks,
    const bssl::Array<unsigned> &blocks_to_commit_to,
    bssl::Array<uint8_t> &out) noexcept {

  if (!ssl || !ssl->verifier || blocks.size() == 0 ||
      blocks_to_commit_to.size() == 0 ||
      blocks_to_commit_to.size() > blocks.size()) {
    return false;
  }

  // Commitment to encrypted blocks follows the following schema:
  // 1) The prover generates the keys for the blocks they want
  //    to commit to, hashes them individually and forwards the hashes
  //    to the verifier, alongside the ciphertexts.
  // 2) The verifier and the prover jointly run the tag verification function
  // and
  //    output the result. They then generate decryption keys in 2PC if the tag
  //    passes.
  // 3) The prover then receives the key share from the other party. In
  // practice,
  //    we reveal all such key shares to make certain proofs potentially easier.

#ifndef NDEBUG
  // In debug mode, ensure that the commitments can be well-formed.
  for (auto index : blocks_to_commit_to) {
    if (index > blocks.size()) {
      return false;
    }
  }
#endif

  // Just an alias.
  auto *verifier = ssl->verifier;

  // These are contingent on using SHA-256 and AES 128. Change these
  // if you want a different hash / cipher.
  constexpr auto size_of_committed_value = 16;
  constexpr auto size_of_hash = 32;

  // Now produce the necessary randomness.
  // We do this by creating a load of random bytes.
  std::vector<uint8_t> shares(blocks_to_commit_to.size() *
                              size_of_committed_value);
  // Each commitment is 256 bits, so twice as big as the previous one.
  // We also offset by a header so we can just use the buffer directly.
  bssl::Array<uint8_t> commitments;
  const auto size = sizeof(Messaging::MessageHeaders) +
                    blocks_to_commit_to.size() * size_of_hash;

  if (!commitments.Init(size)) {
    return false;
  }

  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(Messaging::MessageHeaders::COMMIT))) {
    return false;
  }

  // Generate the randomness. We'll hash in directly.
  RAND_bytes(shares.data(), shares.size());

  // Commit to each individually.
  bssl::ScopedEVP_MD_CTX hash_;
  const auto *md = EVP_sha256();

  const auto nr_blocks = blocks_to_commit_to.size();
  unsigned out_len{};
  std::array<uint8_t, size_of_hash> tmp;

  for (unsigned i = 0; i < nr_blocks; i++) {
    hash_.Reset();

    if (!EVP_DigestInit_ex(hash_.get(), md, nullptr) ||
        !EVP_DigestUpdate(hash_.get(),
                          shares.data() + i * size_of_committed_value,
                          size_of_committed_value) ||
        !EVP_DigestFinal_ex(hash_.get(), tmp.data(), &out_len) ||
        out_len != size_of_hash ||
        !CBB_add_bytes(cbb.get(), tmp.data(), size_of_hash)) {
      return false;
    }
  }

  // Write out the hash.
  if (!CBBFinishArray(cbb.get(), &commitments)) {
    return false;
  }

  // Forward the message to the verifier to show we want to do a commitment.
  // The buffer is already packed with the commit header so all is good.
  Util::process_data(verifier, reinterpret_cast<char *>(commitments.data()),
                     commitments.size(), SSL_write);

  // Now we'll want to call into the circuit derivation functions. We do this
  // just for the blocks that we actually want to commit to.
  // To do this we send the block IDs to the verifier.

  const auto comm_size =
      blocks_to_commit_to.size() * sizeof(blocks_to_commit_to[0]);
  const auto csize = comm_size + sizeof(Messaging::MessageHeaders);
  bssl::Array<uint8_t> commit;

  if (!CBB_init(cbb.get(), csize) || !commit.Init(csize) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(Messaging::MessageHeaders::COMMIT_TO)) ||
      !CBB_add_bytes(
          cbb.get(),
          reinterpret_cast<const uint8_t *>(blocks_to_commit_to.data()),
          comm_size) ||
      !CBBFinishArray(cbb.get(), &commit)) {
    return false;
  }

  commit[0] = static_cast<uint8_t>(Messaging::MessageHeaders::COMMIT_TO);

  memcpy(commit.data() + 1, blocks_to_commit_to.data(),
         blocks_to_commit_to.size() * sizeof(uint8_t));
  Util::process_data(verifier, reinterpret_cast<char *>(commit.data()),
                     commit.size(), SSL_write);

  return true;
}

bool ThreePartyHandshake::aes_encrypt(SSL *const ssl, bssl::Array<uint8_t> &in,
                                      bssl::Array<uint8_t> &out) noexcept {

  if (!ssl || !ssl->verifier) {
    return false;
  }

  // We firstly need to call out to the joint circuit for
}

bool ThreePartyHandshake::aes_decrypt(SSL *const ssl, bssl::Array<uint8_t> &in,
                                      bssl::Array<uint8_t> &out) noexcept {

  // Only one failure case.
  if (!ssl || !ssl->verifier) {
    return false;
  }
}

bool ThreePartyHandshake::derive_handshake_keys(bssl::SSL_HANDSHAKE *hs,
                                                SSL *ssl,
                                                bssl::Array<uint8_t> &secret) {

  // Preconditions.
  if (!hs || !ssl || secret.size() == 0 || SSL_is_server(ssl) ||
      !ssl->verifier) {
    return false;
  }

  // Just an alias
  auto verifier = ssl->verifier;

  const auto group_id = hs->new_session->group_id;
  assert(group_id != 0);

  // We don't support these curves at present.
  // Adding support for SECP224R1 just requires us to make a couple of new
  // circuits: the other two are far harder.
  if (group_id == SSL_CURVE_SECP224R1 || group_id == SSL_CURVE_X25519 ||
      group_id == SSL_CURVE_CECPQ2) {
    return false;
  }

  // We can just call the Circuit derivation routine directly.
  // Note that this function needs the hash to be passed in by us.
  EmpWrapperAG2PCConstants::HandshakeCircuitIn input{};

  if (!Util::get_hash(&hs->transcript, input.hash) ||
      !input.key_share.CopyFrom(bssl::MakeSpan<const uint8_t>(
          ssl->x_key_store.data(), ssl->x_key_store.size()))) {
    return false;
  }

  EmpWrapperAG2PCConstants::HandshakeCircuitOut output;

  // NOTE: We wrap the underlying circuit in a unique_ptr so that it is always
  // deleted when this function exits, even if due to an exception.
  auto circuit = std::unique_ptr<EmpWrapperAG2PC>(ssl->ks_circuit);

  if (!ThreePartyHandshake::run_handshake_circuit(input, output, circuit.get(),
                                                  false)) {
    return false;
  }

  // N.B If you ever want to change this program to support larger than 128 bit
  // secrets, you'll need to modify the definitions in the SSL struct.
  // NOTE: the +4 here is because the AES IV is 12 bytes initially, before being
  // expanded into 16 bytes by another circuit.
  std::copy(output.iv.cbegin(), output.iv.cend(), ssl->shs_iv.begin() + 4);

  ssl->ms_share = output.MS_share;
  ssl->dhs_share = output.dHS_share;
  ssl->fk_s = output.fk_s;
  ssl->server_key_share = output.server_key_share;
  ssl->shts_share = output.SHTS_share;
  ssl->chts_share = output.CHTS_share;

  // Now wait for the header.
  if (!is_correct_header<Messaging::MessageHeaders::KS_DONE>(verifier)) {
    return false;
  }

  // If we need to bail, bail.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::KS_DONE)) {
    delete_circuits(ssl);
    // N.B The C++ standard guarantees that all destructors are called here, so
    // this is fine.
    ssl->thrower();
  }

  return true;
}

template <unsigned long size, bool verifier>
static bool run_handshake_circuit_internal(
    EmpWrapperAG2PC *const circuit,
    const EmpWrapperAG2PCConstants::HandshakeCircuitIn &in,
    EmpWrapperAG2PCConstants::HandshakeCircuitOut &out) noexcept {

  std::array<uint8_t, size> in_arr{};
  unsigned pos{};

  // We assume that we're using SHA-256 here.
  static constexpr auto hash_size = 32;

  // The first input is the input hash.
  // Copy over the right amount of memory.
  if (!verifier) {
    std::copy(in.hash.cbegin(), in.hash.cend(), in_arr.begin());
  }

  // Move forward in the buffer. We'll do this until the end to make sure we've
  // actually written properly.
  pos += hash_size;

  // First we need to generate the randomness. We'll do this in the
  // output buffer and then copy over.
  Util::generate_random_bytes<EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE>(
      out.xor_mask);

  std::fill(out.xor_mask.begin(), out.xor_mask.end(), 0);
  std::copy(out.xor_mask.cbegin(), out.xor_mask.cend(), in_arr.begin() + pos);
  pos += static_cast<unsigned>(EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE);

  assert(pos == 32 + EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE);

  BIGNUM *b = BN_new();

  // Our input circuits expect a little-endian input representation; thus, we
  // need to convert.
  if (!b || !BN_bin2bn(in.key_share.data(), in.key_share.size(), b) ||
      !BN_bn2le_padded(in_arr.data() + pos, in.key_share.size(), b)) {
    return false;
  }

  BN_free(b);

  // This cast is fine because the size can only correspond to a small secret
  // (256 bits, 384 bits etc).
  pos += static_cast<unsigned>(in.key_share.size());

  // We should have filled the whole array.
  assert(pos == in_arr.size());

  std::array<uint8_t, EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE>
      out_arr{};
  if (!circuit->derive_hs(in_arr, out_arr)) {
    return false;
  }

  // With the circuit done, the output depends on the caller.
  // If the caller is the prover/verifier, then they get the lower/upper 16
  // bytes of each 32 byte chunk up to the 160th byte. After that lives the
  // IV/key depending on the caller.
  unsigned offset = (verifier) ? 16 : 0;

  auto copy_func = [&](auto &dest, const unsigned inc) {
    std::copy(out_arr.cbegin() + offset,
              out_arr.cbegin() + offset + dest.size(), dest.begin());
    offset += inc;
  };

  // Each secret is half of the hash_size in size, since these are all evenly
  // split. However, the step size is exactly the same as hash_size.
  copy_func(out.dHE_share, hash_size);
  copy_func(out.CHTS_share, hash_size); // 32
  copy_func(out.SHTS_share, hash_size); // 64
  copy_func(out.dHS_share, hash_size);  // 96
  copy_func(out.MS_share, hash_size);   // 128
                                      // Offset here will be 160 for the prover
                                      // and 176 for the verifier, because of
  // the post increase. All of the bytes below 160 have been used, but those
  // after 160 haven't been touched.
  assert(offset == static_cast<unsigned>(160 + (verifier * 16)));

  // Reset the offset, so that we can actually copy the right bits.
  offset = 160;
  copy_func(out.fk_s, hash_size);

  // The next 128 bits are the AES key, always.
  // If the caller is the prover, then their output is just the
  // mask they fed in.
  copy_func(out.server_key_share, 16);

  // Now we need to copy over the IV, and then we should be done.
  copy_func(out.iv, 12);

  // We should be right at the end of the buffer.
  assert(offset == EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_OUTPUT_SIZE);

  // Now we need to apply the xor against each of the secrets to recover their
  // original values.
  unsigned mask_offset = 0;

  // N.B all secrets are 16 bytes here so we're fine.
  auto xor_func = [&](auto &dest,
                      const unsigned xor_size = sizeof(decltype(dest))) {
    for (unsigned i = 0; i < xor_size; i++) {
      dest[i] ^= out.xor_mask[i + mask_offset];
    }
    mask_offset += static_cast<unsigned>(xor_size);
  };

  xor_func(out.dHE_share);
  xor_func(out.CHTS_share);
  xor_func(out.SHTS_share);
  xor_func(out.dHS_share);
  xor_func(out.MS_share);

  // We don't need to do the mask portion.
  // mask_offset should be the HANDSHAKE_MASK_SIZE minus the mask that's for the
  // key.
  assert(mask_offset == EmpWrapperAG2PCConstants::HANDSHAKE_MASK_SIZE -
                            sizeof(out.server_key_share));

  // We're all done.
  return true;
}

bool ThreePartyHandshake::run_handshake_circuit(
    const EmpWrapperAG2PCConstants::HandshakeCircuitIn &in,
    EmpWrapperAG2PCConstants::HandshakeCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {
  // Really only one precondition here, which is that the circuit is nice.
  if (!circuit)
    return false;

  // Because the input arguments to the circuit functions are templates,
  // we dispatch here based on the circuit's size.
  switch (circuit->get_size()) {
  case 256:
    if (verifier) {
      return run_handshake_circuit_internal<
          EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE, true>(
          circuit, in, out);
    } else {
      return run_handshake_circuit_internal<
          EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_256_IN_SIZE, false>(
          circuit, in, out);
    }
  case 384:
    if (verifier) {
      return run_handshake_circuit_internal<
          EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_384_IN_SIZE, true>(
          circuit, in, out);
    } else {
      return run_handshake_circuit_internal<
          EmpWrapperAG2PCConstants::HANDSHAKE_SECRETS_384_IN_SIZE, false>(
          circuit, in, out);
    }
  default:
    return false;
  }
}
template <bool is_verifier>
static bool run_traffic_circuit_internal(
    const EmpWrapperAG2PCConstants::TrafficCircuitIn &in,
    EmpWrapperAG2PCConstants::TrafficCircuitOut &out,
    EmpWrapperAG2PC *const circuit) {

  // This function simply calls into the garbled circuit after appropriately
  // copying over the relevant input bits.
  EmpWrapperAG2PCConstants::derive_ts_input_type input{};
  unsigned offset{};

  // Both parties feed in their share of MS.
  std::copy(in.ms_share.begin(), in.ms_share.end(), input.begin());
  offset += sizeof(in.ms_share);

  if (!is_verifier) {
    // Copy over the hash input. Notably, the verifier does not do this as they
    // do not hold anything useful here.
    std::copy(in.hash.cbegin(), in.hash.cend(), input.begin() + offset);
  }

  // Both parties need to move forward.
  offset += sizeof(in.hash);

  // Generate the random mask too for both parties.
  Util::generate_random_bytes<sizeof(uint8_t) *
                              EmpWrapperAG2PCConstants::TRAFFIC_MASK_SIZE>(
      input.data() + offset);
  std::copy(input.cbegin() + offset, input.cend(), out.xor_mask.begin());

  assert(offset + out.xor_mask.size() ==
         EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_OUTPUT_SIZE);

  // Call into the circuit.
  EmpWrapperAG2PCConstants::derive_ts_output_type output;
  if (!circuit->derive_ts(input, output)) {
    return false;
  }

  // Now we need to copy over the output.
  // If the caller is not the verifier, then their output is just the mask that
  // they supplied earlier.
  offset = 0;
  if (!is_verifier) {
    // If the caller is not the verifier, then their output is just the mask
    // that they supplied earlier.
    std::copy(out.xor_mask.cbegin(),
              out.xor_mask.cbegin() + out.client_key_share.size(),
              out.client_key_share.begin());
    std::copy(out.xor_mask.cbegin() + out.client_key_share.size(),
              out.xor_mask.cend(), out.server_key_share.begin());

    // N.B This cast is fine: the size of the key share is small.
    offset = unsigned(out.client_key_share.size());
    std::copy(output.cbegin() + offset,
              output.cbegin() + offset + out.client_iv.size(),
              out.client_iv.begin());
    offset += out.client_iv.size() + out.server_key_share.size();
    std::copy(output.cbegin() + offset, output.cend(), out.server_iv.begin());
    offset += out.server_iv.size();
  } else {
    const auto copy_func = [&](auto &dest,
                               const unsigned inc = sizeof(decltype(dest))) {
      std::copy(output.cbegin() + offset,
                output.cbegin() + offset + dest.size(), dest.begin());
      offset += inc;
    };

    copy_func(out.client_key_share);
    copy_func(out.client_iv);
    assert(offset == 28);
    copy_func(out.server_key_share);
    copy_func(out.server_iv);
  }

  // Both should hit the end.
  assert(offset == EmpWrapperAG2PCConstants::TRAFFIC_SECRETS_OUTPUT_SIZE);
  return true;
}

bool ThreePartyHandshake::run_traffic_circuit(
    const EmpWrapperAG2PCConstants::TrafficCircuitIn &in,
    EmpWrapperAG2PCConstants::TrafficCircuitOut &out,
    EmpWrapperAG2PC *const circuit, const bool verifier) noexcept {

  if (!circuit) {
    return false;
  }

  if (verifier) {
    return run_traffic_circuit_internal<true>(in, out, circuit);
  } else {
    return run_traffic_circuit_internal<false>(in, out, circuit);
  }
}

bool ThreePartyHandshake::commit_to_server_certificate(bssl::SSL_HANDSHAKE *hs,
                                                       SSL *ssl) {

  if (!hs || !ssl) {
    return false;
  }

  SSL *verifier = ssl->verifier;
  // Just forward the handshake data to the other party. We also send over a
  // hash of our key share: we prove commitments to this later on during
  // attestation.
  bssl::Array<uint8_t> tmp_buffer;
  constexpr auto hash_size = 32; // SHA-256 Hash.
  const auto size = sizeof(Messaging::MessageHeaders) +
                    ssl->s3->read_buffer.span().size() + hash_size;

  if (!tmp_buffer.Init(size)) {
    return false;
  }

  bssl::ScopedEVP_MD_CTX hash_{};
  const auto *md = EVP_sha256();
  unsigned out_len{};
  std::array<uint8_t, hash_size> tmp;
  if (!EVP_DigestInit_ex(hash_.get(), md, nullptr) ||
      !EVP_DigestUpdate(hash_.get(), ssl->server_key_share.data(),
                        ssl->server_key_share.size()) ||
      !EVP_DigestFinal_ex(hash_.get(), tmp.data(), &out_len) ||
      out_len != hash_size) {
    return false;
  }

  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(
                      Messaging::MessageHeaders::CERTIFICATE_CTX_SEND)) ||
      !CBB_add_u64(cbb.get(), ssl->s3->hs_buf->length) ||
      !CBB_add_bytes(
          cbb.get(),
          reinterpret_cast<const uint8_t *>(ssl->s3->read_buffer.span().data()),
          sizeof(uint8_t) * ssl->s3->read_buffer.span().size()) ||
      !CBB_add_bytes(cbb.get(), reinterpret_cast<const uint8_t *>(tmp.data()),
                     sizeof(tmp)) ||
      !CBBFinishArray(cbb.get(), &tmp_buffer)) {
    return false;
  }

  const auto amount_written = SSL_write(verifier, tmp_buffer.data(),
                                        static_cast<int>(tmp_buffer.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, tmp_buffer.size());

  // In response we expect the following secrets:
  // 1) The CHTS share (128 bits)
  // 2) The SHTS share (128 bits).
  // So we're expecting 32 bytes + sizeof(Header) back.
  using HSO = EmpWrapperAG2PCConstants::HandshakeCircuitOut;
  constexpr auto buf_size = sizeof(HSO::CHTS_share) + sizeof(HSO::SHTS_share) +
                            sizeof(Messaging::MessageHeaders);

  static_assert(sizeof(HSO::CHTS_share) == sizeof(HSO::SHTS_share));
  // This is really ugly C++, but essentially it says "this is the size of the
  // array CHTS". This is done without constructing such an object.
  constexpr auto share_size = std::tuple_size_v<decltype(HSO::CHTS_share)>;

  // Space to read into.
  std::array<uint8_t, buf_size> buf_in;

  // Read in the header.
  const auto amount_read =
      SSL_read(verifier, buf_in.data(), static_cast<int>(buf_in.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_read, buf_in.size());

  // Extract out all the good bits.
  CBS in_cbs;
  CBS_init(&in_cbs, buf_in.data(), buf_in.size());
  uint8_t in_header;
  if (!CBS_get_u8(&in_cbs, &in_header) ||
      !Messaging::is_valid_header(in_header) ||
      static_cast<Messaging::MessageHeaders>(in_header) !=
          Messaging::MessageHeaders::CERTIFICATE_CTX_RECV) {
    return false;
  }

  // The first 16 bytes will be the bytes for the CHTS, and the next 16 will be
  // for the SHTS.
  auto &ir_chts = ssl->chts_share;
  auto &ir_shts = ssl->shts_share;

  auto chts = hs->client_handshake_secret();
  auto shts = hs->server_handshake_secret();

  // Arguably this check is a static condition, but it's better to check
  // here that this is true.
  if (ir_chts.size() != share_size || ir_shts.size() != share_size) {
    return false;
  }

  // As we got the "first half" of each key share we just need to copy over
  // the other share into the requisite place.
  if (chts.size() != 2 * share_size || shts.size() != 2 * share_size) {
    return false;
  }

  std::copy(ir_chts.cbegin(), ir_chts.cend(), chts.begin());
  std::copy(ir_shts.cbegin(), ir_shts.cend(), shts.begin());

  uint8_t tmp_share;

  for (unsigned i = 0; i < share_size; i++) {
    if (!CBS_get_u8(&in_cbs, &tmp_share)) {
      return false;
    }
    chts[i + share_size] = tmp_share;
  }

  for (unsigned i = 0; i < share_size; i++) {
    if (!CBS_get_u8(&in_cbs, &tmp_share)) {
      return false;
    }

    shts[i + share_size] = tmp_share;
  }

  // We reveal the keys when we derive the traffic keys.
  return true;
}

bool ThreePartyHandshake::derive_traffic_keys(bssl::SSL_HANDSHAKE *hs,
                                              SSL *ssl) {

  if (!hs || !ssl || !ssl->verifier) {
    return false;
  }

  // Alias.
  auto verifier = ssl->verifier;

  // We signal that we're ready to derive traffic secrets. This is just a single
  // header that we have to write.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // We have to make the header a big-endian value. You know, for compatibility.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!write_to.Init(sizeof(uint8_t))) {
    return false;
  }

  constexpr static auto header = Messaging::MessageHeaders::DERIVE_TS;

  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }

  // Now just write it.
  const auto amount_written =
      SSL_write(verifier, write_to.data(), sizeof(uint8_t));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, sizeof(uint8_t));
  // Now we'll just call the derivation routine directly.
  // We need to pack our inputs first.
  EmpWrapperAG2PCConstants::TrafficCircuitIn input;
  input.ms_share = ssl->ms_share;
  // We can fetch the hash directly.
  if (!Util::get_hash(&hs->transcript, input.hash)) {
    return false;
  }

  // Call the circuit.
  EmpWrapperAG2PCConstants::TrafficCircuitOut output;

  // N.B Again we wrap ssl->traffic_circuit in a unique_ptr so it is cleaned up
  // even in case of failure.
  auto circuit = std::unique_ptr<EmpWrapperAG2PC>(ssl->traffic_circuit);
  // Prevent double-free.
  ssl->traffic_circuit = nullptr;

  // False here means "not the verifier".
  if (!run_traffic_circuit(input, output, circuit.get(), false)) {
    return false;
  }

  // Copy the output secrets over.
  ssl->client_key_share = output.client_key_share;
  ssl->server_key_share = output.server_key_share;

  // Note: the +4s here are because the AES IV is 96 bits to begin with,
  // but we later expand this to 128 bits.
  std::copy(output.client_iv.cbegin(), output.client_iv.cend(),
            ssl->client_iv.begin() + 4);
  std::copy(output.server_iv.cbegin(), output.server_iv.cend(),
            ssl->server_iv.begin() + 4);

  // NOTE: in some testing situations we want to bail here.
  // We'll do that if the "thrower" is set.
  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::DERIVE_TS)) {
    delete_circuits(ssl);
    ssl->thrower();
  }

  return true;
}

bool ThreePartyHandshake::write_h6(SSL *ssl, bssl::Span<uint8_t> hash) {
  if (!ssl || !ssl->verifier) {
    return false;
  }

  // We just need to write the hash that produces SCV to the other party.
  // This is passed in to us via the hash span.
  SSL *verifier = ssl->verifier;
  const auto size = sizeof(Messaging::MessageHeaders) + sizeof(hash.size());
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> out_arr;
  if (!CBB_init(cbb.get(), size) || !out_arr.Init(size) ||
      !CBB_add_u8(cbb.get(),
                  static_cast<uint8_t>(Messaging::MessageHeaders::H6_SEND)) ||
      !CBB_add_u64(cbb.get(), hash.size()) ||
      !CBB_add_bytes(cbb.get(), hash.data(), hash.size()) ||
      !CBBFinishArray(cbb.get(), &out_arr)) {
    return false;
  }

  const auto amount_written =
      SSL_write(verifier, out_arr.data(), static_cast<int>(out_arr.size()));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, out_arr.size());

  return is_correct_header<Messaging::MessageHeaders::H6_RECV>(verifier);
}

static bool
run_gcm_share_circuit(const EmpWrapperAG2PCConstants::GCMCircuitIn &in,
                      EmpWrapperAG2PCConstants::GCMCircuitOut &out,
                      EmpWrapperAG2PC *const circuit) noexcept {

  EmpWrapperAG2PC::derive_gcm_input_type arr;
  memcpy(arr.data(), in.xor_mask.data(), sizeof(in.xor_mask));
  memcpy(arr.data() + in.xor_mask.size(), in.key_share.data(),
         sizeof(in.key_share));

  // This uses the fact that out.power_share is the exact right type.
  return circuit->derive_gcm_shares(arr, out.power_share);
}

template <bool is_verifier>
static bool
make_gcm_share(SSL *const ssl, const std::array<uint8_t, 16> &key_share,
               EmpWrapperAG2PC *const circuit,
               EmpWrapperAG2PCConstants::AESGCMBulkShareType &out_shares,
               uint64_t *bandwidth) noexcept {

  // Pack the data into the right types.
  EmpWrapperAG2PCConstants::GCMCircuitIn in;
  in.key_share = key_share;
  Util::generate_random_bytes<sizeof(in.xor_mask)>(in.xor_mask.data());
  EmpWrapperAG2PCConstants::GCMCircuitOut out;

  if (!run_gcm_share_circuit(in, out, circuit)) {
    return false;
  }

  // We now need to convert to an emp::block for the
  // input.
  const auto input = (is_verifier)
                         ? F2128_MTA::inv(F2128_MTA::arr_to_block(in.xor_mask))
                         : F2128_MTA::arr_to_block(out.power_share);

  // Now run the routine
  uint64_t m_bandwidth[2]{};
  const auto share =
      (is_verifier) ? F2128_MTA::generate_shares_verifier_batched(
                          *ssl, input, m_bandwidth[0])
                    : F2128_MTA::generate_shares_prover_batched(*ssl, input,
                                                                m_bandwidth[1]);

  m_bandwidth[0] += m_bandwidth[1];
  if (is_verifier) {
    uint64_t tmp_bandwidth;
    if (SSL_read(ssl, &tmp_bandwidth, sizeof(tmp_bandwidth)) !=
        sizeof(tmp_bandwidth)) {
      return false;
    }

    if (bandwidth) {
      *bandwidth = tmp_bandwidth + m_bandwidth[0];
    }
  } else {
    if (SSL_write(ssl, &m_bandwidth[0], sizeof(m_bandwidth[0])) !=
        sizeof(m_bandwidth[0])) {
      return false;
    }
  }

  // Copy over.
  memcpy(out_shares.data(), share.data(), sizeof(share));
  return true;
}

bool ThreePartyHandshake::make_gcm_shares(
    SSL *const ssl, const std::array<uint8_t, 16> &ckey_share,
    const std::array<uint8_t, 16> &skey_share, EmpWrapperAG2PC *const circuit,
    EmpWrapperAG2PCConstants::AESGCMBulkShareType &cgcm_share,
    EmpWrapperAG2PCConstants::AESGCMBulkShareType &sgcm_share,
    uint64_t *bandwidth) noexcept {
  if (!ssl || !circuit) {
    return false;
  }

  // We do the client share first and then the server share. To make life
  // neater, these are done in subroutines.
  return make_gcm_share<true>(ssl, ckey_share, circuit, cgcm_share,
                              bandwidth) &&
         make_gcm_share<true>(ssl, skey_share, circuit, sgcm_share, bandwidth);
}

bool ThreePartyHandshake::derive_gcm_shares(SSL *const ssl) noexcept {
  if (!ssl || !ssl->verifier) {
    return false;
  }

  // Alias.
  auto verifier = ssl->verifier;

  // Tell the verifier we want to make gcm shares.
  // We signal that we're ready to derive traffic secrets. This is just a single
  // header that we have to write.
  constexpr auto expected_size = sizeof(Messaging::MessageHeaders);
  static_assert(expected_size == sizeof(uint8_t),
                "Error: sizeof(Messaging::MessageHeaders) is no longer "
                "sizeof(uint8_t): have you updated this code?");

  // We have to make the header a big-endian value. You know, for compatibility.
  bssl::ScopedCBB cbb;
  bssl::Array<uint8_t> write_to;
  if (!write_to.Init(sizeof(uint8_t))) {
    return false;
  }

  constexpr static auto header = Messaging::MessageHeaders::GCM_SHARE_START;

  if (!CBB_init(cbb.get(), sizeof(uint8_t)) ||
      !CBB_add_u8(cbb.get(), static_cast<uint8_t>(header)) ||
      !CBBFinishArray(cbb.get(), &write_to)) {
    return false;
  }

  // Now just write it.
  const auto amount_written =
      SSL_write(verifier, write_to.data(), sizeof(uint8_t));
  RETURN_FALSE_IF_SSL_FAILED(amount_written, sizeof(uint8_t));

  // We can actually just call the helper function.
  const auto worked =
      make_gcm_share<false>(verifier, ssl->client_key_share, ssl->gcm_circuit,
                            ssl->cgcm_share, nullptr) &&
      make_gcm_share<false>(verifier, ssl->server_key_share, ssl->gcm_circuit,
                            ssl->sgcm_share, nullptr);

  if (!worked) {
    return false;
  }

  // There's no need to rederive the GCM shares.
  delete ssl->gcm_circuit;

  if (ssl->thrower &&
      ssl->throw_state ==
          static_cast<uint8_t>(Messaging::MessageHeaders::GCM_SHARE_DONE)) {
    delete_circuits(ssl);
    ssl->thrower();
  }

  return true;
}

#undef RETURN_FALSE_IF_SSL_FAILED
