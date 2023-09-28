#include "EmpWrapperAG2PC.hpp"
/*
  Warning to any future readers of this code: there's a potential headache in
  this code that you'd do well to keep in mind.

  EMP treats all booleans as individual bits. In other words, if you want to
  pass 128 bits to emp (e.g from std::array<uint8_t, 16>) then you need to
  manually pack them into an array of bools (e.g to std::array<bool, 128>). This
  can cause headaches if you aren't careful with parameters: as a general rule
  of thumb, every function in this file expects the `output_size` to refer to
  the number of _bytes_ in the output.

  An example of this can be seen in evaluate_circuit_internal: the temp_out
  array is scaled by CHAR_BIT so that EMP can represent each element in this
  way.

  If you get this wrong you're likely to have segfaults and other headaches:
  most notably, you'll almost certainly get stack overruns. This will probably
  manifest when the function returns, so be aware.
 */
EmpWrapperAG2PC::EmpWrapperAG2PC(SSL *const ssl,
                                 const char *const filepath) noexcept
    : wrapper{ssl}, addr{&wrapper, &wrapper},
      circuit{(Util::is_valid_filepath(filepath), filepath)}, twopc{nullptr},
      aes{nullptr}, gcm{nullptr}, secret_size{get_secret_size(filepath)} {}

template <unsigned long input_size, unsigned long output_size>
bool EmpWrapperAG2PC::exec_small_internal(
    const std::array<uint8_t, input_size> &in_secret,
    std::array<uint8_t, output_size> &output) noexcept {
  // Note: now we need to turn the size into the bit size. This is the same as
  // multiplying through here by CHAR_BIT, which (we assume) is 8.
  static_assert(CHAR_BIT == 8, "Error: this function expects CHAR_BIT == 8");
  assert(type != CircuitType::NONE);
  /*
  assert(type == CircuitType::SINGLE || type == CircuitType::AES ||
         type == CircuitType::GCM || type == CircuitType::GCM_VFY);
  */
  // WARNING: this might be confusing!
  // Essentially, emp-ag2pc packs its input bits in a particular way. In
  // particular, Bob's inputs are kept in the first n1 entries (e.g [0, n1)) and
  // Alice's inputs are kept in the range [n1, n1+n2). This has several
  // implications, but one is that both parties must supply the same input
  // buffer size to prevent out-of-bound reads. Note that this also has
  // implications for the size of each parties' inputs: because Alice is assumed
  // to have `n2` bits of input, we require that the first set of inputs (e.g
  // what would actually be Alice's inputs) are greater than or equal to n1.
  // This is to prevent circuit clashes, and it's an annoying bug to circumvent.
  // Thankfully the 2PC object stores which party we are, which we can expose
  // here.
  std::array<bool, 2 * CHAR_BIT * input_size> as_bool{};
  const auto mode = [&]() -> int {
    switch (type) {
    case CircuitType::SINGLE:
      return twopc->party;
    case CircuitType::AES:
      return aes->party;
    case CircuitType::GCM:
      return gcm->party;
    case CircuitType::GCM_VFY:
      return gcm_vfy->party;
    case CircuitType::GCM_TAG:
      return gcm_tag->party;
    default:
      assert(false);
      __builtin_unreachable();
    }
  }();

  // N.B The * CHAR_BIT here is definitely needed, or you'll end up with
  // overlapping secrets.
  Util::convert_uint8_to_bool<input_size>(
      in_secret.data(),
      as_bool.data() + ((mode == emp::ALICE) * CHAR_BIT * input_size));
  // N.B This fill isn't strictly necessary, but tools like Valgrind will
  // complain about it if we don't do this.
  std::fill(output.begin(), output.end(), 0);
  // N.B temp_out needs to be scaled by CHAR_BIT because emp stores
  // each output bit as a separate bool (see top of file doc).
  std::array<bool, CHAR_BIT * output_size> temp_out{};
  // N.B The hardcoded true here means that Alice gets the output too.
  switch (type) {
  case CircuitType::SINGLE:
    twopc->online(as_bool.data(), temp_out.data(), true);
    break;
  case CircuitType::AES:
    aes->online(as_bool.data(), temp_out.data());
    break;
  case CircuitType::GCM:
    gcm->online(as_bool.data(), temp_out.data());
    break;
  case CircuitType::GCM_TAG:
    gcm_tag->online(as_bool.data(), temp_out.data());
    break;
  case CircuitType::GCM_VFY:
    gcm_vfy->online(as_bool.data(), temp_out.data());
    break;
  default:
    assert(false);
    __builtin_unreachable();
  }

  // Emp's amortized circuits don't output for ALICE. We'll fix that by sending
  // them over.
  auto post_proc = [&]() {
    // Convert the output.
    unsigned curr{};
    for (unsigned i = 0; i < output_size; i++) {
      uint8_t tmp{};
      for (unsigned j = 0; j < 8; j++) {
        tmp += static_cast<uint8_t>(temp_out[curr] << j);
        ++curr;
      }

      output[i] = tmp;
    }
  };

  // In single iteration circuits, both parties receive the output
  // automatically, so we can just post-process.
  if (type == CircuitType::SINGLE) {
    post_proc();
    return true;
  }

  // Otherwise, only Bob receives the output. We forward the result
  // to Alice manually in that case.
  if (mode == emp::BOB) {
    post_proc();
    // Send the result to Alice and bail.
    wrapper.send_data_internal(output.data(), output.size());
    // Explicitly flush to prevent hangs.
    wrapper.flush();
  } else {
    // Receive the output from Bob (see above).
    wrapper.recv_data_internal(output.data(), output.size());
  }

  ++run_times;
  return true;
}

bool EmpWrapperAG2PC::make_tag(
    const EmpWrapperAG2PC::aes_gcm_tag_input_type &in,
    EmpWrapperAG2PC::aes_gcm_tag_output_type &out) noexcept {
  if (run_times == tag_iters) {
    do_preproc();
  }
  return exec_small_internal(in, out);
}

bool EmpWrapperAG2PC::verify_tag(
    const EmpWrapperAG2PC::aes_gcm_vfy_input_type &in,
    EmpWrapperAG2PC::aes_gcm_vfy_output_type &out) noexcept {
  if (run_times == vfy_iters) {
    do_preproc();
  }
  return exec_small_internal(in, out);
}

bool EmpWrapperAG2PC::derive_ts(
    const EmpWrapperAG2PC::derive_ts_input_type &in,
    EmpWrapperAG2PC::derive_ts_output_type &out) noexcept {
  if (run_times > 0) {
    do_preproc();
  }
  return exec_small_internal(in, out);
}

bool EmpWrapperAG2PC::derive_hs(
    const EmpWrapperAG2PC::derive_hs_256_input_type &in,
    EmpWrapperAG2PC::derive_hs_output_type &out) noexcept {
  assert(secret_size == 256);
  if (run_times > 0) {
    do_preproc();
  }
  return exec_small_internal(in, out);
}

bool EmpWrapperAG2PC::derive_hs(
    const EmpWrapperAG2PC::derive_hs_384_input_type &in,
    EmpWrapperAG2PC::derive_hs_output_type &out) noexcept {
  assert(secret_size == 384);
  if (run_times > 0) {
    do_preproc();
  }
  return exec_small_internal(in, out);
}

bool EmpWrapperAG2PC::derive_gcm_shares(
    const EmpWrapperAG2PC::derive_gcm_input_type &in,
    EmpWrapperAG2PC::derive_gcm_secrets_output_type &out) noexcept {

  if (run_times == EmpWrapperAG2PC::gcm_iters) {
    do_preproc();
  }

  return exec_small_internal(in, out);
}

bool EmpWrapperAG2PC::do_joint_aes(
    const EmpWrapperAG2PC::aes_joint_input_type &in,
    EmpWrapperAG2PC::aes_joint_output_type &out) noexcept {

  if (run_times == EmpWrapperAG2PC::aes_iters) {
    do_preproc();
  }

  return exec_small_internal(in, out);
}

void EmpWrapperAG2PC::set_twopc(const int mode, const int tag) noexcept {
  assert(mode == emp::ALICE || mode == emp::BOB);
  assert(type == CircuitType::NONE);
  twopc.reset(new SingleCircuitType(addr, mode, tag, &circuit));
  type = CircuitType::SINGLE;
}

void EmpWrapperAG2PC::set_gcm(const int mode, const int tag) noexcept {
  assert(mode == emp::ALICE || mode == emp::BOB);
  assert(type == CircuitType::NONE);
  gcm.reset(new GCMCircuitType(addr, mode, tag, &circuit));
  type = CircuitType::GCM;
}

void EmpWrapperAG2PC::set_gcm_tag(const int mode, const int tag) noexcept {
  assert(mode == emp::ALICE || mode == emp::BOB);
  assert(type == CircuitType::NONE);
  gcm_tag.reset(new GCMTagCircuitType(addr, mode, tag, &circuit));
  type = CircuitType::GCM_TAG;
}

void EmpWrapperAG2PC::set_gcm_vfy(const int mode, const int tag) noexcept {
  assert(mode == emp::ALICE || mode == emp::BOB);
  assert(type == CircuitType::NONE);
  gcm_vfy.reset(new GCMVfyCircuitType(addr, mode, tag, &circuit));
  type = CircuitType::GCM_VFY;
}

void EmpWrapperAG2PC::set_aes(const int mode, const int tag) noexcept {
  assert(mode == emp::ALICE || mode == emp::BOB);
  assert(type == CircuitType::NONE);
  aes.reset(new AESCircuitType(addr, mode, tag, &circuit));
  type = CircuitType::AES;
}

EmpWrapperAG2PC *
EmpWrapperAG2PC::build_derive_ts_circuit(SSL *const ssl, const int mode,
                                         const int tag) noexcept {
  auto res = new EmpWrapperAG2PC(ssl, EmpWrapperAG2PCConstants::TS_FILEPATH);
  res->set_twopc(mode, tag);
  return res;
}

EmpWrapperAG2PC *
EmpWrapperAG2PC::build_joint_aes_circuit(SSL *const ssl, const int mode,
                                         const int tag) noexcept {

  auto res = new EmpWrapperAG2PC(
      ssl, EmpWrapperAG2PCConstants::AES_CTR_JOINT_FILEPATH);
  res->set_aes(mode, tag);
  return res;
}

EmpWrapperAG2PC *
EmpWrapperAG2PC::build_gcm_tag_circuit(SSL *const ssl, const int mode,
                                       const int tag) noexcept {
  auto res =
      new EmpWrapperAG2PC(ssl, EmpWrapperAG2PCConstants::AES_GCM_TAG_FILEPATH);
  res->set_gcm_tag(mode, tag);
  return res;
}

EmpWrapperAG2PC *
EmpWrapperAG2PC::build_gcm_vfy_circuit(SSL *const ssl, const int mode,
                                       const int tag) noexcept {
  auto res =
      new EmpWrapperAG2PC(ssl, EmpWrapperAG2PCConstants::AES_GCM_VFY_FILEPATH);
  res->set_gcm_vfy(mode, tag);
  return res;
}

EmpWrapperAG2PC *EmpWrapperAG2PC::build_gcm_circuit(SSL *const ssl,
                                                    const int mode,
                                                    const int tag) noexcept {
  auto res = new EmpWrapperAG2PC(ssl, EmpWrapperAG2PCConstants::GCM_FILEPATH);
  res->set_gcm(mode, tag);
  return res;
}

EmpWrapperAG2PC *EmpWrapperAG2PC::build_derive_hs_256(SSL *const ssl,
                                                      const int mode,
                                                      const int tag) noexcept {
  auto res =
      new EmpWrapperAG2PC(ssl, EmpWrapperAG2PCConstants::CHS_256_FILEPATH);
  res->set_twopc(mode, tag);
  return res;
}

EmpWrapperAG2PC *EmpWrapperAG2PC::build_derive_hs_384(SSL *const ssl,
                                                      const int mode,
                                                      const int tag) noexcept {
  auto res =
      new EmpWrapperAG2PC(ssl, EmpWrapperAG2PCConstants::CHS_384_FILEPATH);
  res->set_twopc(mode, tag);
  return res;
}

EmpWrapperAG2PC *EmpWrapperAG2PC::build_derive_hs_circuit(
    SSL *const ssl, const uint16_t id, const int mode, const int tag) noexcept {

  if (id == 0)
    return nullptr;
  // We only support these curves in circuits at the moment.
  switch (id) {
  case SSL_CURVE_SECP256R1:
    return EmpWrapperAG2PC::build_derive_hs_256(ssl, mode, tag);
  case SSL_CURVE_SECP384R1:
    return EmpWrapperAG2PC::build_derive_hs_384(ssl, mode, tag);
  default:
    std::cerr << "Circuit requested for: " << id << " but not supported"
              << std::endl;
    std::abort();
  }
}

void EmpWrapperAG2PC::do_preproc_indep() noexcept {
  switch (type) {
  case CircuitType::SINGLE:
    twopc->function_independent();
    return;
  case CircuitType::AES:
    aes->function_independent();
    return;
  case CircuitType::GCM:
    gcm->function_independent();
    return;
  case CircuitType::GCM_VFY:
    gcm_vfy->function_independent();
    return;
  case CircuitType::GCM_TAG:
    gcm_tag->function_independent();
    return;
  default:
    assert(false);
  }
}

void EmpWrapperAG2PC::do_preproc_dep() noexcept {
  run_times = 0;
  switch (type) {
  case CircuitType::SINGLE:
    twopc->function_dependent();
    return;
  case CircuitType::AES:
    aes->function_dependent();
    return;
  case CircuitType::GCM:
    gcm->function_dependent();
    return;
  case CircuitType::GCM_VFY:
    gcm_vfy->function_dependent();
    return;
  case CircuitType::GCM_TAG:
    gcm_tag->function_dependent();
    return;
  default:
    assert(false);
  }
}

void EmpWrapperAG2PC::do_preproc() noexcept {
  do_preproc_indep();
  do_preproc_dep();
}
