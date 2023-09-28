#ifndef INCLUDED_F2128MTA_HPP
#error Do not include F2128MtA.inl without F2128MtA.hpp
#endif

template <unsigned long len>
constexpr unsigned F2128_MTA::InnerType<len>::size() noexcept {
  return len;
}

template <unsigned long len>
const emp::block &
F2128_MTA::InnerType<len>::operator[](const unsigned index) const noexcept {
  return elem[index];
}

template <unsigned long len>
emp::block &
F2128_MTA::InnerType<len>::operator[](const unsigned index) noexcept {
  return elem[index];
}

template <unsigned long len>
emp::block *F2128_MTA::InnerType<len>::data() noexcept {
  return &elem[0];
}

template <unsigned long len>
const emp::block *F2128_MTA::InnerType<len>::data() const noexcept {
  return &elem[0];
}

emp::block F2128_MTA::arr_to_block(const std::array<uint8_t, 16> &in) noexcept {
  return _mm_setr_epi8(static_cast<char>(in[0]), static_cast<char>(in[1]),
                       static_cast<char>(in[2]), static_cast<char>(in[3]),
                       static_cast<char>(in[4]), static_cast<char>(in[5]),
                       static_cast<char>(in[6]), static_cast<char>(in[7]),
                       static_cast<char>(in[8]), static_cast<char>(in[9]),
                       static_cast<char>(in[10]), static_cast<char>(in[11]),
                       static_cast<char>(in[12]), static_cast<char>(in[13]),
                       static_cast<char>(in[14]), static_cast<char>(in[15]));
}

std::array<uint8_t, 16> F2128_MTA::block_to_arr(const emp::block in) noexcept {
  return std::array<uint8_t, 16>{
      static_cast<uint8_t>(_mm_extract_epi8(in, 0)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 1)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 2)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 3)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 4)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 5)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 6)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 7)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 8)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 9)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 10)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 11)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 12)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 13)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 14)),
      static_cast<uint8_t>(_mm_extract_epi8(in, 15))};
}

emp::block F2128_MTA::mul(const emp::block a, const emp::block b) noexcept {
  // This code comes from the Intel GCM reference implementation c.f
  // https://www.intel.com/content/dam/develop/public/us/en/documents/carry-less-multiplication-instruction.pdf
  // Algorithm 7.
  emp::block tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9, tmp10, tmp11, tmp12;
  emp::block XMMMASK = _mm_setr_epi32(-1, 0x0, 0x0, 0x0);
  tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
  tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
  tmp4 = _mm_shuffle_epi32(a, 78);
  tmp5 = _mm_shuffle_epi32(b, 78);
  tmp4 = _mm_xor_si128(tmp4, a);
  tmp5 = _mm_xor_si128(tmp5, b);
  tmp4 = _mm_clmulepi64_si128(tmp4, tmp5, 0x00);
  tmp4 = _mm_xor_si128(tmp4, tmp3);
  tmp4 = _mm_xor_si128(tmp4, tmp6);
  tmp5 = _mm_slli_si128(tmp4, 8);
  tmp4 = _mm_srli_si128(tmp4, 8);
  tmp3 = _mm_xor_si128(tmp3, tmp5);
  tmp6 = _mm_xor_si128(tmp6, tmp4);
  tmp7 = _mm_srli_epi32(tmp6, 31);
  tmp8 = _mm_srli_epi32(tmp6, 30);
  tmp9 = _mm_srli_epi32(tmp6, 25);
  tmp7 = _mm_xor_si128(tmp7, tmp8);
  tmp7 = _mm_xor_si128(tmp7, tmp9);
  tmp8 = _mm_shuffle_epi32(tmp7, 147);
  tmp7 = _mm_and_si128(XMMMASK, tmp8);
  tmp8 = _mm_andnot_si128(XMMMASK, tmp8);
  tmp3 = _mm_xor_si128(tmp3, tmp8);
  tmp6 = _mm_xor_si128(tmp6, tmp7);
  tmp10 = _mm_slli_epi32(tmp6, 1);
  tmp3 = _mm_xor_si128(tmp3, tmp10);
  tmp11 = _mm_slli_epi32(tmp6, 2);
  tmp3 = _mm_xor_si128(tmp3, tmp11);
  tmp12 = _mm_slli_epi32(tmp6, 7);
  tmp3 = _mm_xor_si128(tmp3, tmp12);
  return _mm_xor_si128(tmp6, tmp3);
}

emp::block F2128_MTA::inv(const emp::block a) noexcept {
  emp::block curr = emp::makeBlock(0, 1);
  for (unsigned i = 0; i < 127; i++) {
    curr = mul(curr, a);
    curr = mul(curr, curr);
  }
  return curr;
}

template <int bits>
emp::block F2128_MTA::shift_left_bits(const emp::block in) noexcept {
  // This code (and the shift right bits function) comes from
  // https://stackoverflow.com/questions/17610696/shift-a-m128i-of-n-bits
  if (bits >= 64) {
    return _mm_slli_si128(_mm_slli_si128(in, 8), bits - 64);
  }

  emp::block v1, v2;
  v1 = _mm_slli_epi64(in, bits);
  v2 = _mm_slli_si128(in, 8);
  v2 = _mm_srli_epi64(v2, 64 - bits);
  return _mm_or_si128(v1, v2);
}

template <int bits>
emp::block F2128_MTA::shift_right_bits(const emp::block in) noexcept {
  if (bits >= 64) {
    return _mm_srli_epi64(_mm_srli_si128(in, 8), bits - 64);
  }

  emp::block v1 = _mm_srli_epi64(in, bits);
  emp::block v2 = _mm_srli_si128(in, 8);
  v2 = _mm_slli_epi64(v2, 64 - bits);
  return _mm_or_si128(v1, v2);
}

std::unique_ptr<F2128_MTA::AType> F2128_MTA::generate_a() noexcept {
  auto a = new AType();
  Util::generate_random_bytes<sizeof(AType)>(a->data());
  return std::unique_ptr<AType>(a);
}

std::unique_ptr<F2128_MTA::AlphaType>
F2128_MTA::produce_alpha(const AType &a_tilde, const AType &a_hat) noexcept {
  auto alpha = new AlphaType();
  // The elements are actually repeated in batches of `chi` (i.e
  // gadget_element). The whole thing is repeated `l` times.
  unsigned curr = 0;
  for (unsigned i = 0; i < a_tilde.size(); i++) {
    for (unsigned j = 0; j < gadget_elements; j++) {
      (*alpha)[curr + 0] = a_tilde[i];
      (*alpha)[curr + 1] = a_hat[i];
      curr += 2;
    }
    assert(curr == (2 * i + 2) * gadget_elements);
  }

  assert(curr == alpha->size());
  return std::unique_ptr<F2128_MTA::AlphaType>(alpha);
}

F2128_MTA::BetaType F2128_MTA::generate_beta() noexcept {
  BetaType beta;
  Util::generate_random_bytes<sizeof(beta)>(&beta);
  return beta;
}

F2128_MTA::BType F2128_MTA::produce_b(const GadgetType &gadget,
                                      const BetaType &beta) noexcept {
  BType out;
  for (unsigned i = 0; i < F2128_MTA::l; i++) {
    out[i] = dot_product(&beta[3 * i], gadget);
  }
  return out;
}

F2128_MTA::GadgetType F2128_MTA::generate_gadget_r() noexcept {
  GadgetType g_r;
  Util::generate_random_bytes<sizeof(GadgetType)>(g_r.data());
  return g_r;
}

F2128_MTA::GType F2128_MTA::generate_g(const GadgetType &g_r) noexcept {
  GType g;

  // The first 128 elements are just various powers of 2, and the rest are
  // just the gadget elements.
  emp::block curr = emp::makeBlock(0, 1);
  for (unsigned i = 0; i < 128; i++) {
    g[i] = curr;
    curr = shift_left_bits<1>(curr);
  }

  for (unsigned i = 0; i < g_r.size(); i++) {
    g[128 + i] = g_r[i];
  }

  return g;
}

emp::block F2128_MTA::dot_product(const emp::block *const gamma,
                                  const GadgetType &gadget) noexcept {

  assert(gamma);
  static_assert(GadgetType::size() == 3 * 128);
  emp::block dot_prod = emp::zero_block;
  for (unsigned i = 0; i < 3; i++) {
    auto curr = gamma[i];
    for (unsigned j = 0; j < 128; j++) {
      if (emp::getLSB(curr)) {
        dot_prod ^= gadget[i * 128 + j];
      }
      curr = shift_right_bits<1>(curr);
    }
  }
  return dot_prod;
}

F2128_MTA::EncodeType F2128_MTA::encode(const emp::block in,
                                        const GadgetType &gadget) noexcept {
  EncodeType out;

  // This only works if `EncodeType` is 4 lots of 128 bits.
  static_assert(sizeof(EncodeType) == sizeof(emp::block) * 4);

  // We treat gamma separately, for reasons that will be apparent later.
  emp::block gamma[3];
  // Generate the random gamma vector. This is put at the end of `out`
  Util::generate_random_bytes<sizeof(gamma)>(&gamma);
  memcpy(&out[1], &gamma, sizeof(gamma));

  // The inner product here is treated as a series of multiplications over
  // GF(2^128), using the GCM polynomial. This is just because later on we need
  // to reconstruct this by doing a multiplication over GF(2^128). This means
  // that we need to treat each bit of out[1:3] as separate elements over
  // GF(2^128).
  static_assert(sizeof(GadgetType) % sizeof(emp::block) == 0);
  static_assert(sizeof(GadgetType) * CHAR_BIT % 128 == 0);

  // Calculate the subtraction. This is just an XOR.
  out[0] = in ^ F2128_MTA::dot_product(gamma, gadget);
  return out;
}

F2128_MTA::TType F2128_MTA::generate_pads() noexcept {
  TType elems;
  Util::generate_random_bytes<sizeof(elems)>(elems.data());
  return elems;
}

std::unique_ptr<F2128_MTA::BatchedTType>
F2128_MTA::generate_batched_pads() noexcept {
  auto elems = new BatchedTType();
  assert(elems);
  Util::generate_random_bytes<sizeof(BatchedTType)>(elems->data());
  return std::unique_ptr<BatchedTType>(elems);
}

emp::block F2128_MTA::generate_alpha_hat() noexcept {
  emp::block alpha_hat;
  Util::generate_random_bytes<sizeof(alpha_hat)>(&alpha_hat);
  return alpha_hat;
}

std::unique_ptr<F2128_MTA::BatchedOTType>
F2128_MTA::prepare_batched_pairs(const AlphaType &alpha,
                                 const BatchedTType &batched_ts) noexcept {

  auto elems = std::make_unique<BatchedOTType>();

  // The elems[0]'s are just the pads.
  memcpy((*elems)[0].data(), batched_ts.data(), sizeof(batched_ts));

  for (unsigned i = 0; i < BatchedTType::size(); i += 2) {
    (*elems)[1][i] = alpha[i] ^ batched_ts[i];
    (*elems)[1][i + 1] = alpha[i + 1] ^ batched_ts[i + 1];
  }

  return elems;
}

F2128_MTA::OTType F2128_MTA::prepare_pairs(const emp::block alpha,
                                           const emp::block alpha_hat,
                                           const TType &ts) noexcept {

  OTType elems;
  static_assert(sizeof(elems[0]) == sizeof(ts));

  // The elems[0] are just the pads.
  memcpy(elems[0].data(), ts.data(), sizeof(ts));

  // The elems[1] are alpha[i] - ts[i], but including alpha_hat too.
  // Make sure the loop below actually covers all of the entries.
  static_assert(2 * batch_size == TType::size());

  for (unsigned i = 0; i < TType::size(); i += 2) {
    elems[1][i] = alpha ^ ts[i];
    elems[1][i + 1] = alpha_hat ^ ts[i + 1];
  }

  return elems;
}

F2128_MTA::OTOutType F2128_MTA::get_sender_out(const TType &ts) noexcept {
  OTOutType out;
  for (unsigned i = 0; i < batch_size; i++) {
    out[0][i] = ts[2 * i];
    out[1][i] = ts[2 * i + 1];
  }
  return out;
}

std::unique_ptr<F2128_MTA::BatchedOTOutType>
F2128_MTA::get_sender_batched_out(const BatchedTType &ts) noexcept {
  BatchedOTOutType *out = new BatchedOTOutType();
  for (unsigned i = 0; i < number_of_batched_ots / 2; i++) {
    (*out)[0][i] = ts[2 * i];
    (*out)[1][i] = ts[2 * i + 1];
  }
  return std::unique_ptr<BatchedOTOutType>(out);
}

template <typename OTSocket>
void F2128_MTA::play_batched_sender(OTSocket &socket,
                                    const BatchedOTType &alpha) noexcept {
  socket.send(alpha[0].data(), alpha[1].data(),
              static_cast<int64_t>(number_of_batched_ots));
}

template <typename OTSocket>
void F2128_MTA::play_sender(OTSocket &socket, const OTType &alpha) noexcept {
  // Here we can just send out from `alpha`.
  socket.send(alpha[0].data(), alpha[1].data(),
              static_cast<int64_t>(number_of_ots));
}

F2128_MTA::ChoiceBitType
F2128_MTA::get_choice_bits(const EncodeType &omega) noexcept {

  ChoiceBitType choice_bits;
  uint64_t as_uint64[2];

  unsigned curr = 0;
  const auto extract_from = [&curr, &choice_bits](uint64_t val) {
    for (unsigned j = 0; j < 64; j++) {
      choice_bits[curr] = choice_bits[curr + 1] = (val & 1);
      assert(choice_bits[curr] == choice_bits[curr + 1]);
      val >>= 1;
      curr += 2;
    }
  };

  for (unsigned i = 0; i < EncodeType::size(); i++) {
    // Copy over the value in omega.
    memcpy(as_uint64, &omega[i], sizeof(omega[i]));
    extract_from(as_uint64[0]);
    extract_from(as_uint64[1]);
    assert(curr == (i + 1) * 256);
  }

  return choice_bits;
}

std::unique_ptr<F2128_MTA::BatchedChoiceBitType>
F2128_MTA::get_batched_choice_bits(const BetaType &beta) noexcept {
  BatchedChoiceBitType *choice_bits = new BatchedChoiceBitType();
  // The derivation for this is: beta contains emp::blocks. Each emp::block
  // contains CHAR_BIT * sizeof(emp::block) bits, and we need to represent each
  // bit twice.
  static_assert(sizeof(BatchedChoiceBitType) ==
                    2 * CHAR_BIT * sizeof(emp::block) * BetaType::size(),
                "Error: BatchedChoiceBitType is the wrong size.");
  unsigned curr = 0;
  const auto extract_from = [&curr, &choice_bits](uint64_t val) {
    for (unsigned j = 0; j < 64; j++) {
      assert(choice_bits->size() > curr + 1);
      (*choice_bits)[curr] = (*choice_bits)[curr + 1] = (val & 1);
      assert((*choice_bits)[curr] == (*choice_bits)[curr + 1]);
      val >>= 1;
      curr += 2;
    }
  };

  uint64_t as_uint64[2];
  for (unsigned i = 0; i < BetaType::size(); i++) {
    // Copy over the value in beta.
    memcpy(as_uint64, &beta[i], sizeof(beta[i]));
    extract_from(as_uint64[0]);
    extract_from(as_uint64[1]);
    assert(curr == (i + 1) * 256);
  }

  return std::unique_ptr<BatchedChoiceBitType>(choice_bits);
}

template <typename OTSocket>
std::unique_ptr<F2128_MTA::BatchedOTOutType>
F2128_MTA::play_batched_receiver(OTSocket &socket,
                                 const BatchedChoiceBitType &omega) noexcept {
  BatchedOTOutType *t_b = new BatchedOTOutType();
  emp::block *tmp_ot = new emp::block[number_of_batched_ots];
  socket.recv(tmp_ot, omega.data(),
              static_cast<int64_t>(number_of_batched_ots));
  for (unsigned i = 0; i < number_of_batched_ots; i += 2) {
    (*t_b)[0][i / 2] = tmp_ot[i + 0];
    (*t_b)[1][i / 2] = tmp_ot[i + 1];
  }
  delete[] tmp_ot;
  return std::unique_ptr<BatchedOTOutType>(t_b);
}

template <typename OTSocket>
std::unique_ptr<F2128_MTA::BatchedOTOutType>
F2128_MTA::play_batched_receiver(OTSocket &socket,
                                 const BetaType &omega) noexcept {
  const auto bits = get_batched_choice_bits(omega);
  return play_batched_receiver(socket, *bits);
}

template <typename OTSocket>
F2128_MTA::OTOutType
F2128_MTA::play_receiver(OTSocket &socket,
                         const ChoiceBitType &omega) noexcept {
  OTOutType t_b;

  // Place the results into a temporary array.
  emp::block tmp_ot[number_of_ots];
  socket.recv(tmp_ot, omega.data(), static_cast<int64_t>(number_of_ots));

  // Now we need to unpack each element into the right output
  for (unsigned i = 0; i < number_of_ots; i += 2) {
    t_b[0][i / 2] = tmp_ot[i + 0];
    t_b[1][i / 2] = tmp_ot[i + 1];
  }
  return t_b;
}

template <typename OTSocket>
F2128_MTA::OTOutType
F2128_MTA::play_receiver(OTSocket &socket, const EncodeType &omega) noexcept {

  // `omega` needs to be packed
  const auto choice_bits = get_choice_bits(omega);
  static_assert(choice_bits.size() == number_of_ots);
  return play_receiver(socket, choice_bits);
}

F2128_MTA::ChiType
F2128_MTA::generate_batched_randomness(SSL &ssl, const bool sender) noexcept {
  ChiType val;
  emp::block randomness[l];
  Util::generate_random_bytes<sizeof(randomness)>(&randomness);
  if (sender) {
    SSL_read(&ssl, &val[1], sizeof(val[1]));
    memcpy(&val[0], randomness, sizeof(randomness));
    SSL_write(&ssl, &val[0], sizeof(val[0]));
  } else {
    memcpy(&val[1], randomness, sizeof(randomness));
    SSL_write(&ssl, &randomness, sizeof(randomness));
    SSL_read(&ssl, &val[0], sizeof(val[0]));
  }
  return val;
}

F2128_MTA::RandomType
F2128_MTA::generate_randomness(SSL &ssl, const bool sender) noexcept {
  RandomType val;
  emp::block randomness;
  Util::generate_random_bytes<sizeof(emp::block)>(&randomness);

  if (sender) {
    // chi hat
    SSL_read(&ssl, &val[1], sizeof(val[1]));
    // chi
    val[0] = randomness;
    SSL_write(&ssl, &val[0], sizeof(val[0]));
  } else {
    // chi hat.
    val[1] = randomness;
    SSL_write(&ssl, &randomness, sizeof(randomness));
    SSL_read(&ssl, &val[0], sizeof(val[0]));
  }
  return val;
}

bool F2128_MTA::check_consistency(SSL &ssl, const OTOutType &t_b,
                                  const RandomType &chi,
                                  const ChoiceBitType &omega) noexcept {

  emp::block r[3];
  if (SSL_read(&ssl, &r, sizeof(r)) != sizeof(r)) {
    return false;
  }

  emp::block u = r[2];
  emp::block mask[2];
  mask[0] = emp::makeBlock(0, 0);
  mask[1] = emp::makeBlock(0, 1);

  bool correct = true;
  RType input;

  for (unsigned i = 0; i < batch_size; i++) {
    input[i] = (mul(chi[0], t_b[0][i]) ^ mul(chi[1], t_b[1][i]) ^
                mul(u, mask[omega[2 * i]]));
  }

  // Compute the hash
  emp::block hash[2];
  unsigned int out_size;
  if (!EVP_Digest(&input, sizeof(input), reinterpret_cast<uint8_t *>(&hash),
                  &out_size, EVP_sha256(), nullptr)) {
    correct = false;
  }

  if (correct && memcmp(r, hash, sizeof(emp::block) * 2) != 0) {
    correct = false;
  }

  if (SSL_write(&ssl, &correct, sizeof(correct)) != sizeof(correct)) {
    return false;
  }

  return correct;
}

bool F2128_MTA::check_consistency(SSL &ssl, const OTOutType &t_b,
                                  const RandomType &chi,
                                  const EncodeType &omega) noexcept {
  const auto choices = get_choice_bits(omega);
  return check_consistency(ssl, t_b, chi, choices);
}

bool F2128_MTA::check_consistency_batched(SSL &ssl, const BatchedOTOutType &t_b,
                                          const ChiType &chi,
                                          const BetaType &beta) noexcept {

  const auto as_bits = get_batched_choice_bits(beta);
  return check_consistency_batched(ssl, t_b, chi, *as_bits);
}

bool F2128_MTA::check_consistency_batched(
    SSL &ssl, const BatchedOTOutType &t_b, const ChiType &chi,
    const BatchedChoiceBitType &beta) noexcept {
  auto r = std::make_unique<BatchedRType>(BatchedRType());
  Util::process_data(&ssl, reinterpret_cast<char *>(r->data()),
                     sizeof(BatchedRType), SSL_read);

  bool correct = true;
  emp::block tmp;
  unsigned curr = 0;
  for (unsigned i = 0; i < gadget_elements; i++) {
    emp::block rhs = (*r)[curr];
    tmp = (*r)[curr + 1];
    for (unsigned j = 0; j < l; j++) {
      tmp ^= mul(chi[0][i], t_b[0][i * gadget_elements + j]) ^
             mul(chi[1][i], t_b[1][i * gadget_elements + j]);
      if (beta[i * gadget_elements + j]) {
        rhs ^= rhs;
      }
    }

    if (emp::cmpBlock(&tmp, &rhs, 1)) {
      correct = false;
    }

    curr += 2;
  }

  if (SSL_write(&ssl, &correct, sizeof(correct)) != sizeof(correct)) {
    return false;
  }

  return correct;
}

bool F2128_MTA::prove_consistency_batched(SSL &ssl, const AType &a_tilde,
                                          const AType &a_hat,
                                          const BatchedOTOutType &t_a,
                                          const ChiType &chi) noexcept {

  auto r = std::make_unique<BatchedRType>(BatchedRType());

  // N.B This is the other way around from the original paper.
  // This is because the BatchedOTOutType array is much larger
  // than the chi array, and thus reading it sensibly is more important
  // for performance.

  for (unsigned i = 0; i < gadget_elements; i++) {
    (*r)[2 * i + 0] = mul(chi[0][i], a_tilde[i]) ^ mul(chi[1][i], a_hat[i]);
    (*r)[2 * i + 1] = emp::zero_block;
  }

  for (unsigned j = 0; j < l; j++) {
    for (unsigned i = 0; i < gadget_elements; i++) {
      (*r)[2 * i + 1] ^= mul(chi[0][i], t_a[0][j * gadget_elements + i]) ^
                         mul(chi[1][i], t_a[1][j * gadget_elements + i]);
    }
  }

  // Make sure we can actually use SSL_write.
  static_assert(sizeof(BatchedRType) < SSL3_RT_MAX_PLAIN_LENGTH);
  if (SSL_write(&ssl, r->data(), sizeof(BatchedRType)) !=
      sizeof(BatchedRType)) {
    return false;
  }

  bool worked;
  if (SSL_read(&ssl, &worked, sizeof(bool)) != sizeof(worked)) {
    return false;
  }
  return worked;
}

bool F2128_MTA::prove_consistency(SSL &ssl, const emp::block alpha,
                                  const emp::block alpha_hat,
                                  const OTOutType &t_a,
                                  const RandomType &chi) noexcept {
  RType r;
  for (unsigned i = 0; i < batch_size; i++) {
    r[i] = mul(chi[0], t_a[0][i]) ^ mul(chi[1], t_a[1][i]);
  }

  emp::block arr[3];
  unsigned int out_size;
  if (!EVP_Digest(&r, sizeof(r), reinterpret_cast<uint8_t *>(&arr), &out_size,
                  EVP_sha256(), nullptr)) {
    return false;
  }

  // u
  arr[2] = mul(chi[0], alpha) ^ mul(chi[1], alpha_hat);

  if (SSL_write(&ssl, &arr, sizeof(arr)) != sizeof(arr)) {
    return false;
  }

  bool worked;
  if (!SSL_read(&ssl, &worked, sizeof(bool))) {
    return false;
  }
  return worked;
}

emp::block F2128_MTA::compute_share(const unsigned upper,
                                    const InnerType<batch_size> &t,
                                    const GType &g) noexcept {
  emp::block out;
  emp::vector_inn_prdt_sum_red(&out, t.data(), g.data(),
                               static_cast<int>(upper));
  return out;
}

F2128_MTA::GadgetType F2128_MTA::generate_and_send_gadget(SSL &ssl) noexcept {
  auto out = generate_gadget_r();
  SSL_write(&ssl, &out, sizeof(out));
  return out;
}

F2128_MTA::GadgetType F2128_MTA::receive_gadget(SSL &ssl) noexcept {
  GadgetType out;
  SSL_read(&ssl, &out, sizeof(out));
  return out;
}

template <bool is_receiver, typename OTType>
bool F2128_MTA::single_iter(OTType &socket, SSL &ssl, const emp::block in,
                            emp::block &out) noexcept {

  const auto gadget_r =
      (is_receiver) ? generate_and_send_gadget(ssl) : receive_gadget(ssl);
  const auto g = generate_g(gadget_r);
  OTOutType t_out;

  if (is_receiver) {
    // N.B we explicitly unpack the choice bits here to save on allocations.
    const auto omega = encode(in, gadget_r);
    const auto choice_bits = get_choice_bits(omega);
    t_out = play_receiver(socket, choice_bits);
    const auto chi = generate_randomness(ssl, false);
    if (!check_consistency(ssl, t_out, chi, choice_bits)) {
      return false;
    }
  } else {
    const auto pads = generate_pads();
    const auto alpha_hat = generate_alpha_hat();
    const auto alpha_vec = prepare_pairs(in, alpha_hat, pads);
    play_sender(socket, alpha_vec);
    t_out = get_sender_out(pads);

    const auto chi = generate_randomness(ssl, true);
    if (!prove_consistency(ssl, in, alpha_hat, t_out, chi)) {
      return false;
    }
  }

  out = compute_share(g.size(), t_out[0], g);
  return true;
}

template <bool is_verifier, typename OTType>
F2128_MTA::ShareType
F2128_MTA::generate_shares_repeated(OTType &socket, SSL &ssl,
                                    const emp::block in) noexcept {

  // This function works as follows. Recall that the operations
  // are all over a binary field. Label `h` = Enc(k, 0) as our secret and share
  // h as h = p_in + v_in. For this documentation we will consider the
  // vernacular of the prover (i.e in = p_in).

  // As the shares are over a binary field, we can.

  // 1) Compute shares of all power of two shares locally by simply computing
  // in^2, in^4, ...
  //    by using the identity that h^2 = (p_in + v_in) ^2 = p_in^2 + v_in^2
  //    (over binary fields).
  // 2) We can  also compute a portion of the odd shares locally too. Indeed,
  // consider h^3:
  //    h^3 = (p_in + v_in)^2 (p_in + v_in) = p_in^3 + v_in^3 + p_in^2(v_in) +
  //    v_in^2(p_in). Clearly, the terms p_in^3 + v_in^3 can be computed
  //    locally.
  // 3) We can compute the other terms using OT multiplication (i.e p_in^2(v_in)
  // + v_in^2(p_in)).
  //    This does take two separate OT multiplications. Once that's done we
  //    update our local shares and square as above.
  // 4) For higher powers we use the identity of (p_in+v_in)^x =
  //    (p_in+v_in)^(x-1) * (p_in+v_in). In other words, we take our previous
  //    result and multiply it by our original input and then apply two OT
  //    multiplications.

  ShareType out;
  // The first share is always the share we received.
  // Note: we have an off-by-one here. The element at 0 is actually a share of
  // h^1.
  out[0] = in;

  auto compute_squares = [&](const unsigned start) {
    unsigned lhs = start * 2 + 1;
    unsigned rhs = start;
    while (lhs < 1024) {
      out[lhs] = mul(out[rhs], out[rhs]);
      rhs = lhs;
      lhs = lhs * 2 + 1;
    }
  };

  // Now we can generate the squared powers 2,4,8,...
  compute_squares(0);

  // Now we want to compute the shared terms.
  // We do this iteratively.
  emp::block first_out, second_out, first_in, second_in;

  // Start at the 3rd power (i.e h^3).
  for (unsigned i = 2; i < 1024; i += 2) {
    // We take the previous term and multiply it by our `in` term,
    // and then do the OT-based multiplication.
    auto our_share = mul(out[i - 1], in);

    // Now we'll do the mixed multiplication.
    // First we do the verifier's multiplication and then the
    // prover's.
    first_in = (is_verifier) ? in : out[i - 1];
    // Second is v_in^(i) \cdot p_in (i.e...)
    second_in = (is_verifier) ? out[i - 1] : in;

    // N.B we don't swap roles because emp has a bug around that sort of
    // switching (due to use of keying material).
    if (!single_iter<is_verifier>(socket, ssl, first_in, first_out) ||
        !single_iter<is_verifier>(socket, ssl, second_in, second_out)) {
      std::abort();
    }

    // out[i] is just the share + the existing multiple.
    out[i] = our_share ^ first_out ^ second_out;
    compute_squares(i);
  }

  return out;
}

template <typename OTType>
F2128_MTA::ShareType
F2128_MTA::generate_shares_verifier_repeated(OTType &socket, SSL &ssl,
                                             const emp::block in) noexcept {
  return generate_shares_repeated<true>(socket, ssl, in);
}

template <typename OTType>
F2128_MTA::ShareType
F2128_MTA::generate_shares_prover_repeated(OTType &socket, SSL &ssl,
                                           const emp::block in) noexcept {
  return generate_shares_repeated<false>(socket, ssl, in);
}

F2128_MTA::ShareType
F2128_MTA::generate_shares_verifier_repeated(SSL &ssl,
                                             const emp::block in) noexcept {
  EmpWrapper<> wrapper{&ssl};
  if (use_ferret) {
    EmpWrapper<> *as_arr[2]{&wrapper, &wrapper};
    emp::FerretCOT<EmpWrapper<>> ot(emp::BOB, 1, as_arr, true, true);
    return generate_shares_verifier_repeated(ot, ssl, in);
  }
  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
  return generate_shares_verifier_repeated(ot, ssl, in);
}

F2128_MTA::ShareType
F2128_MTA::generate_shares_prover_repeated(SSL &ssl,
                                           const emp::block in) noexcept {
  EmpWrapper<> wrapper{&ssl};
  if (use_ferret) {
    EmpWrapper<> *as_arr[2]{&wrapper, &wrapper};
    emp::FerretCOT<EmpWrapper<>> ot(emp::ALICE, 1, as_arr, true, true);
    return generate_shares_prover_repeated(ot, ssl, in);
  }

  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
  return generate_shares_prover_repeated(ot, ssl, in);
}

F2128_MTA::ReceiverType::ReceiverType(const GadgetType &gadget) noexcept
    : beta{generate_beta()}, b{produce_b(gadget, beta)},
      omega{get_batched_choice_bits(beta)}, t_b{}, chi{} {}

template <typename OTType>
void F2128_MTA::ReceiverType::do_ot(OTType &ot) noexcept {
  t_b = play_batched_receiver(ot, *omega);
}

F2128_MTA::SenderType::SenderType(const GadgetType &) noexcept
    : a_tilde{generate_a()}, a_hat{generate_a()}, alpha{produce_alpha(*a_tilde,
                                                                      *a_hat)},
      pads{generate_batched_pads()}, pairs{prepare_batched_pairs(*alpha,
                                                                 *pads)},
      t_a{get_sender_batched_out(*pads)}, chi{} {}

template <typename OTType>
void F2128_MTA::SenderType::do_ot(OTType &ot) noexcept {
  F2128_MTA::play_batched_sender(ot, *pairs);
}

void F2128_MTA::ReceiverType::generate_batched_randomness(SSL &ssl) noexcept {
  chi = F2128_MTA::generate_batched_randomness(ssl, false);
}

void F2128_MTA::SenderType::generate_batched_randomness(SSL &ssl) noexcept {
  chi = F2128_MTA::generate_batched_randomness(ssl, true);
}

bool F2128_MTA::SenderType::is_consistent(SSL &ssl) noexcept {
  return F2128_MTA::prove_consistency_batched(ssl, *a_tilde, *a_hat, *t_a, chi);
}

bool F2128_MTA::ReceiverType::is_consistent(SSL &ssl) noexcept {
  return F2128_MTA::check_consistency_batched(ssl, *t_b, chi, beta);
}

template <typename F>
emp::block F2128_MTA::ReceiverType::compute_share(
    SSL &ssl, const unsigned i, const emp::block in, const emp::block other_in,
    F &&compute_share_of) noexcept {

  emp::block my_tmp[2]{other_in ^ b[i - 2], in ^ b[i - 1]};
  emp::block other_tmp[2];
  SSL_read(&ssl, &other_tmp, sizeof(other_tmp));
  SSL_write(&ssl, &my_tmp, sizeof(my_tmp));

  return F2128_MTA::mul(other_in, in) ^
         compute_share_of(b[i - 2], other_tmp[0], i - 2, *t_b) ^
         compute_share_of(b[i - 1], other_tmp[1], i - 1, *t_b);
}

template <typename F>
emp::block F2128_MTA::SenderType::compute_share(SSL &ssl, const unsigned i,
                                                const emp::block in,
                                                const emp::block other_in,
                                                F &&compute_share_of) noexcept {

  emp::block my_tmp[2]{in ^ (*a_tilde)[i - 2], other_in ^ (*a_tilde)[i - 1]};
  emp::block other_tmp[2];
  SSL_write(&ssl, &my_tmp, sizeof(my_tmp));
  SSL_read(&ssl, &other_tmp, sizeof(other_tmp));

  return mul(other_in, in) ^ compute_share_of(in, other_tmp[0], i - 2, *t_a) ^
         compute_share_of(other_in, other_tmp[1], i - 1, *t_a);
}

template <typename F>
void F2128_MTA::SenderType::compute_mult_shares(SSL &ssl, ShareType &out,
                                                F &&compute_share_of) noexcept {
  // We first pack each odd element into a temporary array.
  emp::block *my_tmp = new emp::block[F2128_MTA::l];
  emp::block *other_tmp = new emp::block[F2128_MTA::l];

  // N.b we start at 0 so we turn our multiplicative share of `h` into
  // an additive one.

  for (unsigned i = 0; i < F2128_MTA::l; i++) {
    my_tmp[i] = out[2 * i] ^ (*a_tilde)[i];
  }

  // We now write out our portion and read theirs in too.
  // N.B As these messages may be large, we use the Util functions instead.
  // NOTE: to make sure that the serialisation works, we convert to a
  // serialisaton format.
  constexpr auto size = sizeof(emp::block) * F2128_MTA::l;

  Util::process_data(&ssl, reinterpret_cast<const char *>(my_tmp), size,
                     SSL_write);
  Util::process_data(&ssl, reinterpret_cast<char *>(other_tmp), size, SSL_read);

  // And now we just do the multiplication.
  for (unsigned i = 0; i < F2128_MTA::l; i++) {
    out[2 * i] = compute_share_of(out[2 * i], other_tmp[i], i, *t_a);
  }

  delete[] my_tmp;
  delete[] other_tmp;
}

template <typename F>
void F2128_MTA::ReceiverType::compute_mult_shares(
    SSL &ssl, ShareType &out, F &&compute_share_of) noexcept {
  // We first pack each odd element into a temporary array.
  emp::block *my_tmp = new emp::block[F2128_MTA::l];
  emp::block *other_tmp = new emp::block[F2128_MTA::l];

  // N.b we start at 0 so we turn our multiplicative share of `h` into
  // an additive one.
  for (unsigned i = 0; i < F2128_MTA::l; i++) {
    my_tmp[i] = out[2 * i] ^ b[i];
  }

  // We now read in the other portion before writing ours.
  // N.B As these messages may be large, we use the Util functions instead.
  constexpr auto size = sizeof(emp::block) * F2128_MTA::l;
  Util::process_data(&ssl, reinterpret_cast<char *>(other_tmp), size, SSL_read);
  Util::process_data(&ssl, reinterpret_cast<const char *>(my_tmp), size,
                     SSL_write);

  // And now we just do the multiplication.
  for (unsigned i = 0; i < F2128_MTA::l; i++) {
    out[2 * i] = compute_share_of(b[i], other_tmp[i], i, *t_b);
  }

  delete[] my_tmp;
  delete[] other_tmp;
}

template <bool is_verifier, typename OTType>
F2128_MTA::ShareType
F2128_MTA::generate_shares_batched(OTType &socket, SSL &ssl,
                                   const emp::block in,
                                   uint64_t &bandwidth) noexcept {

  // How this function works depends on the secret sharing that is used.
  // For notation, label `h` = Enc(k, 0) as our secret. If multiplicative
  // secrets are used, then `h` is shared as p_in * v_in. By contrast, if
  // additive secrets are used, then `h` = `p_in ^ v_in`. For this documentation
  // we will consider the vernacular of the prover (i.e in = p_in). For additive
  // shares, we use the TLSNotary protocol. Namely, we: 1) Compute shares of all
  // power of two shares locally by simply computing in^2, in^4, ...
  //    by using the identity that h^2 = (p_in + v_in) ^2 = p_in^2 + v_in^2
  //    (over binary fields).
  // 2) We can  also compute a portion of the odd shares locally too. Indeed,
  // consider h^3:
  //    h^3 = (p_in + v_in)^2 (p_in + v_in) = p_in^3 + v_in^3 + p_in^2(v_in) +
  //    v_in^2(p_in). Clearly, the terms p_in^3 + v_in^3 can be computed
  //    locally.
  // 3) We can compute the other terms using OT multiplication (i.e
  // p_in^2(v_in)
  // + v_in^2(p_in)).
  //    This does take two separate OT multiplications. Once that's done we
  //    update our local shares and square as above.
  // 4) For higher powers we use the identity of (p_in+v_in)^x =
  //    (p_in+v_in)^(x-1) * (p_in+v_in). In other words, we take our previous
  //    result and multiply it by our original input and then apply two OT
  //    multiplications.
  //
  // For multiplicative shares, we use the same optimisation provided in step 1
  // above, but all multiplications are done in a single round. This is because
  // we have no dependency (as described in step 4).

  // To make this function neater, we delegate all functionality to a sub object
  // of the correct type. As the data layout for each party is somewhat
  // different, we hide this behind a sub-type.
  using DataType = std::conditional_t<is_verifier, SenderType, ReceiverType>;

  ShareType out;
  // The first share is always the share we received.
  // Note: we have an off-by-one here. The element at 0 is actually a share of
  // h^1.
  out[0] = in;

  // This will be useful later.
  auto compute_squares = [&](const unsigned start) {
    unsigned lhs = start * 2 + 1;
    unsigned rhs = start;
    while (lhs < 1024) {
      out[lhs] = mul(out[rhs], out[rhs]);
      rhs = lhs;
      lhs = lhs * 2 + 1;
    }
  };

  // Now we want to compute the shared terms.
  // As per usual, we do different work depending on if we're the verifier
  // or the prover. Here the prover plays the receiver and the verifier plays
  // the sender, so the work that each party does is a little bit different.
  const auto gadget_r =
      (!is_verifier) ? generate_and_send_gadget(ssl) : receive_gadget(ssl);

  // The prover sends the Gadget.
  if (!is_verifier)
    bandwidth += sizeof(GadgetType);

  // This will come in useful later.
  auto compute_share_of = [&](const emp::block my_in, const emp::block other_in,
                              const unsigned i, const BatchedOTOutType &t) {
    emp::block dot = emp::zero_block;
    for (unsigned j = 0; j < gadget_elements; j++) {
      dot ^= mul(t[0][i * gadget_elements + j], gadget_r[j]);
    }

    return dot ^ mul(my_in, other_in);
  };

  // Build the right type of sub-object for the OT.
  DataType data(gadget_r);

  // Now we can carry out the OT.
  data.do_ot(socket);

  // We can now check the consistency bits.
  data.generate_batched_randomness(ssl);

  // Each party is responsible for half.
  bandwidth += sizeof(ChiType) / 2;

  // Check the consistency.
  if (!data.is_consistent(ssl)) {
    std::abort();
  }

  // The verifier sends the `r` values, whereas the prover only sends a single
  // bool.
  bandwidth += (is_verifier) ? sizeof(BatchedRType) : sizeof(bool);

  // Now what we do depends on if the shares are multiplicative or additive.
  // If they're multiplicative, we locally generate powers of our input share
  // and then carry out the MtA in a single batch, only considering the odd
  // powers. We then apply the squaring trick to produce other powers. If
  // they're additive, then we just have to generate them one-by-one.
  if (use_multiplicative_shares) {
    // Generate the local shares. We only do the odd shares here
    // as the even ones will be covered later.
    const emp::block sq = mul(in, in);
    emp::block tmp = in;
    for (unsigned i = 2; i < 1024; i += 2) {
      tmp = mul(sq, tmp);
      out[i] = tmp;
    }

    // Run the whole protocol forwards. This just computes the odd shares
    // 1, 3, 5, 7, etc, so we also need to square those.
    data.compute_mult_shares(ssl, out, compute_share_of);
    // N.B we need to do the initial squares 2, 4, 8... etc here too.
    for (unsigned i = 0; i < 1024; i += 2) {
      compute_squares(i);
    }

  } else {
    // Compute the powers 2, 4, 8, ...
    compute_squares(0);

    // Now we can produce the values that we are going to send. Sadly we have
    // to do this one-by-one, which is suboptimal (we require the previous
    // output to make the next power up).
    for (unsigned i = 2; i < 1024; i += 2) {
      out[i] = data.compute_share(ssl, i, in, out[i - 1], compute_share_of);
      compute_squares(i);
    }
  }

  // In any case, we've used this much data during the OTs.
  bandwidth += sizeof(emp::block) * F2128_MTA::l;
  return out;
}

template <typename OTType>
F2128_MTA::ShareType
F2128_MTA::generate_shares_verifier_batched(OTType &socket, SSL &ssl,
                                            const emp::block in,
                                            uint64_t &bandwidth) noexcept {
  return generate_shares_batched<true>(socket, ssl, in, bandwidth);
}

F2128_MTA::ShareType
F2128_MTA::generate_shares_verifier_batched(SSL &ssl, const emp::block in,
                                            uint64_t &bandwidth) noexcept {
  EmpWrapper<> wrapper{&ssl};
  if (use_ferret) {
    EmpWrapper<> *as_arr[2]{&wrapper, &wrapper};
    emp::FerretCOT<EmpWrapper<>> ot(emp::BOB, 1, as_arr, true, true);
    return generate_shares_verifier_batched(ot, ssl, in, bandwidth);
  }

  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
  return generate_shares_verifier_batched(ot, ssl, in, bandwidth);
}

template <typename OTType>
F2128_MTA::ShareType
F2128_MTA::generate_shares_prover_batched(OTType &socket, SSL &ssl,
                                          const emp::block in,
                                          uint64_t &bandwidth) noexcept {
  return generate_shares_batched<false>(socket, ssl, in, bandwidth);
}

F2128_MTA::ShareType
F2128_MTA::generate_shares_prover_batched(SSL &ssl, const emp::block in,
                                          uint64_t &bandwidth) noexcept {
  EmpWrapper<> wrapper{&ssl};
  if (use_ferret) {
    EmpWrapper<> *as_arr[2]{&wrapper, &wrapper};
    emp::FerretCOT<EmpWrapper<>> ot(emp::ALICE, 1, as_arr, true, true);
    return generate_shares_prover_batched(ot, ssl, in, bandwidth);
  }

  emp::IKNP<EmpWrapper<>> ot(&wrapper, true);
  return generate_shares_prover_batched(ot, ssl, in, bandwidth);
}

F2128_MTA::ShareType F2128_MTA::generate_shares_prover_batched(
    SSL &ssl, const std::array<uint8_t, 16> &in, uint64_t &bandwidth) noexcept {
  return generate_shares_prover_batched(ssl, arr_to_block(in), bandwidth);
}

F2128_MTA::ShareType F2128_MTA::generate_shares_verifier_batched(
    SSL &ssl, const std::array<uint8_t, 16> &in, uint64_t &bandwidth) noexcept {
  return generate_shares_verifier_batched(ssl, arr_to_block(in), bandwidth);
}
