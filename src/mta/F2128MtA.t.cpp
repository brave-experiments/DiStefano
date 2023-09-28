#include "../doctest.h"
#include "../ssl/EmpWrapper.hpp"
#include "../ssl/TLSSocket.hpp"
#define SOCKET_SETUP
#include "../ssl/TestUtil.hpp"

#include "F2128MtA.hpp"

//! [F2128MtAGenerateGadgetR]
TEST_CASE("generate_gadget_r") {
  const auto res = F2128_MTA::generate_gadget_r();
  CHECK(res.size() == 384);
  CHECK(res.data());
  CHECK(sizeof(res[0]) == sizeof(emp::block));
}
//! [F2128MtAGenerateGadgetR]

//! [F2128MtAEncode]
TEST_CASE("Encode") {
  emp::block in;
  Util::generate_random_bytes<sizeof(in)>(&in);

  // Produce some randomness.
  const auto gadget = F2128_MTA::generate_gadget_r();
  const auto encoded = F2128_MTA::encode(in, gadget);

  CHECK(encoded.size() == 4);

  // The gadget contains a load of random entries that are
  // conditionally enabled based on the bytes in
  // out[1...3]. That means checking the results is a little bit
  // complicated.
  emp::block dot_prod = emp::zero_block;
  for (unsigned i = 0; i < 3; i++) {
    // Each inner element of EncodeType is 128 bits in length.
    auto curr = encoded[i + 1];
    for (unsigned j = 0; j < 128; j++) {
      // Extract the bit we need and then multiply.
      if (emp::getLSB(curr)) {
        dot_prod ^= gadget[i * 128 + j];
      }
      curr = F2128_MTA::shift_right_bits<1>(curr);
    }
  }

  // Compute the difference.
  emp::block diff = dot_prod ^ in;
  CHECK(emp::cmpBlock(&diff, encoded.data(), 1));
}
//! [F2128MtAEncode]

//! [F2128MtAInv]
TEST_CASE("inv") {

  emp::block a;
  Util::generate_random_bytes<sizeof(a)>(&a);
  const auto one = emp::makeBlock(0, 1);
  const auto prod = F2128_MTA::mul(a, F2128_MTA::inv(a));
  CHECK(emp::cmpBlock(&prod, &one, 1));
}
//! [F2128MtAInv]

//! [F2128MtAGeneratePads]
TEST_CASE("generate_pads") {
  // This test is mostly here to see if the stack pops,
  // because sizeof(F2128_MTA::TType) is pretty large.
  const auto pads = F2128_MTA::generate_pads();
  CHECK(pads.size() == F2128_MTA::number_of_ots);
}
//! [F2128MtAGeneratePads]

TEST_CASE("prepare_pairs") {
  // Generate a random alpha value.
  emp::block alpha;
  Util::generate_random_bytes<sizeof(alpha)>(&alpha);
  const auto pads = F2128_MTA::generate_pads();
  const auto alpha_hat = F2128_MTA::generate_alpha_hat();

  const auto out = F2128_MTA::prepare_pairs(alpha, alpha_hat, pads);
  // 2 arrays.
  REQUIRE(out.size() == 2);
  REQUIRE(sizeof(out[0]) == sizeof(out[1]));
  REQUIRE(sizeof(out[0]) == sizeof(emp::block) * F2128_MTA::number_of_ots);

  // The first set is just the pads.
  CHECK(emp::cmpBlock(out[0].data(), pads.data(), F2128_MTA::number_of_ots));

  unsigned curr = 0;
  while (curr != F2128_MTA::number_of_ots) {
    emp::block tmp = alpha ^ pads[curr];
    CHECK(emp::cmpBlock(&out[1][curr], &tmp, 1));
    tmp = alpha_hat ^ pads[curr + 1];
    CHECK(emp::cmpBlock(&out[1][curr + 1], &tmp, 1));
    curr += 2;
  }
}

TEST_CASE("get_sender_out") {
  const auto pads = F2128_MTA::generate_pads();
  // The sender only learns the pads.
  const auto out = F2128_MTA::get_sender_out(pads);

  // There should be 2 arrays here.
  REQUIRE(out.size() == 2);
  // Each containing batch_size many values.
  REQUIRE(sizeof(out[0]) == sizeof(out[1]));
  REQUIRE(sizeof(out[0]) == sizeof(emp::block) * F2128_MTA::batch_size);

  // out[0] should contain the even values in `pads`, whereas out[1] should
  // contain the odd values in `pads`.
  for (unsigned i = 0; i < F2128_MTA::batch_size; i++) {
    CHECK(emp::cmpBlock(&out[0][i], &pads[2 * i], 1));
    CHECK(emp::cmpBlock(&out[1][i], &pads[2 * i + 1], 1));
  }
}

TEST_CASE("get_choice_bits") {
  emp::block beta;
  Util::generate_random_bytes<sizeof(beta)>(&beta);

  const auto omega = F2128_MTA::encode(beta, F2128_MTA::generate_gadget_r());
  const auto bits = F2128_MTA::get_choice_bits(omega);
  CHECK(bits.size() == F2128_MTA::number_of_ots);

  unsigned curr = 0;
  uint64_t vals[2];

  for (unsigned i = 0; i < omega.size(); i++) {
    memcpy(vals, &omega[i], sizeof(omega[i]));

    for (unsigned j = 0; j < 64; j++) {
      CHECK((vals[0] & 1) == bits[curr]);
      CHECK((vals[0] & 1) == bits[curr + 1]);
      curr += 2;
      vals[0] >>= 1;
    }

    for (unsigned j = 0; j < 64; j++) {
      CHECK((vals[1] & 1) == bits[curr]);
      CHECK((vals[1] & 1) == bits[curr + 1]);
      curr += 2;
      vals[1] >>= 1;
    }
  }
}

TEST_CASE("generate_g") {
  const auto g_r = F2128_MTA::generate_gadget_r();
  const auto g = F2128_MTA::generate_g(g_r);

  CHECK(g.size() == F2128_MTA::batch_size);
  CHECK(g.size() == g_r.size() + 128);
  emp::block val = emp::makeBlock(0, 1);
  for (unsigned i = 0; i < 128; i++) {
    CHECK(emp::cmpBlock(&val, &g[i], 1));
    val = F2128_MTA::shift_left_bits<1>(val);
  }

  for (unsigned i = 128; i < g.size(); i++) {
    CHECK(emp::cmpBlock(&g[i], &g_r[i - 128], 1));
  }
}

TEST_CASE("do_ot") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));

  EmpWrapper<> s_wrapper{server->get_ssl_object()};
  EmpWrapper<> c_wrapper{client->get_ssl_object()};

  emp::IKNP<EmpWrapper<>> sender_ot{&s_wrapper, true};
  emp::IKNP<EmpWrapper<>> receiver_ot{&c_wrapper, true};

  emp::block alpha, beta;
  Util::generate_random_bytes<sizeof(alpha)>(&alpha);
  Util::generate_random_bytes<sizeof(beta)>(&beta);

  const auto pads = F2128_MTA::generate_pads();
  const auto alpha_hat = F2128_MTA::generate_alpha_hat();
  const auto alpha_vec = F2128_MTA::prepare_pairs(alpha, alpha_hat, pads);
  const auto g_r = F2128_MTA::generate_gadget_r();
  const auto omega = F2128_MTA::encode(beta, g_r);
  const auto choice_bits = F2128_MTA::get_choice_bits(omega);
  const auto g = F2128_MTA::generate_g(g_r);

  emp::block t_A = emp::zero_block, t_B = emp::zero_block;
  emp::block f128_A = emp::zero_block, f128_B = emp::zero_block;

  F2128_MTA::OTOutType t_a{}, t_b{};

  SUBCASE("no ot") {
    for (unsigned i = 0; i < choice_bits.size(); i += 2) {
      emp::block tmp = alpha_vec[choice_bits[i]][i];
      emp::block tmp2 = alpha_vec[choice_bits[i]][i + 1];
      CHECK(choice_bits[i] == choice_bits[i + 1]);

      emp::block expected1 = pads[i];
      emp::block expected2 = pads[i + 1];
      if (choice_bits[i]) {
        expected1 ^= alpha;
        expected2 ^= alpha_hat;
      }

      CHECK(emp::cmpBlock(&expected1, &tmp, 1));
      CHECK(emp::cmpBlock(&expected2, &tmp2, 1));
    }
  }

  SUBCASE("with ot") {
    auto receiver_work = [&]() {
      t_b = F2128_MTA::play_receiver(receiver_ot, omega);

      // Check the results were what we expected.
      for (unsigned i = 0; i < F2128_MTA::number_of_ots; i += 2) {
        emp::block tmp = pads[i], tmp2 = pads[i + 1];
        if (choice_bits[i]) {
          tmp ^= alpha;
          tmp2 ^= alpha_hat;
        }
        CHECK(emp::cmpBlock(&t_b[0][i / 2], &tmp, 1));
        CHECK(emp::cmpBlock(&t_b[1][i / 2], &tmp2, 1));
      }

      const auto chi =
          F2128_MTA::generate_randomness(*client->get_ssl_object(), false);
      CHECK(F2128_MTA::check_consistency(*client->get_ssl_object(), t_b, chi,
                                         choice_bits));

      // The first sum of the first 128 elements (across both parties) is
      // Bits(beta - <g^r, out[1]>) * alpha.
      f128_B = F2128_MTA::compute_share(128, t_b[0], g);
      // The rest is the whole share.
      t_B = F2128_MTA::compute_share(g.size(), t_b[0], g);
    };

    auto sender_work = [&]() {
      F2128_MTA::play_sender(sender_ot, alpha_vec);
      t_a = F2128_MTA::get_sender_out(pads);

      // Produce the random values.
      const auto chi =
          F2128_MTA::generate_randomness(*server->get_ssl_object(), true);
      CHECK(F2128_MTA::prove_consistency(*server->get_ssl_object(), alpha,
                                         alpha_hat, t_a, chi));

      // Output the share.
      // The first sum of the first 128 elements (across both parties) is
      // Bits(beta - <g^r, out[1]>) * alpha.
      f128_A = F2128_MTA::compute_share(128, t_a[0], g);
      t_A = F2128_MTA::compute_share(g.size(), t_a[0], g);
    };

    std::thread sender_thread(sender_work);
    receiver_work();
    sender_thread.join();

    auto check_gr_share = [&](bool is_alice) {
      emp::block alpha_val, diff;
      emp::block alice_tmp, bob_tmp;
      emp::block alice_out = emp::zero_block, bob_out = emp::zero_block;
      // We have to start at 256 because the choice bits are double packed,
      // so inner products over the first 128 elements consumes 256 choice bits.
      unsigned curr = 256;
      // We just check that the answers are as we expect them to be for the
      // gadget portion.
      for (unsigned i = 128; i < g.size(); i++) {
        alice_tmp = F2128_MTA::mul(t_a[0][i], g[i]);
        bob_tmp = F2128_MTA::mul(t_b[0][i], g[i]);

        diff = alice_tmp ^ bob_tmp;
        if (choice_bits[curr]) {
          // Just alpha \cdot g^r[i]
          alpha_val = F2128_MTA::mul(alpha, g[i]);
          CHECK(emp::cmpBlock(&diff, &alpha_val, 1));
        } else {
          CHECK(emp::cmpBlock(&diff, &emp::zero_block, 1));
        }

        bob_out ^= bob_tmp;
        alice_out ^= alice_tmp;
        curr += 2;
      }

      if (is_alice) {
        return alice_out;
      }
      return bob_out;
    };

    SUBCASE("is_correct") {
      // Check that the first part is right.
      emp::block res1 = F2128_MTA::mul(alpha, omega[0]);
      emp::block sum1 = f128_A ^ f128_B;
      CHECK(emp::cmpBlock(&res1, &sum1, 1));

      emp::block grA = check_gr_share(true);
      emp::block grB = check_gr_share(false);
      const auto alice_share = grA ^ f128_A;
      const auto bob_share = grB ^ f128_B;

      CHECK(emp::cmpBlock(&alice_share, &t_A, 1));
      CHECK(emp::cmpBlock(&bob_share, &t_B, 1));

      emp::block sum = alice_share ^ bob_share;
      emp::block out = t_A ^ t_B;
      CHECK(emp::cmpBlock(&sum, &out, 1));

      emp::block res = F2128_MTA::mul(beta, alpha);
      sum = t_A ^ t_B;
      CHECK(emp::cmpBlock(&res, &sum, 1));
    }
  }
}

TEST_CASE("power_shares") {
  emp::block alpha, beta;
  Util::generate_random_bytes<sizeof(alpha)>(&alpha);
  Util::generate_random_bytes<sizeof(beta)>(&beta);

  // The point of this is to check that computing the various powers work.
  emp::block alpha_pows[1024], beta_pows[1024];
  emp::block running_a = alpha, running_b = beta;
  alpha_pows[0] = alpha;
  beta_pows[0] = beta;
  for (unsigned i = 1; i < 1024; i++) {
    running_a = alpha_pows[i] = F2128_MTA::mul(alpha, running_a);
    running_b = beta_pows[i] = F2128_MTA::mul(beta, running_b);
  }

  // Check that free squaring works.
  SUBCASE("powers of 2") {
    emp::block total = alpha ^ beta;
    for (unsigned i = 0; i <= 10; i++) {
      emp::block shares = alpha_pows[(1 << i) - 1] ^ beta_pows[(1 << i) - 1];
      CHECK(emp::cmpBlock(&total, &shares, 1));
      total = F2128_MTA::mul(total, total);
    }
  }
}

TEST_CASE("do_unbatched_ot") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));
  EmpWrapper<> s_wrapper{server->get_ssl_object()};
  EmpWrapper<> c_wrapper{client->get_ssl_object()};

  emp::IKNP<EmpWrapper<>> sender_ot{&s_wrapper, true};
  emp::IKNP<EmpWrapper<>> receiver_ot{&c_wrapper, true};

  // Generate the random values.
  emp::block alpha, beta;
  Util::generate_random_bytes<sizeof(alpha)>(&alpha);
  Util::generate_random_bytes<sizeof(beta)>(&beta);

  F2128_MTA::ShareType verifier_share, prover_share;

  auto verifier_work = [&]() {
    verifier_share = F2128_MTA::generate_shares_verifier_repeated(
        sender_ot, *server->get_ssl_object(), alpha);
  };

  std::thread verifier(verifier_work);
  prover_share = F2128_MTA::generate_shares_prover_repeated(
      receiver_ot, *client->get_ssl_object(), beta);
  verifier.join();

  emp::block total_secret = alpha ^ beta;
  emp::block running = emp::makeBlock(0, 1);
  emp::block share;

  // h, h^2, h^3, ...

  for (unsigned i = 0; i < 1024; i++) {
    // Check that the shares add up.
    running = F2128_MTA::mul(running, total_secret);
    share = verifier_share[i] ^ prover_share[i];
    CHECK(emp::cmpBlock(&share, &running, 1));
  }
  std::cerr << "Verifier bandwidth, batched:" << s_wrapper.counter << " bytes"
            << std::endl;
  std::cerr << "Prover bandwidth, batched:" << c_wrapper.counter << " bytes"
            << std::endl;
}

//! [GenerateA]
TEST_CASE("generate_a") {
  // Check that `a` is the right size.
  CHECK(F2128_MTA::generate_a()->size() == F2128_MTA::l);
}
//! [GenerateA]

//! [ProduceAlpha]
TEST_CASE("produce_alpha") {
  // Generate two random vectors.
  const auto a_tilde_ptr = F2128_MTA::generate_a();
  const auto a_hat_ptr = F2128_MTA::generate_a();
  const auto a_tilde = *a_tilde_ptr.get();
  const auto a_hat = *a_hat_ptr.get();
  // Pack
  const auto alpha_ptr = F2128_MTA::produce_alpha(a_tilde, a_hat);
  const auto &alpha = *alpha_ptr.get();
  // Must contain both a_tilde and a_hat
  CHECK(alpha.size() == 2 * F2128_MTA::eta);

  // The elements in alpha are actually double packed.
  unsigned curr = 0;
  for (unsigned i = 0; i < a_tilde.size(); i++) {
    for (unsigned j = 0; j < F2128_MTA::gadget_elements; j++) {
      CHECK(emp::cmpBlock(&alpha[curr], &a_tilde[i], 1));
      CHECK(emp::cmpBlock(&alpha[curr + 1], &a_hat[i], 1));
      curr += 2;
    }
  }
}
//! [ProduceAlpha]

//! [GenerateBeta]
TEST_CASE("generate_beta") {
  const auto beta = F2128_MTA::generate_beta();
  static_assert(sizeof(emp::block) == 16,
                "Error: sizeof(emp::block) is not 16");
  static_assert(decltype(beta)::size() * (sizeof(emp::block) * CHAR_BIT) ==
                F2128_MTA::eta);
  CHECK(beta.size() == F2128_MTA::eta / (CHAR_BIT * sizeof(emp::block)));
}
//! [GenerateBeta]

//! [ProduceB]
TEST_CASE("produce_b") {
  const auto gadget = F2128_MTA::generate_gadget_r();
  const auto beta = F2128_MTA::generate_beta();
  const auto b = F2128_MTA::produce_b(gadget, beta);

  CHECK(b.size() == F2128_MTA::l);
  for (unsigned i = 0; i < b.size(); i++) {
    // Produce the same inner product.
    const auto tmp = F2128_MTA::dot_product(&beta[3 * i], gadget);
    CHECK(emp::cmpBlock(&tmp, &b[i], 1));
  }
}
//! [ProduceB]

//! [GenerateBatchedPads]
TEST_CASE("generate_batched_pads") {
  const auto out = F2128_MTA::generate_batched_pads();
  CHECK(out->size() == F2128_MTA::number_of_batched_ots);
}
//! [GenerateBatchedPads]

//! [PrepareBatchedPairs]
TEST_CASE("prepare_batched_pairs") {
  const auto a_tilde_ptr = F2128_MTA::generate_a();
  const auto a_hat_ptr = F2128_MTA::generate_a();

  const auto &a_tilde = *a_tilde_ptr.get();
  const auto &a_hat = *a_hat_ptr.get();
  const auto alpha = F2128_MTA::produce_alpha(a_tilde, a_hat);

  const auto pads_ptr = F2128_MTA::generate_batched_pads();
  CHECK(pads_ptr->size() == F2128_MTA::number_of_batched_ots);
  const auto &pads = *pads_ptr.get();

  const auto &pairs_ptr = F2128_MTA::prepare_batched_pairs(*alpha, pads);
  REQUIRE(pairs_ptr);
  const auto &pairs = *pairs_ptr.get();

  REQUIRE(pairs[0].size() == F2128_MTA::number_of_batched_ots);
  REQUIRE(pairs[1].size() == F2128_MTA::number_of_batched_ots);

  // The first set should just be the pads.
  CHECK(emp::cmpBlock(pairs[0].data(), pads.data(),
                      sizeof(pads) / sizeof(emp::block)));

  // The second set should just be various xors. As with the single OT case,
  // each element is double packed.
  for (unsigned i = 0; i < pairs[1].size(); i += 2) {
    const auto ltmp = (*alpha)[i] ^ pads[i];
    const auto rtmp = (*alpha)[i + 1] ^ pads[i + 1];
    CHECK(emp::cmpBlock(&pairs[1][i], &ltmp, 1));
    CHECK(emp::cmpBlock(&pairs[1][i + 1], &rtmp, 1));

    const auto fsec = a_tilde[i / (2 * F2128_MTA::gadget_elements)] ^ pads[i];
    const auto ssec = a_hat[i / (2 * F2128_MTA::gadget_elements)] ^ pads[i + 1];
    CHECK(emp::cmpBlock(&fsec, &pairs[1][i], 1));
    CHECK(emp::cmpBlock(&ssec, &pairs[1][i + 1], 1));
  }
}
//! [PrepareBatchedPairs]

//! [GetSenderBatchedOut]
TEST_CASE("sender_batched_out") {
  const auto pads = F2128_MTA::generate_batched_pads();
  const auto out = F2128_MTA::get_sender_batched_out(*pads.get());
  CHECK(out->size() == 2);

  for (unsigned i = 0; i < F2128_MTA::number_of_batched_ots / 2; i++) {
    CHECK(emp::cmpBlock(&(*out)[0][i], &(*pads)[2 * i + 0], 1));
    CHECK(emp::cmpBlock(&(*out)[1][i], &(*pads)[2 * i + 1], 1));
  }
}
//! [GetSenderBatchedOut]

//! [GetBatchedChoiceBits]
TEST_CASE("get_batched_choice_bits") {
  const auto omega = F2128_MTA::generate_beta();
  const auto bits = F2128_MTA::get_batched_choice_bits(omega);
  CHECK(bits->size() == F2128_MTA::number_of_batched_ots);

  unsigned curr = 0;
  uint64_t vals[2];

  for (unsigned i = 0; i < omega.size(); i++) {
    memcpy(vals, &omega[i], sizeof(omega[i]));

    for (unsigned j = 0; j < 64; j++) {
      CHECK((vals[0] & 1) == (*bits)[curr]);
      CHECK((vals[0] & 1) == (*bits)[curr + 1]);
      curr += 2;
      vals[0] >>= 1;
    }

    for (unsigned j = 0; j < 64; j++) {
      CHECK((vals[1] & 1) == (*bits)[curr]);
      CHECK((vals[1] & 1) == (*bits)[curr + 1]);
      curr += 2;
      vals[1] >>= 1;
    }
  }
}
//! [GetBatchedChoiceBits]

//! [DoBatchedOT]
TEST_CASE("ot_check_batched") {
  // Run the whole thing.
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));

  EmpWrapper<> s_wrapper{server->get_ssl_object()};
  EmpWrapper<> c_wrapper{client->get_ssl_object()};

  emp::IKNP<EmpWrapper<>> sender_ot{&s_wrapper, true};
  emp::IKNP<EmpWrapper<>> receiver_ot{&c_wrapper, true};

  const auto beta = F2128_MTA::generate_beta();
  const auto a_tilde_ptr = F2128_MTA::generate_a();
  const auto a_hat_ptr = F2128_MTA::generate_a();

  const auto &a_tilde = *a_tilde_ptr.get();
  const auto &a_hat = *a_hat_ptr.get();
  const auto alpha = F2128_MTA::produce_alpha(a_tilde, a_hat);

  const auto pads_ptr = F2128_MTA::generate_batched_pads();
  const auto &pads = *pads_ptr.get();

  const auto &pairs_ptr = F2128_MTA::prepare_batched_pairs(*alpha, pads);

  auto server_work = [&]() {
    F2128_MTA::play_batched_sender(sender_ot, *pairs_ptr);
  };

  auto client_work = [&]() {
    const auto t_b = F2128_MTA::play_batched_receiver(receiver_ot, beta);
    const auto choice_bits = F2128_MTA::get_batched_choice_bits(beta);
    CHECK(choice_bits->size() == pads.size());
    CHECK(choice_bits->size() == alpha->size());

    for (unsigned i = 0; i < choice_bits->size(); i += 2) {
      emp::block tmp = (*pairs_ptr)[(*choice_bits)[i]][i];
      emp::block tmp2 = (*pairs_ptr)[(*choice_bits)[i]][i + 1];

      CHECK((*choice_bits)[i] == (*choice_bits)[i + 1]);
      emp::block expected1 = pads[i];
      emp::block expected2 = pads[i + 1];

      if ((*choice_bits)[i]) {
        expected1 ^= (*alpha)[i];
        expected2 ^= (*alpha)[i + 1];
      }

      CHECK(emp::cmpBlock(&expected1, &tmp, 1));
      CHECK(emp::cmpBlock(&expected2, &tmp2, 1));
    }
  };

  std::thread server_thread(server_work);
  client_work();
  server_thread.join();
}
//! [DoBatchedOT]

//! [GenerateBatchedRandomness]
TEST_CASE("generate_batched_randomness") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));

  F2128_MTA::ChiType sender_chi, receiver_chi;

  auto sender_work = [&]() {
    sender_chi =
        F2128_MTA::generate_batched_randomness(*server->get_ssl_object(), true);
  };

  std::thread server_thread(sender_work);
  receiver_chi =
      F2128_MTA::generate_batched_randomness(*client->get_ssl_object(), false);
  server_thread.join();
  CHECK(emp::cmpBlock(sender_chi[0].data(), receiver_chi[0].data(),
                      sender_chi[0].size()));
  CHECK(emp::cmpBlock(sender_chi[1].data(), receiver_chi[1].data(),
                      sender_chi[1].size()));
}
//! [GenerateBatchedRandomness]

//! [CheckConsistencyBatched]
TEST_CASE("check_consistency_batched") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));

  EmpWrapper<> s_wrapper{server->get_ssl_object()};
  EmpWrapper<> c_wrapper{client->get_ssl_object()};

  emp::IKNP<EmpWrapper<>> sender_ot{&s_wrapper, true};
  emp::IKNP<EmpWrapper<>> receiver_ot{&c_wrapper, true};

  // NOTE: this code doesn't generate `b` because it isn't
  // needed for functional tests. It is, however, important from
  // a functionality perspective later.
  const auto beta = F2128_MTA::generate_beta();
  const auto a_tilde_ptr = F2128_MTA::generate_a();
  const auto a_hat_ptr = F2128_MTA::generate_a();

  const auto &a_tilde = *a_tilde_ptr.get();
  const auto &a_hat = *a_hat_ptr.get();
  const auto alpha = F2128_MTA::produce_alpha(a_tilde, a_hat);

  const auto pads_ptr = F2128_MTA::generate_batched_pads();
  const auto &pads = *pads_ptr.get();

  const auto &pairs_ptr = F2128_MTA::prepare_batched_pairs(*alpha, pads);

  auto server_work = [&]() {
    F2128_MTA::play_batched_sender(sender_ot, *pairs_ptr);
    const auto out = F2128_MTA::get_sender_batched_out(pads);
    const auto chi =
        F2128_MTA::generate_batched_randomness(*server->get_ssl_object(), true);
    CHECK(F2128_MTA::prove_consistency_batched(*server->get_ssl_object(),
                                               a_tilde, a_hat, *out, chi));
  };

  auto client_work = [&]() {
    const auto t_b = F2128_MTA::play_batched_receiver(receiver_ot, beta);
    const auto choice_bits = F2128_MTA::get_batched_choice_bits(beta);
    const auto chi = F2128_MTA::generate_batched_randomness(
        *client->get_ssl_object(), false);
    CHECK(F2128_MTA::check_consistency_batched(*client->get_ssl_object(), *t_b,
                                               chi, beta));
  };

  std::thread server_thread(server_work);
  client_work();
  server_thread.join();
}
//! [CheckConsistencyBatched]

TEST_CASE("do_batched_ot") {
  auto context = CreateContextWithTestCertificate(TLS_method());
  REQUIRE(context);
  std::unique_ptr<TLSSocket> client, server;
  REQUIRE(setup_sockets(context, server, client));
  EmpWrapper<> s_wrapper{server->get_ssl_object()};
  EmpWrapper<> c_wrapper{client->get_ssl_object()};

  emp::IKNP<EmpWrapper<>> sender_ot{&s_wrapper, true};
  emp::IKNP<EmpWrapper<>> receiver_ot{&c_wrapper, true};

  // Generate the random values.
  emp::block alpha, beta;
  Util::generate_random_bytes<sizeof(alpha)>(&alpha);
  Util::generate_random_bytes<sizeof(beta)>(&beta);

  F2128_MTA::ShareType verifier_share, prover_share;
  uint64_t verif_band{}, prover_band{};

  SUBCASE("native") {

    auto verifier_work = [&]() {
      verifier_share = F2128_MTA::generate_shares_verifier_batched(
          sender_ot, *server->get_ssl_object(), alpha, verif_band);
    };

    std::thread verifier(verifier_work);
    prover_share = F2128_MTA::generate_shares_prover_batched(
        receiver_ot, *client->get_ssl_object(), beta, prover_band);
    verifier.join();
  }

  // If we're using multiplicative secrets then we need to change how we treat
  // the starting share. The rest is the same though.
  emp::block total_secret = (F2128_MTA::use_multiplicative_shares)
                                ? F2128_MTA::mul(alpha, beta)
                                : alpha ^ beta;

  emp::block running = emp::makeBlock(0, 1);
  emp::block share;

  // Check the shares for h, h^2, h^3, ...
  for (unsigned i = 0; i < 1024; i++) {
    // Check that the shares add up.
    running = F2128_MTA::mul(running, total_secret);
    share = verifier_share[i] ^ prover_share[i];
    CHECK(emp::cmpBlock(&share, &running, 1));
  }
}
