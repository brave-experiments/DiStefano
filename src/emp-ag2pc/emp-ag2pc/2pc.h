#ifndef EMP_AG2PC_2PC_H__
#define EMP_AG2PC_2PC_H__
#include "emp-ag2pc/fpre.h"
#include <emp-tool/emp-tool.h>

namespace emp {
template <typename T, int threads, template <typename> class OTType,
          bool debug = false>
class C2PC {
public:
  const static int SSP = 5; // 5*8 in fact...
  const block MASK = makeBlock(0x0ULL, 0xFFFFFULL);

  using FpreType = Fpre<T, threads, OTType, debug>;
  FpreType *fpre = nullptr;

  using in_io_type = typename FpreType::in_io_type;

  block *mac = nullptr;
  block *key = nullptr;

  block *preprocess_mac = nullptr;
  block *preprocess_key = nullptr;

  block *sigma_mac = nullptr;
  block *sigma_key = nullptr;

  block *labels = nullptr;

  bool *mask = nullptr;
  BristolFormat *cf;
  T *io;
  int num_ands = 0;
  int party, total_pre;

  uint64_t bandwidth() noexcept { return fpre->bandwidth(); }

  C2PC(in_io_type io, int party, int tag, BristolFormat *cf) {
    this->party = party;
    this->io = nullptr;

    this->io = FpreType::get_first(io);
    this->cf = cf;

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE)
        ++num_ands;
    }

    total_pre = cf->n1 + cf->n2 + num_ands;
    fpre = new Fpre<T, threads, OTType, debug>(io, party, num_ands, tag);

    key = new block[cf->num_wire];
    mac = new block[cf->num_wire];

    preprocess_mac = new block[total_pre];
    preprocess_key = new block[total_pre];

    // sigma values in the paper
    sigma_mac = new block[num_ands];
    sigma_key = new block[num_ands];

    labels = new block[cf->num_wire];

    mask = new bool[cf->n1 + cf->n2];
  }
  ~C2PC() {
    delete[] key;
    delete[] mac;
    delete[] mask;
    delete[] GT;
    delete[] GTK;
    delete[] GTM;

    delete[] preprocess_mac;
    delete[] preprocess_key;

    delete[] sigma_mac;
    delete[] sigma_key;

    delete[] labels;
    delete fpre;
  }
  PRG prg;
  PRP prp;
  block (*GT)[4][2] = nullptr;
  block (*GTK)[4] = nullptr;
  block (*GTM)[4] = nullptr;

  // not allocation
  block *ANDS_mac = nullptr;
  block *ANDS_key = nullptr;
  void function_independent() {
    if (party == ALICE) {
      prg.random_block(labels, cf->num_wire);
    }
    fpre->refill();

    ANDS_mac = fpre->MAC_res();
    ANDS_key = fpre->KEY_res();

    fpre->independent_ot(preprocess_mac, preprocess_key, total_pre);

    memcpy(key, preprocess_key, (cf->n1 + cf->n2) * sizeof(block));
    memcpy(mac, preprocess_mac, (cf->n1 + cf->n2) * sizeof(block));
    // Flush any pending ops.
    io->flush();
  }

  void function_dependent() {
    int ands = cf->n1 + cf->n2;

    bool *x1 = new bool[num_ands]{};
    bool *y1 = new bool[num_ands]{};
    bool *x2 = new bool[num_ands]{};
    bool *y2 = new bool[num_ands]{};

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        key[cf->gates[4 * i + 2]] = preprocess_key[ands];
        mac[cf->gates[4 * i + 2]] = preprocess_mac[ands];
        ++ands;
      }
    }

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == XOR_GATE) {
        key[cf->gates[4 * i + 2]] =
            key[cf->gates[4 * i]] ^ key[cf->gates[4 * i + 1]];
        mac[cf->gates[4 * i + 2]] =
            mac[cf->gates[4 * i]] ^ mac[cf->gates[4 * i + 1]];
        if (party == ALICE)
          labels[cf->gates[4 * i + 2]] =
              labels[cf->gates[4 * i]] ^ labels[cf->gates[4 * i + 1]];
      } else if (cf->gates[4 * i + 3] == NOT_GATE) {
        if (party == ALICE)
          labels[cf->gates[4 * i + 2]] =
              labels[cf->gates[4 * i]] ^ fpre->Delta();
        key[cf->gates[4 * i + 2]] = key[cf->gates[4 * i]];
        mac[cf->gates[4 * i + 2]] = mac[cf->gates[4 * i]];
      }
    }

    ands = 0;
    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        x1[ands] = getLSB(mac[cf->gates[4 * i]] ^ ANDS_mac[3 * ands]);
        y1[ands] = getLSB(mac[cf->gates[4 * i + 1]] ^ ANDS_mac[3 * ands + 1]);
        ands++;
      }
    }

    if (party == ALICE) {
      io->send_bool(x1, num_ands);
      io->send_bool(y1, num_ands);
      io->flush();
      io->recv_bool(x2, num_ands);
      io->recv_bool(y2, num_ands);
    } else {
      io->recv_bool(x2, num_ands);
      io->recv_bool(y2, num_ands);
      io->send_bool(x1, num_ands);
      io->send_bool(y1, num_ands);
      io->flush();
    }

    for (int i = 0; i < num_ands; ++i) {
      x1[i] = logic_xor(x1[i], x2[i]);
      y1[i] = logic_xor(y1[i], y2[i]);
    }

    ands = 0;

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        sigma_mac[ands] = ANDS_mac[3 * ands + 2];
        sigma_key[ands] = ANDS_key[3 * ands + 2];

        if (x1[ands]) {
          sigma_mac[ands] = sigma_mac[ands] ^ ANDS_mac[3 * ands + 1];
          sigma_key[ands] = sigma_key[ands] ^ ANDS_key[3 * ands + 1];
        }
        if (y1[ands]) {
          sigma_mac[ands] = sigma_mac[ands] ^ ANDS_mac[3 * ands];
          sigma_key[ands] = sigma_key[ands] ^ ANDS_key[3 * ands];
        }
        if (x1[ands] and y1[ands]) {
          if (party == ALICE)
            sigma_key[ands] = sigma_key[ands] ^ fpre->ZDelta();
          else
            sigma_mac[ands] = sigma_mac[ands] ^ fpre->one();
        }

        ands++;
      }
    } // sigma_[] stores the and of input wires to each AND gates

    fpre->free_mac();
    fpre->free_key();

    GT = new block[num_ands][4][2];
    GTK = new block[num_ands][4];
    GTM = new block[num_ands][4];

    ands = 0;
    block H[4][2];
    block K[4], M[4];
    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        M[0] = sigma_mac[ands] ^ mac[cf->gates[4 * i + 2]];
        M[1] = M[0] ^ mac[cf->gates[4 * i]];
        M[2] = M[0] ^ mac[cf->gates[4 * i + 1]];
        M[3] = M[1] ^ mac[cf->gates[4 * i + 1]];
        if (party == BOB)
          M[3] = M[3] ^ fpre->one();

        K[0] = sigma_key[ands] ^ key[cf->gates[4 * i + 2]];
        K[1] = K[0] ^ key[cf->gates[4 * i]];
        K[2] = K[0] ^ key[cf->gates[4 * i + 1]];
        K[3] = K[1] ^ key[cf->gates[4 * i + 1]];
        if (party == ALICE)
          K[3] = K[3] ^ fpre->ZDelta();

        if (party == ALICE) {
          Hash(H, labels[cf->gates[4 * i]], labels[cf->gates[4 * i + 1]], i);
          for (int j = 0; j < 4; ++j) {
            H[j][0] = H[j][0] ^ M[j];
            H[j][1] = H[j][1] ^ K[j] ^ labels[cf->gates[4 * i + 2]];
            if (getLSB(M[j]))
              H[j][1] = H[j][1] ^ fpre->Delta();
            if (debug) {
              check2(M[j], K[j]);
            }
          }
          for (int j = 0; j < 4; ++j) {
            send_partial_block<T, SSP>(io, &H[j][0], 1);
            io->send_block(&H[j][1], 1);
          }
        } else {
          memcpy(GTK[ands], K, sizeof(block) * 4);
          memcpy(GTM[ands], M, sizeof(block) * 4);
          if (debug) {
            for (int j = 0; j < 4; ++j)
              check2(M[j], K[j]);
          }
          for (int j = 0; j < 4; ++j) {
            recv_partial_block<T, SSP>(io, &GT[ands][j][0], 1);
            io->recv_block(&GT[ands][j][1], 1);
          }
        }
        ++ands;
      }
    }

    io->flush();

    delete[] x1;
    delete[] x2;
    delete[] y1;
    delete[] y2;

    block tmp;
    if (party == ALICE) {
      send_partial_block<T, SSP>(io, mac, cf->n1);
      io->flush();

      for (int i = cf->n1; i < cf->n1 + cf->n2; ++i) {
        recv_partial_block<T, SSP>(io, &tmp, 1);
        block ttt = key[i] ^ fpre->Delta();
        ttt = ttt & MASK;
        block mask_key = key[i] & MASK;
        tmp = tmp & MASK;
        if (cmpBlock(&tmp, &mask_key, 1))
          mask[i] = false;
        else if (cmpBlock(&tmp, &ttt, 1))
          mask[i] = true;
        else
          cout << "no match! ALICE\t" << i << endl;
      }
    } else {
      for (int i = 0; i < cf->n1; ++i) {
        recv_partial_block<T, SSP>(io, &tmp, 1);
        block ttt = key[i] ^ fpre->Delta();
        ttt = ttt & MASK;
        tmp = tmp & MASK;
        block mask_key = key[i] & MASK;
        if (cmpBlock(&tmp, &mask_key, 1)) {
          mask[i] = false;
        } else if (cmpBlock(&tmp, &ttt, 1)) {
          mask[i] = true;
        } else
          cout << "no match! BOB\t" << i << endl;
      }

      send_partial_block<T, SSP>(io, mac + cf->n1, cf->n2);
    }
    io->flush();
  }

  void online(const bool *input, bool *output, bool alice_output = false) {
    uint8_t *mask_input = new uint8_t[cf->num_wire];
    memset(mask_input, 0, cf->num_wire);
    block tmp;
    if (debug) {
      for (int i = 0; i < cf->n1 + cf->n2; ++i)
        check2(mac[i], key[i]);
    }
    if (party == ALICE) {
      for (int i = cf->n1; i < cf->n1 + cf->n2; ++i) {
        mask_input[i] = logic_xor(input[i], getLSB(mac[i]));
        mask_input[i] = logic_xor(mask_input[i], mask[i]);
      }
      io->recv_data(mask_input, cf->n1);
      io->send_data(mask_input + cf->n1, cf->n2);
      for (int i = 0; i < cf->n1 + cf->n2; ++i) {
        tmp = labels[i];
        if (mask_input[i])
          tmp = tmp ^ fpre->Delta();
        io->send_block(&tmp, 1);
      }
      // send output mask data
      send_partial_block<T, SSP>(io, mac + cf->num_wire - cf->n3, cf->n3);
      io->flush();
    } else {
      for (int i = 0; i < cf->n1; ++i) {
        mask_input[i] = logic_xor(input[i], getLSB(mac[i]));
        mask_input[i] = logic_xor(mask_input[i], mask[i]);
      }

      io->send_data(mask_input, cf->n1);
      io->flush();
      io->recv_data(mask_input + cf->n1, cf->n2);
      io->recv_block(labels, cf->n1 + cf->n2);
    }
    int ands = 0;
    if (party == BOB) {
      for (int i = 0; i < cf->num_gate; ++i) {
        if (cf->gates[4 * i + 3] == XOR_GATE) {
          labels[cf->gates[4 * i + 2]] =
              labels[cf->gates[4 * i]] ^ labels[cf->gates[4 * i + 1]];
          mask_input[cf->gates[4 * i + 2]] = logic_xor(
              mask_input[cf->gates[4 * i]], mask_input[cf->gates[4 * i + 1]]);
        } else if (cf->gates[4 * i + 3] == AND_GATE) {
          int index = 2 * mask_input[cf->gates[4 * i]] +
                      mask_input[cf->gates[4 * i + 1]];
          block H[2];
          Hash(H, labels[cf->gates[4 * i]], labels[cf->gates[4 * i + 1]], i,
               index);
          GT[ands][index][0] = GT[ands][index][0] ^ H[0];
          GT[ands][index][1] = GT[ands][index][1] ^ H[1];

          block ttt = GTK[ands][index] ^ fpre->Delta();
          ttt = ttt & MASK;
          GTK[ands][index] = GTK[ands][index] & MASK;
          GT[ands][index][0] = GT[ands][index][0] & MASK;

          if (cmpBlock(&GT[ands][index][0], &GTK[ands][index], 1))
            mask_input[cf->gates[4 * i + 2]] = false;
          else if (cmpBlock(&GT[ands][index][0], &ttt, 1))
            mask_input[cf->gates[4 * i + 2]] = true;
          else
            cout << ands << " no match GT!" << endl;
          mask_input[cf->gates[4 * i + 2]] = logic_xor(
              mask_input[cf->gates[4 * i + 2]], getLSB(GTM[ands][index]));

          labels[cf->gates[4 * i + 2]] = GT[ands][index][1] ^ GTM[ands][index];
          ands++;
        } else {
          mask_input[cf->gates[4 * i + 2]] = not mask_input[cf->gates[4 * i]];
          labels[cf->gates[4 * i + 2]] = labels[cf->gates[4 * i]];
        }
      }
    }
    if (party == BOB) {
      bool *o = new bool[cf->n3];
      for (int i = 0; i < cf->n3; ++i) {
        block tmp;
        recv_partial_block<T, SSP>(io, &tmp, 1);
        tmp = tmp & MASK;

        block ttt = key[cf->num_wire - cf->n3 + i] ^ fpre->Delta();
        ttt = ttt & MASK;
        key[cf->num_wire - cf->n3 + i] = key[cf->num_wire - cf->n3 + i] & MASK;

        if (cmpBlock(&tmp, &key[cf->num_wire - cf->n3 + i], 1))
          o[i] = false;
        else if (cmpBlock(&tmp, &ttt, 1))
          o[i] = true;
        else
          cout << "no match output label!" << endl;
      }
      for (int i = 0; i < cf->n3; ++i) {
        output[i] = logic_xor(o[i], mask_input[cf->num_wire - cf->n3 + i]);
        output[i] =
            logic_xor(output[i], getLSB(mac[cf->num_wire - cf->n3 + i]));
      }
      delete[] o;
      if (alice_output) {
        send_partial_block<T, SSP>(io, mac + cf->num_wire - cf->n3, cf->n3);
        send_partial_block<T, SSP>(io, labels + cf->num_wire - cf->n3, cf->n3);
        io->send_data(mask_input + cf->num_wire - cf->n3, cf->n3);
        io->flush();
      }
    } else { // ALICE
      if (alice_output) {
        block *tmp_mac = new block[cf->n3];
        block *tmp_label = new block[cf->n3];
        bool *tmp_mask_input = new bool[cf->n3];
        recv_partial_block<T, SSP>(io, tmp_mac, cf->n3);
        recv_partial_block<T, SSP>(io, tmp_label, cf->n3);
        io->recv_data(tmp_mask_input, cf->n3);
        io->flush();
        for (int i = 0; i < cf->n3; ++i) {
          block tmp = tmp_mac[i];
          tmp = tmp & MASK;

          block ttt = key[cf->num_wire - cf->n3 + i] ^ fpre->Delta();
          ttt = ttt & MASK;
          key[cf->num_wire - cf->n3 + i] =
              key[cf->num_wire - cf->n3 + i] & MASK;

          if (cmpBlock(&tmp, &key[cf->num_wire - cf->n3 + i], 1))
            output[i] = false;
          else if (cmpBlock(&tmp, &ttt, 1))
            output[i] = true;
          else
            cout << "no match output label!" << endl;
          block mask_label = tmp_label[i];
          if (tmp_mask_input[i])
            mask_label = mask_label ^ fpre->Delta();
          mask_label = mask_label & MASK;
          block masked_labels = labels[cf->num_wire - cf->n3 + i] & MASK;
          if (!cmpBlock(&mask_label, &masked_labels, 1))
            cout << "no match output label2!" << endl;

          output[i] = logic_xor(output[i], tmp_mask_input[i]);
          output[i] =
              logic_xor(output[i], getLSB(mac[cf->num_wire - cf->n3 + i]));
        }
        delete[] tmp_mac;
        delete[] tmp_label;
        delete[] tmp_mask_input;
      }
    }
    delete[] mask_input;
  }

  void check(block *MAC, block *KEY, bool *r, int length = 1) {
    if (party == ALICE) {
      io->send_data(r, length * 3);
      io->send_block(&fpre->Delta(), 1);
      io->send_block(KEY, length * 3);
      io->flush();
      block DD;
      io->recv_block(&DD, 1);

      for (int i = 0; i < length * 3; ++i) {
        block tmp;
        io->recv_block(&tmp, 1);
        if (r[i])
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC[i], 1))
          cout << i << "\tWRONG ABIT!\n";
      }

    } else {
      bool tmp[3];
      for (int i = 0; i < length; ++i) {
        io->recv_data(tmp, 3);
        bool res =
            (logic_xor(tmp[0], r[3 * i])) and (logic_xor(tmp[1], r[3 * i + 1]));
        if (res != logic_xor(tmp[2], r[3 * i + 2])) {
          cout << i << "\tWRONG!\n";
        }
      }
      block DD;
      io->recv_block(&DD, 1);

      for (int i = 0; i < length * 3; ++i) {
        block tmp;
        io->recv_block(&tmp, 1);
        if (r[i])
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC[i], 1))
          cout << i << "\tWRONG ABIT!\n";
      }
      io->send_block(&fpre->Delta(), 1);
      io->send_block(KEY, length * 3);
    }
    io->flush();
  }

  void check2(block &MAC, block &KEY) {
    if (party == ALICE) {
      io->send_block(&fpre->Delta(), 1);
      io->send_block(&KEY, 1);
      io->flush();
      block DD;
      io->recv_block(&DD, 1);
      for (int i = 0; i < 1; ++i) {
        block tmp;
        io->recv_block(&tmp, 1);
        if (getLSB(MAC))
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC, 1))
          cout << i << "\tWRONG ABIT!2\n";
      }
    } else {
      block DD;
      io->recv_block(&DD, 1);
      for (int i = 0; i < 1; ++i) {
        block tmp;
        io->recv_block(&tmp, 1);
        if (getLSB(MAC))
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC, 1))
          cout << i << "\tWRONG ABIT!2\n";
      }
      io->send_block(&fpre->Delta(), 1);
      io->send_block(&KEY, 1);
    }
    io->flush();
  }

  void Hash(block H[4][2], const block &a, const block &b, uint64_t i) {
    block A[2], B[2];
    A[0] = a;
    A[1] = a ^ fpre->Delta();
    B[0] = b;
    B[1] = b ^ fpre->Delta();
    A[0] = sigma(A[0]);
    A[1] = sigma(A[1]);
    B[0] = sigma(sigma(B[0]));
    B[1] = sigma(sigma(B[1]));

    H[0][1] = H[0][0] = A[0] ^ B[0];
    H[1][1] = H[1][0] = A[0] ^ B[1];
    H[2][1] = H[2][0] = A[1] ^ B[0];
    H[3][1] = H[3][0] = A[1] ^ B[1];
    for (uint64_t j = 0; j < 4; ++j) {
      H[j][0] = H[j][0] ^ makeBlock(4 * i + j, 0);
      H[j][1] = H[j][1] ^ makeBlock(4 * i + j, 1);
    }
    prp.permute_block((block *)H, 8);
  }

  void Hash(block H[2], block a, block b, uint64_t i, uint64_t row) {
    a = sigma(a);
    b = sigma(sigma(b));
    H[0] = H[1] = a ^ b;
    H[0] = H[0] ^ makeBlock(4 * i + row, 0);
    H[1] = H[1] ^ makeBlock(4 * i + row, 1);
    prp.permute_block((block *)H, 2);
  }

  bool logic_xor(bool a, bool b) { return a != b; }
};
} // namespace emp
#endif // C2PC_H__
