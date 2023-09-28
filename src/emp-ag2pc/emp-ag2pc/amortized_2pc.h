#ifndef EMP_AG2PC_AMORTIZED_C2PC_H__
#define EMP_AG2PC_AMORTIZED_C2PC_H__
#include "emp-ag2pc/fpre.h"
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>

namespace emp {
template <typename T, int exec, template<typename> class OTType, bool debug = false> class AmortizedC2PC {
public:
  const static int SSP = 5; // 5*8 in fact...
  const block MASK = makeBlock(0x0ULL, 0xFFFFFULL);
  Fpre<T, 1, OTType, debug> *fpre = nullptr;
  using in_io_type = typename Fpre<T, 1, OTType, debug>::in_io_type;
  block *mac[exec];
  block *key[exec];

  block *preprocess_mac;
  block *preprocess_key;

  block *sigma_mac[exec];
  block *sigma_key[exec];

  block *labels[exec];

  bool *mask[exec];
  BristolFormat *cf;
  T *io;
  int num_ands = 0;
  int party, total_pre;
  int exec_times = 0;
  bool *x1[exec];
  bool *y1[exec];
  bool *x2[exec];
  bool *y2[exec];

  AmortizedC2PC(in_io_type io, int party, int tag, BristolFormat *cf) {
    this->party = party;
    this->io = io[0];
    this->cf = cf;
    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE)
        ++num_ands;
    }
    total_pre = cf->n1 + cf->n2 + num_ands;
    fpre = new Fpre<T, 1, OTType, debug>(io, party, num_ands * exec, tag);

    preprocess_mac = new block[total_pre * exec];
    preprocess_key = new block[total_pre * exec];

    for (int i = 0; i < exec; ++i) {
      x1[i] = new bool[num_ands];
      y1[i] = new bool[num_ands];
      x2[i] = new bool[num_ands];
      y2[i] = new bool[num_ands];

      key[i] = new block[cf->num_wire];
      mac[i] = new block[cf->num_wire];

      // sigma values in the paper
      sigma_mac[i] = new block[num_ands];
      sigma_key[i] = new block[num_ands];

      labels[i] = new block[cf->num_wire];
      GT[i] = new block[num_ands][4][2];
      GTK[i] = new block[num_ands][4];
      GTM[i] = new block[num_ands][4];
      mask[i] = new bool[cf->n1 + cf->n2];
    }
  }
  ~AmortizedC2PC() {
    for (int i = 0; i < exec; ++i) {
      delete[] key[i];
      delete[] mac[i];
      delete[] GT[i];
      delete[] GTK[i];
      delete[] GTM[i];

      delete[] sigma_mac[i];
      delete[] sigma_key[i];

      delete[] labels[i];
      delete[] mask[i];
      delete[] x1[i];
      delete[] x2[i];
      delete[] y1[i];
      delete[] y2[i];
    }
    delete[] preprocess_mac;
    delete[] preprocess_key;
    delete fpre;
  }

  PRG prg;
  PRP prp;
  block (*GT[exec])[4][2];
  block (*GTK[exec])[4];
  block (*GTM[exec])[4];

  // not allocation
  block *ANDS_mac[exec];
  block *ANDS_key[exec];
  void function_independent() {
    if (party == ALICE) {
      for (int e = 0; e < exec; ++e)
        prg.random_block(labels[e], total_pre);
    }

    fpre->refill();
    for (int e = 0; e < exec; ++e) {
      ANDS_mac[e] = fpre->MAC_res() + 3 * e * num_ands;
      ANDS_key[e] = fpre->KEY_res() + 3 * e * num_ands;
    }
    fpre->independent_ot(preprocess_mac, preprocess_key, exec * total_pre);
    for (int i = 0; i < exec; ++i) {
      memcpy(key[i], preprocess_key + total_pre * i,
             (cf->n1 + cf->n2) * sizeof(block));
      memcpy(mac[i], preprocess_mac + total_pre * i,
             (cf->n1 + cf->n2) * sizeof(block));
    }
  }
  
  void function_dependent_st() {
    int ands = cf->n1 + cf->n2;

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        for (int e = 0; e < exec; ++e) {
          key[e][cf->gates[4 * i + 2]] = preprocess_key[e * total_pre + ands];
          mac[e][cf->gates[4 * i + 2]] = preprocess_mac[e * total_pre + ands];
        }
        ++ands;
      }
    }

    for (int e = 0; e < exec; ++e)
      for (int i = 0; i < cf->num_gate; ++i) {
        if (cf->gates[4 * i + 3] == XOR_GATE) {
          key[e][cf->gates[4 * i + 2]] =
              key[e][cf->gates[4 * i]] ^ key[e][cf->gates[4 * i + 1]];
          mac[e][cf->gates[4 * i + 2]] =
              mac[e][cf->gates[4 * i]] ^ mac[e][cf->gates[4 * i + 1]];
          if (party == ALICE)
            labels[e][cf->gates[4 * i + 2]] =
                labels[e][cf->gates[4 * i]] ^ labels[e][cf->gates[4 * i + 1]];
        } else if (cf->gates[4 * i + 3] == NOT_GATE) {
          if (party == ALICE)
            labels[e][cf->gates[4 * i + 2]] =
                labels[e][cf->gates[4 * i]] ^ fpre->Delta();

          key[e][cf->gates[4 * i + 2]] = key[e][cf->gates[4 * i]];
          mac[e][cf->gates[4 * i + 2]] = mac[e][cf->gates[4 * i]];
        }
      }
    for (int e = 0; e < exec; ++e) {
      ands = 0;
      for (int i = 0; i < cf->num_gate; ++i) {
        if (cf->gates[4 * i + 3] == AND_GATE) {
          x1[e][ands] =
              getLSB(mac[e][cf->gates[4 * i]] ^ ANDS_mac[e][3 * ands]);
          y1[e][ands] =
              getLSB(mac[e][cf->gates[4 * i + 1]] ^ ANDS_mac[e][3 * ands + 1]);
          ands++;
        }
      }
    }

    if (party == ALICE) {
      for (int e = 0; e < exec; ++e) {
        io->send_bool(x1[e], num_ands);
        io->send_bool(y1[e], num_ands);
      }
      io->flush();
      for (int e = 0; e < exec; ++e) {
        io->recv_bool(x2[e], num_ands);
        io->recv_bool(y2[e], num_ands);
      }
    } else {
      for (int e = 0; e < exec; ++e) {
        io->recv_bool(x2[e], num_ands);
        io->recv_bool(y2[e], num_ands);
      }
      for (int e = 0; e < exec; ++e) {
        io->send_bool(x1[e], num_ands);
        io->send_bool(y1[e], num_ands);
      }
      io->flush();
    }

    for (int e = 0; e < exec; ++e)
      for (int i = 0; i < num_ands; ++i) {
        x1[e][i] = logic_xor(x1[e][i], x2[e][i]);
        y1[e][i] = logic_xor(y1[e][i], y2[e][i]);
      }
    for (int e = 0; e < exec; ++e) {
      ands = 0;
      for (int i = 0; i < cf->num_gate; ++i) {
        if (cf->gates[4 * i + 3] == AND_GATE) {
          sigma_mac[e][ands] = ANDS_mac[e][3 * ands + 2];
          sigma_key[e][ands] = ANDS_key[e][3 * ands + 2];
          if (x1[e][ands]) {
            sigma_mac[e][ands] = sigma_mac[e][ands] ^ ANDS_mac[e][3 * ands + 1];
            sigma_key[e][ands] = sigma_key[e][ands] ^ ANDS_key[e][3 * ands + 1];
          }
          if (y1[e][ands]) {
            sigma_mac[e][ands] = sigma_mac[e][ands] ^ ANDS_mac[e][3 * ands];
            sigma_key[e][ands] = sigma_key[e][ands] ^ ANDS_key[e][3 * ands];
          }
          if (x1[e][ands] and y1[e][ands]) {
            if (party == ALICE) {
              sigma_key[e][ands] = sigma_key[e][ands] ^ fpre->Delta();
              sigma_key[e][ands] = sigma_key[e][ands] ^ makeBlock(0, 1);
            } else
              sigma_mac[e][ands] = sigma_mac[e][ands] ^ makeBlock(0, 1);
          }

          ands++;
        }
      } // sigma_[] stores the and of input wires to each AND gates
    }

    block H[4][2];
    block K[4], M[4];
    for (int e = 0; e < exec; ++e) {
      ands = 0;
      for (int i = 0; i < cf->num_gate; ++i) {
        if (cf->gates[4 * i + 3] == AND_GATE) {
          M[0] = sigma_mac[e][ands] ^ mac[e][cf->gates[4 * i + 2]];
          M[1] = M[0] ^ mac[e][cf->gates[4 * i]];
          M[2] = M[0] ^ mac[e][cf->gates[4 * i + 1]];
          M[3] = M[1] ^ mac[e][cf->gates[4 * i + 1]];
          if (party == BOB)
            M[3] = M[3] ^ makeBlock(0, 1);

          K[0] = sigma_key[e][ands] ^ key[e][cf->gates[4 * i + 2]];
          K[1] = K[0] ^ key[e][cf->gates[4 * i]];
          K[2] = K[0] ^ key[e][cf->gates[4 * i + 1]];
          K[3] = K[1] ^ key[e][cf->gates[4 * i + 1]];
          if (party == ALICE) {
            K[3] = K[3] ^ fpre->Delta();
            K[3] = K[3] ^ makeBlock(0, 1);
          }

          if (party == ALICE) {
            Hash(H, labels[e][cf->gates[4 * i]],
                 labels[e][cf->gates[4 * i + 1]], i);
            for (int j = 0; j < 4; ++j) {
              H[j][0] = H[j][0] ^ M[j];
              H[j][1] = H[j][1] ^ K[j] ^ labels[e][cf->gates[4 * i + 2]];
              if (getLSB(M[j]))
                H[j][1] = H[j][1] ^ fpre->Delta();
            }
            for (int j = 0; j < 4; ++j) {
              send_partial_block<T, SSP>(io, &H[j][0], 1);
              io->send_block(&H[j][1], 1);
            }
            io->flush();

          } else {
            memcpy(GTK[e][ands], K, sizeof(block) * 4);
            memcpy(GTM[e][ands], M, sizeof(block) * 4);

            for (int j = 0; j < 4; ++j) {
              recv_partial_block<T, SSP>(io, &GT[e][ands][j][0], 1);
              io->recv_block(&GT[e][ands][j][1], 1);
            }
          }
          ++ands;
        }
      }
    }

    block tmp;
    if (party == ALICE) {
      for (int e = 0; e < exec; ++e)
        send_partial_block<T, SSP>(io, mac[e], cf->n1);

      for (int e = 0; e < exec; ++e)
        for (int i = cf->n1; i < cf->n1 + cf->n2; ++i) {
          recv_partial_block<T, SSP>(io, &tmp, 1);
          block ttt = key[e][i] ^ fpre->Delta();
          ttt = ttt & MASK;
          block mask_key = key[e][i] & MASK;
          tmp = tmp & MASK;

          if (cmpBlock(&tmp, &mask_key, 1))
            mask[e][i] = false;
          else if (cmpBlock(&tmp, &ttt, 1))
            mask[e][i] = true;
          else
            cout << "no match! ALICE\t" << i << endl;
        }
    } else {
      for (int e = 0; e < exec; ++e)
        for (int i = 0; i < cf->n1; ++i) {
          recv_partial_block<T, SSP>(io, &tmp, 1);
          block ttt = key[e][i] ^ fpre->Delta();
          ttt = ttt & MASK;
          tmp = tmp & MASK;
          block mask_key = key[e][i] & MASK;

          if (cmpBlock(&tmp, &mask_key, 1)) {
            mask[e][i] = false;
          } else if (cmpBlock(&tmp, &ttt, 1)) {
            mask[e][i] = true;
          } else
            cout << "no match! BOB\t" << i << endl;
        }
      for (int e = 0; e < exec; ++e)
        send_partial_block<T, SSP>(io, mac[e] + cf->n1, cf->n2);
    }
  }

  void function_dependent() {
    for (int i = 0; i < exec; i++) {
      function_dependent_thread(i, i);
    }
  }
  void function_dependent_thread(int e, int I) {
    int ands = cf->n1 + cf->n2;

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        key[e][cf->gates[4 * i + 2]] = preprocess_key[e * total_pre + ands];
        mac[e][cf->gates[4 * i + 2]] = preprocess_mac[e * total_pre + ands];
        ++ands;
      }
    }

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == XOR_GATE) {
        key[e][cf->gates[4 * i + 2]] =
            key[e][cf->gates[4 * i]] ^ key[e][cf->gates[4 * i + 1]];
        mac[e][cf->gates[4 * i + 2]] =
            mac[e][cf->gates[4 * i]] ^ mac[e][cf->gates[4 * i + 1]];
        if (party == ALICE)
          labels[e][cf->gates[4 * i + 2]] =
              labels[e][cf->gates[4 * i]] ^ labels[e][cf->gates[4 * i + 1]];
        ;
      } else if (cf->gates[4 * i + 3] == NOT_GATE) {
        if (party == ALICE)
          labels[e][cf->gates[4 * i + 2]] =
              labels[e][cf->gates[4 * i]] ^ fpre->Delta();
        key[e][cf->gates[4 * i + 2]] = key[e][cf->gates[4 * i]];
        mac[e][cf->gates[4 * i + 2]] = mac[e][cf->gates[4 * i]];
      }
    }
    ands = 0;
    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        x1[e][ands] = getLSB(mac[e][cf->gates[4 * i]] ^ ANDS_mac[e][3 * ands]);
        y1[e][ands] =
            getLSB(mac[e][cf->gates[4 * i + 1]] ^ ANDS_mac[e][3 * ands + 1]);
        ands++;
      }
    }

    if (party == ALICE) {
      io->send_bool(x1[e], num_ands);
      io->send_bool(y1[e], num_ands);
      io->flush();
      io->recv_bool(x2[e], num_ands);
      io->recv_bool(y2[e], num_ands);
    } else {
      io->recv_bool(x2[e], num_ands);
      io->recv_bool(y2[e], num_ands);
      io->send_bool(x1[e], num_ands);
      io->send_bool(y1[e], num_ands);
      io->flush();
    }

    for (int i = 0; i < num_ands; ++i) {
      x1[e][i] = logic_xor(x1[e][i], x2[e][i]);
      y1[e][i] = logic_xor(y1[e][i], y2[e][i]);
    }
    
    ands = 0;
    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        sigma_mac[e][ands] = ANDS_mac[e][3 * ands + 2];
        sigma_key[e][ands] = ANDS_key[e][3 * ands + 2];
        if (x1[e][ands]) {
          sigma_mac[e][ands] = sigma_mac[e][ands] ^ ANDS_mac[e][3 * ands + 1];
          sigma_key[e][ands] = sigma_key[e][ands] ^ ANDS_key[e][3 * ands + 1];
        }
        if (y1[e][ands]) {
          sigma_mac[e][ands] = sigma_mac[e][ands] ^ ANDS_mac[e][3 * ands];
          sigma_key[e][ands] = sigma_key[e][ands] ^ ANDS_key[e][3 * ands];
        }
        if (x1[e][ands] and y1[e][ands]) {
          if (party == ALICE) {
            sigma_key[e][ands] = sigma_key[e][ands] ^ fpre->Delta();
            sigma_key[e][ands] = sigma_key[e][ands] ^ makeBlock(0, 1);

          } else
            sigma_mac[e][ands] = sigma_mac[e][ands] ^ makeBlock(0, 1);
        }

        ands++;
      }
    } // sigma_[] stores the and of input wires to each AND gates

    block H[4][2];
    block K[4], M[4];
    ands = 0;
    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        M[0] = sigma_mac[e][ands] ^ mac[e][cf->gates[4 * i + 2]];
        M[1] = M[0] ^ mac[e][cf->gates[4 * i]];
        M[2] = M[0] ^ mac[e][cf->gates[4 * i + 1]];
        M[3] = M[1] ^ mac[e][cf->gates[4 * i + 1]];
        if (party == BOB)
          M[3] = M[3] ^ makeBlock(0, 1);

        K[0] = sigma_key[e][ands] ^ key[e][cf->gates[4 * i + 2]];
        K[1] = K[0] ^ key[e][cf->gates[4 * i]];
        K[2] = K[0] ^ key[e][cf->gates[4 * i + 1]];
        K[3] = K[1] ^ key[e][cf->gates[4 * i + 1]];
        if (party == ALICE) {
          K[3] = K[3] ^ fpre->Delta();
          K[3] = K[3] ^ makeBlock(0, 1);
        }

        if (party == ALICE) {
          Hash(H, labels[e][cf->gates[4 * i]], labels[e][cf->gates[4 * i + 1]],
               i);
          for (int j = 0; j < 4; ++j) {
            H[j][0] = H[j][0] ^ M[j];
            H[j][1] = H[j][1] ^ K[j] ^ labels[e][cf->gates[4 * i + 2]];
            if (getLSB(M[j]))
              H[j][1] = H[j][1] ^ fpre->Delta();
          }
          for (int j = 0; j < 4; ++j) {
            send_partial_block<T, SSP>(io, &H[j][0], 1);
            io->send_block(&H[j][1], 1);
          }
        } else {
          memcpy(GTK[e][ands], K, sizeof(block) * 4);
          memcpy(GTM[e][ands], M, sizeof(block) * 4);
  
          for (int j = 0; j < 4; ++j) {
            recv_partial_block<T, SSP>(io, &GT[e][ands][j][0], 1);
            io->recv_block(&GT[e][ands][j][1], 1);
          }
        }
        ++ands;
      }
    }
    io->flush();

    block tmp;
    if (party == ALICE) {
      send_partial_block<T, SSP>(io, mac[e], cf->n1);
      io->flush();
      for (int i = cf->n1; i < cf->n1 + cf->n2; ++i) {
        recv_partial_block<T, SSP>(io, &tmp, 1);
        block ttt = key[e][i] ^ fpre->Delta();
        ttt = ttt & MASK;
        block mask_key = key[e][i] & MASK;
        tmp = tmp & MASK;
        if (cmpBlock(&tmp, &mask_key, 1))
          mask[e][i] = false;
        else if (cmpBlock(&tmp, &ttt, 1))
          mask[e][i] = true;
        else
          cout << "no match! ALICE\t" << i << endl;
      }
    } else {
      for (int i = 0; i < cf->n1; ++i) {
        recv_partial_block<T, SSP>(io, &tmp, 1);
        block ttt = key[e][i] ^ fpre->Delta();
        ttt = ttt & MASK;
        tmp = tmp & MASK;
        block mask_key = key[e][i] & MASK;
        if (cmpBlock(&tmp, &mask_key, 1)) {
          mask[e][i] = false;
        } else if (cmpBlock(&tmp, &ttt, 1)) {
          mask[e][i] = true;
        } else
          cout << "no match! BOB\t" << i << endl;
      }
      send_partial_block<T, SSP>(io, mac[e] + cf->n1, cf->n2);
    }
    io->flush();
  }

  void online(const bool * const input, bool * const output) {
    uint8_t *mask_input = new uint8_t[cf->num_wire];
    memset(mask_input, 0, cf->num_wire);
    block tmp;

    if (party == ALICE) {
      for (int i = cf->n1; i < cf->n1 + cf->n2; ++i) {
        mask_input[i] =
            logic_xor(input[i], getLSB(mac[exec_times][i]));
        mask_input[i] = logic_xor(mask_input[i], mask[exec_times][i]);
      }
      io->recv_data(mask_input, cf->n1);
      io->send_data(mask_input + cf->n1, cf->n2);
      for (int i = 0; i < cf->n1 + cf->n2; ++i) {
        tmp = labels[exec_times][i];
        if (mask_input[i])
          tmp = tmp ^ fpre->Delta();
        io->send_block(&tmp, 1);
      }
      // send output mask data
      send_partial_block<T, SSP>(io, mac[exec_times] + cf->num_wire - cf->n3,
                                 cf->n3);
      io->flush();
    } else {
      for (int i = 0; i < cf->n1; ++i) {
        mask_input[i] = logic_xor(input[i], getLSB(mac[exec_times][i]));
        mask_input[i] = logic_xor(mask_input[i], mask[exec_times][i]);
      }
      io->send_data(mask_input, cf->n1);
      io->flush();
      io->recv_data(mask_input + cf->n1, cf->n2);
      io->recv_block(labels[exec_times], cf->n1 + cf->n2);
    }
    int ands = 0;
    if (party == BOB) {
      for (int i = 0; i < cf->num_gate; ++i) {
        if (cf->gates[4 * i + 3] == XOR_GATE) {
          labels[exec_times][cf->gates[4 * i + 2]] =
              labels[exec_times][cf->gates[4 * i]] ^
              labels[exec_times][cf->gates[4 * i + 1]];
          mask_input[cf->gates[4 * i + 2]] = logic_xor(
              mask_input[cf->gates[4 * i]], mask_input[cf->gates[4 * i + 1]]);
        } else if (cf->gates[4 * i + 3] == AND_GATE) {
          int index = 2 * mask_input[cf->gates[4 * i]] +
                      mask_input[cf->gates[4 * i + 1]];
          block H[2];
          Hash(H, labels[exec_times][cf->gates[4 * i]],
               labels[exec_times][cf->gates[4 * i + 1]], i, index);
          GT[exec_times][ands][index][0] =
              GT[exec_times][ands][index][0] ^ H[0];
          GT[exec_times][ands][index][1] =
              GT[exec_times][ands][index][1] ^ H[1];

          block ttt = GTK[exec_times][ands][index] ^ fpre->Delta();
          ttt = ttt & MASK;
          GTK[exec_times][ands][index] = GTK[exec_times][ands][index] & MASK;
          GT[exec_times][ands][index][0] =
              GT[exec_times][ands][index][0] & MASK;

          if (cmpBlock(&GT[exec_times][ands][index][0],
                       &GTK[exec_times][ands][index], 1))
            mask_input[cf->gates[4 * i + 2]] = false;
          else if (cmpBlock(&GT[exec_times][ands][index][0], &ttt, 1))
            mask_input[cf->gates[4 * i + 2]] = true;
          else
            cout << ands << "no match GT!" << endl;
          mask_input[cf->gates[4 * i + 2]] =
              logic_xor(mask_input[cf->gates[4 * i + 2]],
                        getLSB(GTM[exec_times][ands][index]));

          labels[exec_times][cf->gates[4 * i + 2]] =
              GT[exec_times][ands][index][1] ^ GTM[exec_times][ands][index];
          ands++;
        } else {
          mask_input[cf->gates[4 * i + 2]] = not mask_input[cf->gates[4 * i]];
          labels[exec_times][cf->gates[4 * i + 2]] =
              labels[exec_times][cf->gates[4 * i]];
        }
      }
    }
    if (party == BOB) {
      bool *o = new bool[cf->n3];
      for (int i = 0; i < cf->n3; ++i) {
        block tmp;
        recv_partial_block<T, SSP>(io, &tmp, 1);
        tmp = tmp & MASK;

        block ttt = key[exec_times][cf->num_wire - cf->n3 + i] ^ fpre->Delta();
        ttt = ttt & MASK;
        key[exec_times][cf->num_wire - cf->n3 + i] =
            key[exec_times][cf->num_wire - cf->n3 + i] & MASK;

        if (cmpBlock(&tmp, &key[exec_times][cf->num_wire - cf->n3 + i], 1))
          o[i] = false;
        else if (cmpBlock(&tmp, &ttt, 1))
          o[i] = true;
        else
          cout << "no match output label!" << endl;
      }
      for (int i = 0; i < cf->n3; ++i) {
        output[i] = logic_xor(o[i], mask_input[cf->num_wire - cf->n3 + i]);
        output[i] = logic_xor(
            output[i], getLSB(mac[exec_times][cf->num_wire - cf->n3 + i]));
      }
      delete[] o;
    }
    exec_times++;
    delete[] mask_input;
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
      H[j][0] = H[j][0] ^ _mm_set_epi64x(4 * i + j, 0ULL);
      H[j][1] = H[j][1] ^ _mm_set_epi64x(4 * i + j, 1ULL);
    }
    prp.permute_block((block *)H, 8);
  }

  void Hash(block H[2], block a, block b, uint64_t i, uint64_t row) {
    a = sigma(a);
    b = sigma(sigma(b));
    H[0] = H[1] = a ^ b;
    H[0] = H[0] ^ _mm_set_epi64x(4 * i + row, 0ULL);
    H[1] = H[1] ^ _mm_set_epi64x(4 * i + row, 1ULL);
    ;
    prp.permute_block((block *)H, 2);
  }

  bool logic_xor(bool a, bool b) {
    return a != b;
    if (a)
      if (not b)
        return true;
    if (not a)
      if (b)
        return true;
    return false;
  }
  string tostring(bool a) {
    if (a)
      return "T";
    else
      return "F";
  }
};
} // namespace emp
#endif // AMORTIZED_C2PC_H__
