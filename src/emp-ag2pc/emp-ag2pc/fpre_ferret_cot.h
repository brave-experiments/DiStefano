#ifndef EMP_AG2PC_FPRE_FERRET_COT_H__
#define EMP_AG2PC_FPRE_FERRET_COT_H__
#include "emp-ag2pc/feq.h"
#include "emp-ag2pc/helper.h"
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>
#include <thread>

namespace emp {

template <typename T, int threads, bool debug = false> class FpreFerretCOT {
public:

  using in_io_type = T *[threads+1];
  
  int batch_size = 0, bucket_size = 0, size = 0;
  int party;
  block *keys = nullptr;
  bool *values = nullptr;
  PRG prg;
  PRP prp;
  PRP *prps;

  T *io[threads + 1];
  uint64_t bandwidth() {
    uint64_t sum = 0;
    if (threads == 1 && (io[0] == io[1])) {
        return io[0]->counter;
    }
    
    for (int i = 0; i < threads + 1; ++i)
      sum += io[i]->counter;
    
    return sum;
  }

  FerretCOT<T> *abit1, *abit2;
  block Delta;
  block ZDelta;
  block one;
  Feq<T> *eq[threads];
  block *MAC = nullptr, *KEY = nullptr;
  block *MAC_res = nullptr, *KEY_res = nullptr;


  template<typename F> static T* get_first(F ios) {
    static_assert(std::is_same_v<F, T**>);
    return ios[0];
  }
  
  FpreFerretCOT(in_io_type _io, int in_party, int bsize = 1000, int tag = 0) {
    this->party = in_party;
    for (int i = 0; i < threads; ++i) {
      this->io[i] = _io[i];
      eq[i] = new Feq<T>(io[i], party);
    }
    this->io[threads] = _io[threads];

    prps = new PRP[threads];
    abit1 = new FerretCOT<T>(party, threads, io, true, false);
    abit2 = new FerretCOT<T>(ALICE + BOB - party, threads, io, true, false);

    PRG prg;
    prg.random_block(&Delta, 1);
    Delta = Delta & makeBlock(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFC);
    if (party == ALICE) {
      Delta = Delta ^ makeBlock(0x0, 0x3);
      abit1->setup(Delta, string("./data/abit1") + std::to_string(party) + std::to_string(tag));
      abit2->setup(string("./data/abit2") + std::to_string(party) + std::to_string(tag));
      Delta = abit1->Delta;
    } else {
      Delta = Delta ^ makeBlock(0x0, 0x1);
      abit1->setup(string("./data/abit1") + std::to_string(party) + std::to_string(tag));
      abit2->setup(Delta, string("./data/abit2") + std::to_string(party) + std::to_string(tag));
      Delta = abit2->Delta;
    }

    one = makeBlock(0, 1);
    ZDelta = Delta & makeBlock(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE);
    set_batch_size(bsize);
  }
  int permute_batch_size;
  void set_batch_size(int size) {
    size = std::max(size, 320);
    batch_size = ((size + threads - 1) / (threads)) * threads;
    if (batch_size >= 280 * 1000) {
      bucket_size = 3;
      permute_batch_size = 280000;
    } else if (batch_size >= 3100) {
      bucket_size = 4;
      permute_batch_size = 3100;
    } else
      bucket_size = 5;
    if (MAC != nullptr) {
      delete[] MAC;
      delete[] KEY;
    }

    MAC = new block[batch_size * bucket_size * 3]{};
    KEY = new block[batch_size * bucket_size * 3]{};
    MAC_res = new block[batch_size * 3]{};
    KEY_res = new block[batch_size * 3]{};
    //std::cerr << size<<"\t"<<batch_size<<"\n";
  }
  ~FpreFerretCOT() {
    delete[] MAC;
    delete[] KEY;
    delete[] prps;
    delete[] MAC_res;
    delete[] KEY_res;
    
    delete abit1;
    delete abit2;
    for (int i = 0; i < threads; ++i) {
      delete eq[i];
    }
  }

  void independent_ot(emp::block * preprocess_mac, emp::block * preprocess_key, int total_pre) {
    if(party == ALICE) {
      abit1->rcot(preprocess_key, total_pre);
      abit2->rcot(preprocess_mac, total_pre);
    } else {
      abit1->rcot(preprocess_mac,  total_pre);
      abit2->rcot(preprocess_key, total_pre);
    }
    
  }
  
  void refill() {
    //auto start_time = clock_start();
    if (party == ALICE) {
      abit1->rcot(KEY, batch_size * bucket_size * 3);
      abit2->rcot(MAC, batch_size * bucket_size * 3);
    } else {
      abit1->rcot(MAC, batch_size * bucket_size * 3);
      abit2->rcot(KEY, batch_size * bucket_size * 3);
    }

    io[0]->flush();
    io[1]->flush();

    /*
    if (party == ALICE) {
      cout << "ABit\t" << time_from(start_time) << "\n";
      start_time = clock_start();
    }
    */
    
    int T2U = threads;
    for (int i = 0; i < T2U; ++i) {
      int start = i * (batch_size / T2U);
      int length = batch_size / T2U;
      check(MAC + start * bucket_size * 3, KEY + start * bucket_size * 3,
              length * bucket_size, i);
    }

    /*
    if (party == ALICE) {
      cout << "check\t" << time_from(start_time) << "\n";
      start_time = clock_start();
    }
    */

    if(debug) {
      check_correctness(MAC, KEY, batch_size, true);
    }
    block S = coin_tossing(prg, io[0], party);
    if (bucket_size > 4) {
      combine(S, 0, MAC, KEY, batch_size, bucket_size, MAC_res, KEY_res);
    } else {
      int width = min((batch_size + threads - 1) / threads, permute_batch_size);
      for (int i = 0; i < threads; ++i) {
        int start = i * width;
        int length = min((i + 1) * width, batch_size) - i * width;
        combine(S, i, MAC + start * bucket_size * 3,
                  KEY + start * bucket_size * 3, length, bucket_size,
                  MAC_res + start * 3, KEY_res + start * 3);
        
      }
    }
    /*
    if (party == ALICE) {
      cout << "permute\t" << time_from(start_time) << "\n";
      start_time = clock_start();
    }
    */

    if(debug) {
      check_correctness(MAC, KEY, batch_size);
    }

    char dgst[Hash::DIGEST_SIZE];
    for (int i = 1; i < threads; ++i) {
      eq[i]->dgst(dgst);
      eq[0]->add_data(dgst, Hash::DIGEST_SIZE);
    }
    if (!eq[0]->compare()) {
      error("FEQ error\n");
    }
  }

  void check(block *MAC, block *KEY, int length, int I) {
    T *local_io = io[I];

    block *G = new block[length];
    block *C = new block[length];
    block *GR = new block[length];
    bool *d = new bool[length];
    bool *dR = new bool[length];

    for (int i = 0; i < length; ++i) {
      C[i] = KEY[3 * i + 1] ^ MAC[3 * i + 1];
      C[i] = C[i] ^ (select_mask[getLSB(MAC[3 * i + 1])] & Delta);
      G[i] = H2D(KEY[3 * i], Delta, I);
      G[i] = G[i] ^ C[i];
    }
    if (party == ALICE) {
      local_io->send_data(G, sizeof(block) * length);
      local_io->flush();
      local_io->recv_data(GR, sizeof(block) * length);
    } else {
      local_io->recv_data(GR, sizeof(block) * length);
      local_io->send_data(G, sizeof(block) * length);
      local_io->flush();
    }
    
    local_io->flush();
    for (int i = 0; i < length; ++i) {
      block S = H2(MAC[3 * i], KEY[3 * i], I);
      S = S ^ MAC[3 * i + 2] ^ KEY[3 * i + 2];
      S = S ^ (select_mask[getLSB(MAC[3 * i])] & (GR[i] ^ C[i]));
      G[i] = S ^ (select_mask[getLSB(MAC[3 * i + 2])] & Delta);
      d[i] = getL2SB(G[i]);
    }

    if (party == ALICE) {
      local_io->send_bool(d, length);
      local_io->flush();
      local_io->recv_bool(dR, length);
    } else {
      local_io->recv_bool(dR, length);
      local_io->send_bool(d, length);
       local_io->flush();
    }

    for (int i = 0; i < length; ++i) {
      d[i] = d[i] != dR[i];
      if (d[i]) {
        if (party == ALICE)
          MAC[3 * i + 2] = MAC[3 * i + 2] ^ one;
        else
          KEY[3 * i + 2] = KEY[3 * i + 2] ^ ZDelta;

        G[i] = G[i] ^ Delta;
      }
      eq[I]->add_block(G[i]);
    }
    delete[] G;
    delete[] GR;
    delete[] C;
    delete[] d;
    delete[] dR;
  }
  block H2D(block a, block b, int I) {
    block d[2];
    d[0] = a;
    d[1] = a ^ b;
    prps[I].permute_block(d, 2);
    d[0] = d[0] ^ d[1];
    return d[0] ^ b;
  }

  block H2(block a, block b, int I) {
    block d[2];
    d[0] = a;
    d[1] = b;
    prps[I].permute_block(d, 2);
    d[0] = d[0] ^ d[1];
    d[0] = d[0] ^ a;
    return d[0] ^ b;
  }

  bool getL2SB(block b) {
    unsigned char x = *((unsigned char *)&b);
    return ((x >> 1) & 0x1) == 1;
  }

  void combine(block S, int I, block *MAC, block *KEY, int length,
               int bucket_size, block *MAC_res, block *KEY_res) {
   
    int *location = new int[length * bucket_size];
    for (int i = 0; i < length * bucket_size; ++i)
      location[i] = i;
    PRG prg(&S, I);
    int *ind = new int[length * bucket_size];
    prg.random_data(ind, length * bucket_size * 4);
    for (int i = length * bucket_size - 1; i >= 0; --i) {
      int index = ind[i] % (i + 1);
      index = index > 0 ? index : (-1 * index);
      int tmp = location[i];
      location[i] = location[index];
      location[index] = tmp;
    }
    delete[] ind;

    bool *data = new bool[length * bucket_size]{};
    bool *data2 = new bool[length * bucket_size]{};
    
    for (int i = 0; i < length; ++i) {
      for (int j = 1; j < bucket_size; ++j) {
        data[i * bucket_size + j] =
            getLSB(MAC[location[i * bucket_size] * 3 + 1] ^
                   MAC[location[i * bucket_size + j] * 3 + 1]);
      }
    }
    
    if (party == ALICE) {
      io[I]->send_bool(data, length * bucket_size);
      io[I]->flush();
      io[I]->recv_bool(data2, length * bucket_size);
    } else {
      io[I]->recv_bool(data2, length * bucket_size);
      io[I]->send_bool(data, length * bucket_size);
      io[I]->flush();
    }
    
    for (int i = 0; i < length; ++i) {
      for (int j = 1; j < bucket_size; ++j) {
        data[i * bucket_size + j] =
            (data[i * bucket_size + j] != data2[i * bucket_size + j]);
      }
    }
    for (int i = 0; i < length; ++i) {
      for (int j = 0; j < 3; ++j) {
        MAC_res[i * 3 + j] = MAC[location[i * bucket_size] * 3 + j];
        KEY_res[i * 3 + j] = KEY[location[i * bucket_size] * 3 + j];
      }
      for (int j = 1; j < bucket_size; ++j) {
        MAC_res[3 * i] =
            MAC_res[3 * i] ^ MAC[location[i * bucket_size + j] * 3];
        KEY_res[3 * i] =
            KEY_res[3 * i] ^ KEY[location[i * bucket_size + j] * 3];

        MAC_res[i * 3 + 2] =
            MAC_res[i * 3 + 2] ^ MAC[location[i * bucket_size + j] * 3 + 2];
        KEY_res[i * 3 + 2] =
            KEY_res[i * 3 + 2] ^ KEY[location[i * bucket_size + j] * 3 + 2];

        if (data[i * bucket_size + j]) {
          KEY_res[i * 3 + 2] =
              KEY_res[i * 3 + 2] ^ KEY[location[i * bucket_size + j] * 3];
          MAC_res[i * 3 + 2] =
              MAC_res[i * 3 + 2] ^ MAC[location[i * bucket_size + j] * 3];
        }
      }
    }

    delete[] data;
    delete[] location;
    delete[] data2;
  }

  // for debug
  void check_correctness(block *MAC, block *KEY, int length,
                         bool check_relation = false) {
    if (party == ALICE) {
      if (check_relation) {
        for (int i = 0; i < length * 3; ++i) {
          bool tmp = getLSB(MAC[i]);
          io[0]->send_data(&tmp, 1);
        }
      }
      
      io[0]->send_block(&Delta, 1);
      io[0]->send_block(KEY, length * 3);
      io[0]->flush();
      block DD;
      io[0]->recv_block(&DD, 1);

      for (int i = 0; i < length * 3; ++i) {
        block tmp;
        io[0]->recv_block(&tmp, 1);
        if (getLSB(MAC[i]))
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC[i], 1))
          cout << i << "\tWRONG ABIT!\n";
      }

    } else {
      if (check_relation) {
        bool tmp[3];
        for (int i = 0; i < length; ++i) {
          io[0]->recv_data(tmp, 3);
          bool res = ((tmp[0] != getLSB(MAC[3 * i])) &&
                      (tmp[1] != getLSB(MAC[3 * i + 1])));
          if (res != (tmp[2] != getLSB(MAC[3 * i + 2]))) {
            cout << i << "\tWRONG!\t";
          }
        }
      }
      block DD;
      io[0]->recv_block(&DD, 1);
      
      for (int i = 0; i < length * 3; ++i) {
        block ttmp;
        io[0]->recv_block(&ttmp, 1);
              
        if (getLSB(MAC[i]))
          ttmp = ttmp ^ DD;
        if (!cmpBlock(&ttmp, &MAC[i], 1))
          cout << i << "\tWRONG ABIT2!\n";
      }

      io[0]->send_block(&Delta, 1);
      io[0]->send_block(KEY, length * 3);
    }
    io[0]->flush();
  }
};
} // namespace emp
#endif // FPRE_H__
