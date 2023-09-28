#ifndef LEAKY_DELTA_OT_H__
#define LEAKY_DELTA_OT_H__
#include <emp-ot/emp-ot.h>
namespace emp {
#ifdef __GNUC__
#ifndef __clang__
#pragma GCC push_options
#pragma GCC optimize("unroll-loops")
#endif
#endif

template <typename T> class LeakyDeltaOT : public IKNP<T> {
public:
  LeakyDeltaOT(T *io, bool active = false) : IKNP<T>(io, active) {}

  void send_dot(block *data, int length) {
    this->send_cot(data, length);
    this->io->flush();
    block one = makeBlock(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE);
    for (int i = 0; i < length; ++i) {
      data[i] = data[i] & one;
    }
  }
  void recv_dot(block *data, int length) {
    bool *b = new bool[length];
    this->prg.random_bool(b, length);
    this->recv_cot(data, b, length);
    this->io->flush();

    block ch[2];
    ch[0] = zero_block;
    ch[1] = makeBlock(0, 1);
    block one = makeBlock(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE);
    for (int i = 0; i < length; ++i) {
      data[i] = (data[i] & one) ^ ch[b[i]];
    }
    delete[] b;
  }
};

#ifdef __GNUC_
#ifndef __clang___
#pragma GCC pop_options
#endif
#endif
} // namespace emp
#endif // LEAKY_DELTA_OT_H__
