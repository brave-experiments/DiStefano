#ifndef EMP_AG2PC_FPRE_H__
#define EMP_AG2PC_FPRE_H__
#include "emp-ag2pc/config.h"
#include "emp-ag2pc/feq.h"
#include "emp-ag2pc/fpre_ferret_cot.h"
#include "emp-ag2pc/fpre_leaky_delta_ot.h"
#include "emp-ag2pc/helper.h"
#include "emp-ag2pc/leaky_deltaot.h"

#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>
#include <thread>

namespace emp {

/**
   This series of structs dispatch to the correct child type for handling the
   OTType argument. We delegate to these implementations in this fashion because
   each child OT type has its own requirements during execution: whilst we could
use CRTP for this, it ends up requiring us to combat the compiler's two stage
lookup. In addition, it is arguably more cumbersome to instantiate these types
by referring to their names directly.

Usage: these structs are partially specialised to allow for dispatching based
solely on the final type parameter (OTType). This means that compilation will
fail if you pass in an OTType that hasn't been explicitly handled.

These types should only really be useful inside this particular file, and they
do not affect how you instantiate Fpre.

**/

template <typename T, int threads, template <typename> class OTType, bool debug>
struct OTImplDispatch;

template <typename T, int threads, bool debug>
struct OTImplDispatch<T, threads, FerretCOT, debug> {
  using Type = FpreFerretCOT<T, threads, debug>;
};

template <typename T, int threads, bool debug>
struct OTImplDispatch<T, threads, LeakyDeltaOT, debug> {
  using Type = FpreLeakyDeltaOT<T, threads, debug>;
};

template <typename T, int threads, template <typename> class OTType,
          bool debug = false>
class Fpre {
public:
  // Get the instance type of the OT. This is fully specialised to use
  // whichever IO Type etc is passed in.
  using OTImplType = typename OTImplDispatch<T, threads, OTType, debug>::Type;

  // Because different OT types have different constructors, we also have
  // to modify Fpre's constructor to accept the right type.
  using in_io_type = typename OTImplType::in_io_type;

  // Impl is the actual implementation of the OT scheme used by this class.
  OTImplType impl;

  Fpre(in_io_type in_io, int in_party, int bsize = 1000, int tag = 0)
      : impl{in_io, in_party, bsize, tag} {}

  // To make the use of this class separate from the implementation
  // of each child type, we provide proxy functions for access to certain types
  // of functionality or member functions.
  // Note: the functions provided here are only those that are
  // currently called by either C2PC or AmortizedC2PC. These also
  // follow the usual convention of emp (e.g most variables are public).

  uint64_t bandwidth() { return impl.bandwidth(); }

  void set_batch_size(int size) { impl.set_batch_size(size); }

  void refill() { impl.refill(); }

  block *MAC() { return impl.MAC; }
  block *KEY() { return impl.KEY; }
  block *MAC_res() { return impl.MAC_res; }

  block *KEY_res() { return impl.KEY_res; }

  void independent_ot(block *preprocess_mac, block *preprocess_key,
                      int total_pre) {
    impl.independent_ot(preprocess_mac, preprocess_key, total_pre);
  }

  block &Delta() { return impl.Delta; }

  block &one() { return impl.one; }

  block &ZDelta() { return impl.ZDelta; }

  void free_mac() {
    delete[] impl.MAC;
    impl.MAC = nullptr;
  }

  void free_key() {
    delete[] impl.KEY;
    impl.KEY = nullptr;
  }

  template <typename F> static T *get_first(F ios) {
    return OTImplType::get_first(ios);
  }

  static constexpr int THDS() { return threads; }
};
} // namespace emp
#endif
