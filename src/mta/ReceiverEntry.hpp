#ifndef INCLUDED_RECEIVERENTRY_HPP
#define INCLUDED_RECEIVERENTRY_HPP

#include "EmpBlockSpan.hpp" // Needed for sane use of emp::block.
#include "PackArray.hpp"    // Needed for emp::block aligned storage.
#include "openssl/base.h"   // Needed for BoringSSL things.
#include "ssl/internal.h"   // Needed for BoringSSL things.

/**
   ReceiverEntry. This struct is a parameter pack for the variables used
   during the play_receiver functions in MtA.hpp. This is primarily used
   to make the calling experience nicer for the user.

   Note that this struct is initialised by passing the created struct to the
   appropriate initialisation routine:

   \code{.cpp}

   ReceiverEntry re{};
   ...
   MtA::initialise_entries_for_receiver(q, ctx, re);
   ...
   \endcode

   Otherwise there's no guarantees that each field will be properly sized.
**/

struct ReceiverEntry {

  /**
     t. This array is used to hold the choice bits for the oblivious transfer.
  **/
  bssl::Array<bool> t;
  /**
     t_extended. This array is used to hold the expanded choice bits for the OT.
  **/
  bssl::Array<bool> t_extended;
  /**
     v. This array holds the `v` vector generated during the MtA protocol.
  **/
  bssl::Array<BIGNUM *> v;
  /**
     v_serialised. This array holds the serialised version of the `v` vector.
     WARNING: this array is special. Specifically, it is memory aligned to
     emp::block.
  **/
  PackArray v_serialised;
  /**
     sigma_serialised. This array holds the serialised version of `sigma`.
  **/
  bssl::Array<uint8_t> sigma_serialised;
  /**
     z. This contains the chosen messages from the OT.
  **/
  EmpBlockOwningSpan z;
};

#endif
