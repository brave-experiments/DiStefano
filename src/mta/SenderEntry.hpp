#ifndef INCLUDED_SENDERENTRY_HPP
#define INCLUDED_SENDERENTRY_HPP

#include "PackArray.hpp"  // Needed for aligned packs.
#include "openssl/base.h" // Needed for BoringSSL things
#include "ssl/internal.h" // Needed for BoringSSL things.

/**
   SenderEntry. This struct is a parameter pack for the variables used
   during the play_sender functions in MtA.hpp. This is primarily used
   to make the calling experience nicer for the user.

   Note that this struct is initialised by passing the created struct to the
   appropriate initialisation routine:

   \code{.cpp}

   SenderEntry se{};
   ...
   MtA::initialise_entries_for_sender(n, q, ctx, se);
   ...
   \endcode

   Otherwise there's no guarantees that each field will be properly sized.
**/
struct SenderEntry {
  /**
     delta. This array contains the `delta` values that are used during the OT.
     Concretely, each delta[i] is a uniformly random value in Z_{q} for some
  prime q. Each delta[i] creates a parameter to be used in the OT: for each
  choice bit `t[i]`, the chosen message is either `delta[i] - a` (if t[i] == 0)
  or `delta[i] + a` (if t[i] == 1).
  **/
  bssl::Array<BIGNUM *> delta;
  /**
     add_pack. This array contains the serialised messages to be chosen if the
  choice bit t[i] == 1.

  WARNING: this array is aligned to alignment_of(emp::block). This is slightly
  different from the default provided by C++. The underlying object takes care
  of this, but be careful mentally when using this array.
  **/
  PackArray add_pack;

  /**
     sub_pack. This array contains the serialised messages to be chosen if the
  choice bit t[0] == 1.
  WARNING: this array is aligned to alignment_of(emp::block). This is slightly
  different from the default provided by C++. The underlying object takes care
  of this, but be careful mentally when using this array.
  **/
  PackArray sub_pack;

  /**
     vals. This array contains the serialised form of the received `v` values.
     WARNING: this array is aligned to alignment_of(emp::block). This is
  slightly different from the default provided by C++. The underlying object
  takes care of this, but be careful mentally when using this array.
  **/
  PackArray vals;
  /**
     sigma_v. This array contains the serialised form of the received `sigma`
  value.
  **/
  bssl::Array<uint8_t> sigma_v;
};

#endif
