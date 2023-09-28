#ifndef INCLUDED_EMPWRAPPERAG2PCSOCKET_HPP
#define INCLUDED_EMPWRAPPERAG2PCSOCKET_HPP

#include "../emp-tool/emp-tool/io/io_channel.h" // This contains the declarations for emp things.
#include "openssl/base.h"
#include "ssl/internal.h"

/**
   EmpThreadSocket. This component realises a thread-safe wrapper around sockets
for EMP AG2PC (https://github.com/emp-toolkit/emp-ag2pc). This wrapper exists
because EMP AG2PC allows one to specify an arbitrary number of threads for
setup, but in a TLS context this may be unrealistically expensive (or, at best,
confusing). Equally, using a single socket and manually restricting to using a
single thread seems to cause some deadlocks in the I/O code, which implies there
is some sort of implicit assumption that threading is used.

   To circumvent this issue, we use the following strategy to ensure that
multiple threads can access the same socket whilst also playing nicely with
existing EMP code:

   1. The EmpThreadSocket class acts as a barrier class for EMP AG2PC.
   2. Mechanically, this class contains two things: a reference to a thread-safe
TLS socket and a tag. The reference is simple: it is simply a thread safe way to
do I/O without modifying EMP.

   The tag is less straightforward: conceptually, it is a ticket which specifies
when this particular EmpThreadSocket was created. Those of you who have shopped
in the British Shoe shop Clarks will recognise this system: it is a numbered tag
that specifies when an event happened, or the number of a shopper in the queue.
The reason for this is because we want to be able to "tag" our messages as they
go into the outside world to make sure they are delivered to the right thread on
the other side of the network.

   The reference to the thread-safe TLS socket deals with all of the mechanics
of doing this: the important part is that each EmpThreadSocket has a way of
knowing which messages are due for it, and those which aren't.

   @remarks The underlying assumption here is that the EmpThreadSockets are all
made from one thread (i.e the setup is done socket-by-socket). This is important
because otherwise the connection ordering will get broken.
   @remarks For more details on e.g the template invocation here, please see
EmpWrapper.hpp
   @remarks If you want to use this class, you _must_ call
EmpThreadSocket::set_ssl _first_. This sets up a global variable that handles
all of this. To protect against this, the constructor will assert against this
invariant.
**/
class EmpThreadSocket : public emp::IOChannel<EmpThreadSocket> {

  // These constructors are explicitly deleted to prevent them being called
  // accidentally.
  EmpThreadSocket() = delete;
  EmpThreadSocket(EmpThreadSocket &) = delete;
  EmpThreadSocket(EmpThreadSocket &&) = delete;

public:
  /**
     EmpThreadSocket.
   **/
  EmpThreadSocket(const char *const address, const int port, bool quiet);
};
#endif
