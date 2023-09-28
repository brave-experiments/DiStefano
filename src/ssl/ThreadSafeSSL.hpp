#ifndef INCLUDED_THREADSAFESSL_HPP
#define INCLUDED_THREADSAFESSL_HPP

#include "openssl/base.h"
#include "ssl/internal.h"
#include <array>
#include <atomic>
#include <mutex>
#include <vector>

/**
   ThreadSafeSSL. This component realises a thread-safe SSL connection.
   This component exists solely to allow the re-use of an SSL connection inside
   certain parts of EMP.

   Details: this socket is essentially a multiplexing socket.
   As an analogy, you can consider two buildings full of people.
   Normally the fastest way for these people to communicate would be to directly
   phone or email each other, but in absence of that we can use a postal
service.

   Assuming we only know the address, how can we make sure that the messages get
   to the right people?

   One simplifying assumption is that all of the people in both buildings are
capable of the same work. As a result, it just matters that the same two people
always speak in a pair, rather than to other people.

   Let's label the buildings as A and B respectively. We'll assume that both
sides have the same number of people, labelled 0,..., n-1.

   When person 0 in building A sends a message to building B, they will
   tag their message with `0` before sending. Then, some person `i` in building
B will collect that message and note that they are dealing with person 0. Before
person `i` deals with the message, they will send a short note back to person
`0` that tells them they are dealing with person `i`. This is primarily for
consistency across both buildings.

   Iterating this process, we can then build a multiplexed socket for multiple
threads.


@remarks As an implementation detail, this class sends all messages prepended
with a 64-bit tag. This tag is divided into 8-bits for the ID (i.e the person
number in the above example) and the rest is for the length. Whilst this is an
artificial restriction, in practice it seems reasonable: 2^56 bytes is 72
petabytes, which seems unrealistic. The 2^8 = 256 thread count also seems
reasonable, although for other reasons we actually restrict this to 255 threads.

@remarks This class assumes that both platforms have the same endianness:
there's no format independent encoding in this class. We can add this later if
needed.
**/

class ThreadSafeSSL {

public:
  /**
     SizeType. This is the type that is used as a size parameter in send and
     recv. This declaration is here so that callers know what type to which they
  should cast their size parameters.
  **/
  using SizeType = unsigned;

  /**
     register_new_socket. This function increments the number of sockets
  associated with this SSL object and returns the tag for the caller. The value
  returned is always the previous value of `count`: this means that the first
  caller gets 0, the second caller gets 1 and so on. This function does not
  throw.
     @snippet ThreadSafeSSL.t.cpp ThreadSafeSSLRegisterNewSocket
     @return the tag associated with the calling socket.
  **/
  unsigned register_new_socket() noexcept;

  /**
     send. This function sends `nbyte` of `data` to the thread associated with
  `tag`. This function does not throw. Note that similarly to other socket
  classes that interface with EMP, this function does not return any error
  information.
     @param[in] tag: the tag associated with the calling socket. Must be less
  than ThreadSafeSSL::max_size.
     @param[in] data: the data to be sent. Must not be null.
     @param[in] nbyte: the number of bytes to send.
  **/
  void send(const unsigned tag, const void *const data,
            const SizeType nbyte) noexcept;
  /**
     recv. This function receives at most `nbyte` of data meant for the thread
  associated with `tag`. This function does not throw. Note that similarly to
  other socket classes that interface with EMP, this function does not return
  any error information.
  @param[in] tag: the tag associated with the calling socket. Must be less than
  ThreadSafeSSL::max_size.
  @param[in] data: the location to store the incoming data. Must not be null. In
  debug builds, we assert to this.
  @param[in] nbyte: the number of bytes to read.
  **/
  void recv(const unsigned tag, void *const data,
            const SizeType nbyte) noexcept;

  /**
     ThreadSafeSSL. This constructor builds the socket. This constructor does
     not throw.
     @snippet ThreadSafeSSL.t.cpp ThreadSafeSSLConstructor
     @param[in] ssl_in: the input ssl connection to use. Must not be null.
  **/
  ThreadSafeSSL(SSL *const ssl_in) noexcept;

  /**
     get_ssl. Returns a copy of the SSL object associated with `this`
  ThreadSafeSSL object. This function never returns a null pointer and never
  throws.
     @snippet ThreadSafeSocket.t.cpp ThreadSafeSSLConstructor
     @returns a non-null copy of the `ssl` object.
  **/
  SSL *get_ssl() noexcept;

  /**
     is_registered_in. This function returns true if `tag` is registered as
  incoming at this node. This means that the thread with `tag` as their
  identifier has a thread on this node that they consistently communicate with.
  This function does not throw.
     @snippet ThreadSafeSSL.t.cpp ThreadSafeSSLRegisteredInOut
    @param[in] tag: the tag that we are looking up. Must be less than
  ThreadSafeSSL::max_size.
     @return true if tag has a corresponding thread that it communicates with,
  false otherwise.
  **/
  bool is_registered_in(const unsigned tag) const noexcept;

  /**
     is_registered_out. This function returns true if `tag` is registered as
  outgoing at this node. This means that the thread with `tag` as their
  identifier has a thread on the node at the other end of the channel that they
  consistently communicate with.
     @snippet ThreadSafeSSL.t.cpp ThreadSafeSSLRegisteredInOut
     @param[in] tag: the tag that we are looking up. Must be less than
  ThreadSafeSSL::max_size.
     @return true if tag has a corresponding thread that it communicates with,
  false otherwise.
  **/
  bool is_registered_out(const unsigned tag) const noexcept;

private:
  /**
    max_size. This is the maximum number of threads we support in this class.
   This is actually set here to make certain declarations nicer to write.
   **/
  static constexpr uint8_t max_size = 254;

  /**
     tombstone. This is the value that is set in the registered_in and
  registered_out arrays to denote that the thread has not yet been seen or
  registered. This is by default max_size + 1.
  **/
  static constexpr uint8_t tombstone = max_size + 1;

  /**
     count. This is the counter of the number of sockets that have been
  registered with `this` socket. Note that despite the unsigned nature of this
  counter the actual size is at most 255, which we assert to in the
  register_new_socket function in release modes.
  **/
  std::atomic<unsigned> count;

  /**
     socket_lock. This is the lock for this class. All operations that involve
     any variables of this class use this lock.
  **/
  std::mutex socket_lock;
  /**
     ssl. This is the ssl connection to use. Note that this is never null
     after this socket has been connected.
   **/
  SSL *ssl;

  /**
     registered_in. This array contains the IDs of all threads that have been
     registered _in_ at this socket. If an entry here is not set to `tombstone`,
  then it means that it has been registered with a thread. In more detail, if
  registered_in[i] is not `tombstone`, then the value of registered_in[i] is the
  thread on this node that thread `i` (on another node) communicates with.
  **/
  std::array<uint8_t, max_size> registered_in;
  /**
     registered_out. This array contains the IDs of all threads that have been
  registered as sending a message from this socket. If registered_out[i] !=
  tombstone, then thread `i` here is communicating with the thread with ID
  registered_out[i] on another node.
  **/
  std::array<uint8_t, max_size> registered_out;

  /**
     incoming. This vector of vector contains temporary storage for each
     thread. In particular, incoming[i] contains any read messages for thread
  `i`. This may be populated by other threads to prevent locking.
  **/
  std::array<std::vector<char>, max_size> incoming;

  unsigned find_first_tombstone() const noexcept;
};

#endif
