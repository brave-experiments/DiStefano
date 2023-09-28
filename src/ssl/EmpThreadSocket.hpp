#ifndef INCLUDED_EMPTHREADSOCKET_HPP
#define INCLUDED_EMPTHREADSOCKET_HPP

#include "../emp-tool/emp-tool/io/io_channel.h" // This contains the declarations for emp things.
#include "EmpSSLSocketManager.hpp" // Needed for multiplexed sends and receives.
#include "ThreadSafeSSL.hpp"       // Needed for multiplexed sends and receives.
#include "openssl/base.h"          // Needed for various declarations.
#include "ssl/internal.h"          // Needed for various declarations.

#include "NoBuffer.hpp"
#include "SSLBuffer.hpp"

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
EmpThreadSocket::set_ssl _first_. This sets up a global ThreadSafeSSL object
that handles all multiplexing. To protect against this, the constructor will
assert against this invariant. Similarly, once all EmpThreadSockets have
outserved their usefulness, you must also call the
EmpThreadSocket::free_ssl function. We assert against this when creating new
objects, so this will be fairly obvious in debug mode if this is not set.
@tparam is_server: true if this class is a server class, false otherwise.
@tparam BufferType: type of buffering scheme to use. See SSLBuffer.hpp for more.
**/
template <bool server, typename BufferType>
class EmpThreadSocket
    : public emp::IOChannel<EmpThreadSocket<server, BufferType>> {

  // These constructors are explicitly deleted to prevent them being called
  // accidentally.
  EmpThreadSocket() = delete;
  EmpThreadSocket(EmpThreadSocket &) = delete;
  EmpThreadSocket(EmpThreadSocket &&) = delete;

public:
  /**
     is_server. This variable indicates if this particular type of
  EmpThreadSocket is a server socket or not. This variable is unused and only
  exists to satisfy the requirements of EmpAG2PC.
  **/
  static constexpr bool is_server = server;

  /**
     addr. This variable is a placeholder for EMPAG2PC. This isn't actually
     used for anything.
  **/
  inline static const std::string addr = "";

  /**
     port. This variable is a placeholder for EMPAG2PC. This isn't actually used
     for anything.
  **/
  inline static const int port = 0;

  /**
     EmpThreadSocket. This is the default constructor for this class.
     This constructor exists solely to satisfy the API requirements of
  emp::IOChannel, and as a result none of the arguments do anything. This
  function never throws. This function sets up the tag of this socket.
  @snippet EmpThreadSocket.t.cpp EmpThreadSocketConstruct
  **/
  inline EmpThreadSocket(const char *const, const int, bool) noexcept;

  /**
     send_data_internal. This is a wrapper function that is called by EMP's
  IOChannel type. This function accepts a valid void* pointer, `data`, some
  amount of data `nbyte` and sends `data` over the underlying SSL channel. This
  function does not throw.
     @snippet EmpThreadSocket.t.cpp EmpThreadSocketSendDataInternal.
     @tparam T: the type of nbyte.
     @param[in] data: the data to be sent. This must be a non-null pointer.
     @param[in] nbyte: the number of bytes to send. This value should be
  non-zero.
     @remarks Note that this function does not report any errors. This is
  because IOChannel's parent function does not allow the reporting of any
  errors.
  **/
  template <typename T>
  inline void send_data_internal(const void *const data,
                                 const T nbyte) noexcept;

  /**
     recv_data_internal. This is a wrapper function that is called by
     EMP's IOChannel type. This function accepts a `void *` pointer, `data`,
     some amount of data `nbyte` and reads `nbyte`s into `data` using the
   underlying SSL object. This function does not throw any exceptions.

   @snippet EmpThreadSocket.t.cpp EmpThreadSocketSendDataInternalTests.
   @tparam T: the type of nbyte.
   @param[in] data: the buffer to store the read data. This pointer must be
   non-null.
   @param[in] nbyte: the number of bytes to read. This value should be non-zero,
   but we do not enforce this, instead relying on BoringSSL to do this for us.

     @remarks Note that this function does not report any errors. This is
   because (unlike BoringSSL) the IOChannel's parent function does not allow the
   reporting of any errors. Instead, it simply prints to stderr. This seems hard
   to use in a browser setting, so we ignore it here.
   **/
  template <typename T>
  inline void recv_data_internal(void *const data, const T nbyte) noexcept;

  /**
   flush. This function is a wrapper function that is called by EMP's
IOChannel type. This function flushes to the output if a buffering scheme is
used and does nothing otherwise.

This function does not throw. In case where the socket does not support
buffering, this function also does not modify `this` object.
@remarks This function is only enabled if the BufferType does not support
buffering. The template parameter `T` is here to allow SFINAE to work (C++ has
some complicated rules around SFINAE and dependent templates).
**/
  template <typename T = void>
  inline std::enable_if_t<!BufferType::can_buffer(), T> flush() const noexcept;

  /**
     flush. This function is a wrapper function that is called by EMP's
  IOChannel type. This function flushes to the output if a buffering scheme is
  used and does nothing otherwise.

  This function does not throw. In case where the socket does not support
  buffering, this function also does not modify `this` object.
  @remarks This function is only enabled if the BufferType supports buffering.
  The template parameter `T` is here to allow SFINAE to work (C++ has some
  complicated rules around SFINAE and dependent templates).
  **/
  template <typename T = void>
  inline std::enable_if_t<BufferType::can_buffer(), T> flush() noexcept;

  /**
     set_ssl. This static function sets the global ThreadSafeSSL object to the
  `ssl` argument. This exists solely to allow all EmpThreadSockets to use the
  same SSL connection. This function does not throw.
  @snippet EmpThreadSocket.t.cpp EmpThreadSocketSetSSL
  @param[in] ssl: the ssl connection to use. Must not be null.

  **/
  static inline void set_ssl(SSL *const ssl) noexcept;

  /**
     destroy_ssl. This static function destroys the global ThreadSafeSSL object.
     @snippet EmpThreadSocket.t.cpp EmpThreadSocketDestroySSL
  **/
  static inline void destroy_ssl() noexcept;
  /**
    get_socket. This returns a copy of the socket pointer that this class uses.
 This exists solely to allow us to pass static variables from the .cpp file to
 the .inl file. This function does not throw. This should only be used during
 testing.
    @return a copy of the socket object.
 **/
  static inline ThreadSafeSSL *get_socket() noexcept;

  /**
     get_tag. This function returns a copy of the tag assigned to this socket.
  This function does not throw or modify this object.
     @return a copy of the tag of this object.
  **/
  inline unsigned get_tag() const noexcept;

private:
  /**
     tag. This tag identifies the thread of this particular socket. This is used
  to make sure that messages reach the right thread.
  **/
  unsigned tag;

  /**
     buffer. This is the internal write buffer. This buffer is used to store
  outgoing writes to mitigate delays and reduce the number of system calls.
  **/
  BufferType buffer;
};

// Inline definitions live here.
#include "EmpThreadSocket.inl"

/**
   EmpClientSocket. This class is a thread safe SSL socket that is to be used
   by clients. For more information, see EmpThreadSocket in EmpThreadSocket.hpp
**/
using EmpClientSocket = EmpThreadSocket<false, SSLBuffer>;

/**
   EmpServerSocket. This class is a thread safe SSL socket that is to be used
   by server. For more information, see EmpThreadSocket in EmpThreadSocket.hpp
**/
using EmpServerSocket = EmpThreadSocket<true, SSLBuffer>;

// This template class simply returns the type of EmpThreadSocket that should
// be used. This is primarily for neatness.
template <bool type> struct EmpSocketDispatch;
template <> struct EmpSocketDispatch<false> { using type = EmpClientSocket; };
template <> struct EmpSocketDispatch<true> { using type = EmpServerSocket; };

#endif
