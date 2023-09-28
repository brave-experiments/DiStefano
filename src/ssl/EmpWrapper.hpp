#ifndef INCLUDED_EMPWRAPPER_HPP
#define INCLUDED_EMPWRAPPER_HPP

#include "../emp-tool/emp-tool/io/io_channel.h" // This contains the declarations for Emp things.
#include "Util.hpp"       // This contains generic I/O routines.
#include "openssl/base.h" // This only contains the forward declarations for SSL* etc.
#include "ssl/internal.h" // This contains the declaration for Array.

#include "CounterType.hpp"
#include "NoBuffer.hpp"
#include "SSLBuffer.hpp"

/**
   EmpWrapper. This component is a wrapper for using our sockets with the EMP
Toolkit (e.g https://github.com/emp-toolkit) functions. This wrapper exists
because the EMP Toolkit allows one to pass in generic IO classes for IO, but
one does not exist that actually satisfies our use case. In particular, the
sockets used in EMP are not encrypted by default, whereas we want to use
everything inside BoringSSL.

This requires some tweaking. This class simply provides wrapper functions for
the existing BoringSSL SSL* type and makes sure that we can integrate this
nicely with EMP and Emp Toolkit.

It's worth thinking about why this is necessary at all. Essentially, EMP Toolkit
implements a static polymorphism strategy, known as the curiously recurring
template pattern (CRTP). This is a classic C++ technique, but if you're not
familiar with it we'll give a brief summary here.

   Suppose you have a wrapper class for I/O (we'll call it IO). Now, there's
lots of ways to do I/O, but in practice what we really want to be able to do is
say "send this over this channel, and read this over the same channel". That's
normally the domain of virtual functions and a class hierarchy, but that has two
drawbacks:

   1. It's slow at runtime to use virtual functions. This is because we have e.g
      a function pointer to de-reference. Smart compilers can now devirtualize
this, but it isn't always easy.
   2. We lose some information about the underlying type in default
implementations. For example, if we call a function that belongs to the IO
class, it is not longer possible to retrieve which inherited class we used. This
is known as type slicing.

   The trick around this is to use the curiously recurring template pattern
(CRTP). This is best explained in code, but essentially the idea is that we pass
the type of the child type as a template parameter to the parent type. This
means that the parent type can have full type knowledge of the instantiated
child type, which allows us to delegate to child methods.

   For example, imagine we want to make an IO class as above.

   The declaration of the parent class would look like this:

   \code{.cpp}
   template<typename T>
   class IO {
      ...
   };

   \endcode

   Any child types that inherit from this would be declared as follows:

   \code{.cpp}
   class NetworkIO : public IO<NetworkIO> {
      ...
   };
   \endcode


   As a disclaimer: this looks really weird the first time you look at it.
That's because the definition looks circular: how can we instantiate a template
using an incomplete definition?

   The reason is really quite... deep. If you're not interested, you can skip
this bit. Essentially, the reason why is because C++ only instantiates templates
_after_ the first parse of the source code has finished. What this means in
practice is this:

   1. The C++ compiler encounters the definition of `IO`. It notices this is a
template, so it parses the syntax tree to make sure there's no illegal
sentences, and then goes on its way.
   2. The C++ compiler encounters the definition of `NetworkIO`. It notices that
this class inherits from a template. It doesn't instantiate the template yet:
rather, the compiler simply parses the NetworkIO class to make sure there's no
illegal sentences, and then goes on its way.
   3. By the time we need to instantiate the template, both `IO` and `NetworkIO`
have been parsed. The compiler then instantiates `IO<NetworkIO>`: because the
layout of `NetworkIO` is known by this point, the compiler can instantiate the
template, and it all just works.

   This is an entry level technique for more advanced meta-programming, but we
won't discuss that here.

   For what it's worth: this technique can be partially avoided to a certain
extent by using Concepts and free functions instead. However, it isn't enough to
fully remove the CRTP.


@remarks An object of this class does not take ownership of the passed in
parameter. This is primarily for usability; however, it does mean you'll need to
take care of those details externally.
@remarks This class requires a valid `ssl` object to operate. If the object is
not valid, then this class will:

1. `assert(false)` in debug builds, and
2. exhibit undefined behaviour in release builds.
@tparam BufferType: the type of buffering scheme to use. See SSLBuffer.hpp for
more.
@tparam CounterType: the type of bandwidth tracking scheme to use. See
CounterType.hpp for more.
@tparam prepend_header: true if messages sent from this socket should pre-pend
their size, false otherwise. This is primarily used to make buffering faster.
**/
template <typename BufferType = SSLBuffer, typename CounterType = RWCounter,
          bool prepend_header = true>
class EmpWrapper : public emp::IOChannel<
                       EmpWrapper<BufferType, CounterType, prepend_header>> {

  // These constructors are deleted, because there's
  // never a situation where these should be used.
  EmpWrapper() = delete;
  EmpWrapper(EmpWrapper &) = delete;
  EmpWrapper(EmpWrapper &&) = delete;

public:
  /**
     EmpWrapper. This function takes a non-owning pointer to an SSL object and
     stores it in `this` wrapper's SSL object. This function does not throw.
     @snippet EmpWrapper.t.cpp EmpWrapperTestConstruct
     @param[in] ssl_in: the SSL object this class should wrap.
  **/
  inline EmpWrapper(SSL *const ssl_in);

  /**
     is_valid_ssl. This function returns true if `this` wrapper's SSL
     object is a non-null pointer, and false otherwise. This function does
     not modify `this` object and does not throw.
     @snippet EmpWrapper.t.cpp EmpWrapperIsValidSSLNullPtrTest
     @snippet EmpWrapper.t.cpp EmpWrapperIsValidSSLValidPtrTest
     @return true if the `ssl` object is valid, false otherwise.
  **/
  inline bool is_valid_ssl() const noexcept;

  /**
     get_ssl. This function returns a copy of `this` wrapper's SSL object
     as a pointer. This function does not throw.
     @return this object's SSL object. This function shall return a null pointer
     if is_valid_ssl() is false.
  **/
  inline SSL *get_ssl() noexcept;

  /**
     send_data_internal. This is a wrapper function that is called by
     EMP's IOChannel type. This function accepts a `void *` pointer, `data`,
     some amount of data `nbyte` and sends `data` using the
   underlying SSL object. This function does not throw any exceptions.

   @snippet EmpWrapper.t.cpp EmpWrapperSendDataInternalTests.
   @tparam T: the type of nbyte.
   @param[in] data: the data to be sent. This pointer must be non-null.
   @param[in] nbyte: the number of bytes to send. This value should be non-zero,
   but we do not enforce this, instead relying on BoringSSL to do this for us.


     @remarks Note that this function does not report any errors. This is
   because (unlike BoringSSL) the IOChannel's parent function does not allow the
   reporting of any errors. Instead, it simply prints to stderr. This seems hard
   to use in a browser setting, so we ignore it here.
   **/
  template <typename T>
  inline void send_data_internal(const void *const data,
                                 const T nbyte) noexcept;

  /**
     recv_data_internal. This is a wrapper function that is called by
     EMP's IOChannel type. This function accepts a `void *` pointer, `data`,
     some amount of data `nbyte` and reads `nbyte`s into `data` using the
   underlying SSL object. This function does not throw any exceptions.

   @snippet EmpWrapper.t.cpp EmpWrapperSendDataInternalTests.
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
     get_write_counter. This function returns the number of bytes written via
  this socket if write tracking has been enabled. This function does not throw.
     @return the number of bytes written by this socket.
  **/
  inline std::size_t get_write_counter() const noexcept;

  /**
     get_read_counter. This function returns the number of bytes read via
  this socket if read tracking has been enabled. This function does not throw.
     @return the number of bytes read by this socket.
  **/
  inline std::size_t get_read_counter() const noexcept;

  /**
     get_bandwidth. This function returns the total number of bytes that have
  been sent and received via this socket. This function does not throw.
     @return the number of bytes that have passed through this socket.
  **/
  inline std::size_t get_bandwidth() const noexcept;

  /**
     reset_read_counter. This function resets the number of bytes read via
  this socket if read tracking has been enabled. This function does not throw.
  **/
  inline void reset_read_counter() noexcept;

  /**
     reset_write_counter. This function resets the number of bytes written via
  this socket if read tracking has been enabled. This function does not throw.
  **/
  inline void reset_write_counter() noexcept;

  /**
     reset_bandwidth. This function reset the number of bytes written and read
     via this socket. This function does not throw.
  **/
  inline void reset_bandwidth() noexcept;

private:
  /**
     process_data. This function is a private wrapper function for doing generic
  I/O. Essentially, this function exists because the code for sending and
  receiving data is really similar: the only customisation point is the function
  that we're calling, which can be a type parameter here.
     @tparam RT: the type of the buffer that is being written into.
     @tparam F: the function type.
     @param[in] data: the location where the data is kept.
     @param[in] size: the size of the `data` array.
     @param[in] F: the function that is applied.
  **/
  template <typename RT, typename F>
  inline void process_data(RT *const data, const size_t nbyte,
                           F &&func) noexcept(noexcept(func));

  /**
     ssl. This member variable is a non-owning pointer to an SSL object. The SSL
  object must be in a valid state for I/O to occur. Otherwise, the behaviour of
  this class is undefined behaviour.

     Note that once this pointer has been set, it cannot be changed.
  **/
  SSL *const ssl;

  /**
     write buffer. This member variable is the write buffer used for this
  socket. This buffer is only used if a buffering scheme is used.
  **/
  BufferType write_buffer;

  /**
     read_buffer. This member variable is the read buffer used for this socket.
  This buffer is only used if a buffering scheme is used.
  **/
  BufferType read_buffer;

  /**
     counter_w. This member variable is the bandwidth counting type used for
  this socket. This is only used if the counter is set.
  **/
  CounterType counter_w;
};

// Inline definitions live in this file.
#include "EmpWrapper.inl"

#endif
