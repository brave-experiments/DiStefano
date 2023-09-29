#ifndef INCLUDED_SSLBUFFER_HPP
#define INCLUDED_SSLBUFFER_HPP

#include "openssl/base.h"
#include "ssl/internal.h"
#include <cassert>
#include <iostream>
#include <vector>

/**
   SSLBufferPolicy. This policy class implements a simple buffering scheme for
   messages sent using SSL. Essentially, certain libraries (e.g EMP) do many
small writes that can cause performance slowdowns. Indeed, prior to the
introduction of this class perf indicates that around 8% of our time is spent
doing simply the I/O setup and teardown.

   This class simply contains a buffer that can be written into by the child
type. Given that we don't have access to C++20 concepts, the class declares that
it can buffer statically via `can_buffer`. This class also declares that it has
data that can be written via `has_data`.

@tparam flush_size: the upper bound on the amount of data that can be stored in
this class before a flush operation will take place.
@tparam hold_flush: true if the flushing operation is held until an explicit
call to flush, false otherwise.
**/
template <size_t flush_size = SSL3_RT_MAX_PLAIN_LENGTH, bool hold_flush = true>
class SSLBufferPolicy {
public:
  /**
     SizeType. We forward declare a size type for compatibility's sake.
  **/
  using SizeType = unsigned;

  /**
     has_data. This function always returns true. It should be used to indicate
  to callers that a flush should read data from this buffer.
  **/
  inline static constexpr bool has_data() noexcept;
  /**
     can_buffer. This function always returns true. It should be used to
   indicate to callers that a write call should buffer via this class.
   **/
  inline static constexpr bool can_buffer() noexcept;

  /**
     should_send. Returns true if the size of the `buffer` is greater than or
  equal to SSL3_RT_MAX_PLAIN_LENGTH and false otherwise. This function does not
  throw.

     @return true if the buffer should be emptied, false otherwise.
  **/
  inline bool should_send() const noexcept;

  /**
     buffer_data. This function accepts a non-null pointer to some `data`
     and appends `nbytes` of `data` to the end of this buffer. Note that it is
  the caller's responsibility to make sure that `data` actually has at least
  `nbytes` of space, otherwise the behaviour is undefined. This function does
  not throw.
     @snippet SSLBuffer.t.cpp SSLBufferInsert
     @param[in] data: the data to insert into `buffer`. Must be non-null.
     @param[in] nbyte: the number of bytes to insert.
  **/
  inline void buffer_data(const void *const data,
                          const SizeType nbyte) noexcept;

  /**
     clear. This function removes all elements from the current buffer. This
  does not cause reallocation or freeing memory. This function does not throw.
     @snippet SSLBuffer.t.cpp SSLBufferClear
  **/
  inline void clear() noexcept;

  /**
     data. This function returns a non-null const pointer to the buffer held by
  this object. This function does not throw or modify this object.
     @return a pointer to the data held by this buffer.
  **/
  inline const char *data() const noexcept;

  /**
     data. This function returns a non-null pointer to the buffer held by
  this object. This function does not throw.
     @return a pointer to the data held by this buffer.
  **/
  inline char *data() noexcept;

  /**
     size. This function returns the number of bytes held by this buffer. This
  function does not throw or modify this object.
     @return the number of bytes held by this buffer.
  **/
  inline size_t size() const noexcept;

  /**
     reserve. This function reserves at least `size` bytes in the `buffer`. This
  function may cause reallocation but the size of this object is unmodified.
     @snippet SSLBuffer.t.cpp SSLBufferReserve
     @param[in] size: the minimum number of bytes that this buffer should hold.
  **/
  inline void reserve(const SizeType size) noexcept;

  /**
     capacity. This function returns the number of bytes of capacity this buffer
  has. This is equivalent to the amount of memory allocated by this buffer for
  storage.
     @snippet SSLBuffer.t.cpp SSLBufferReserve
  **/
  inline SizeType capacity() const noexcept;

  /**
     resize. This function resizes the buffer to contain `nbyte` of storage.
     This function may cause memory to be freed in some systems.
     @param[in] nbyte: the number of bytes of storage for the buffer.
  **/
  inline void resize(const size_t nbyte) noexcept;

  /**
     add_read. This function increments the upper read head by `nbytes`.
     @param[in] nbyte: the number of bytes to increment the read head.
  **/
  inline void add_read(const size_t nbyte) noexcept;

  /**
     read_bytes_size. This function returns the number of bytes that have not
  been read in the read buffer. If the buffer is not a read buffer, then this
  function always returns 0.
  **/
  inline size_t read_bytes_size() const noexcept;

  /**
     read_bytes. This function reads `nbyte` of data from the read buffer and
  puts it into `data`.
     @param[in] data: a pointer. Must be non-null and point to at least `nbyte`
  of storage.
     @param[in] nbyte: the number of bytes to read. Must be at most
  read_bytes_size().
  **/
  inline void read_bytes(void *const data, const size_t nbyte) noexcept;

private:
  /**
     buffer. This is the private buffer that helds inserted data.
  **/
  std::vector<char> buffer{};

  size_t lower_head{}, upper_head{};
};

// All inline functions live here.
#include "SSLBuffer.inl"

using SSLBuffer = SSLBufferPolicy<>;

#endif
