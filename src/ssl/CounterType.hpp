#ifndef INCLUDED_COUNTERTYPE_HPP
#define INCLUDED_COUNTERTYPE_HPP

#include <cstddef>

/**
   RWCounter. This policy class implements a simple bandwidth tracking type
   for EmpWrapper that solely tracks reads or writes. This can be disabled for
   better performance if this is desired.
**/
class RWCounter {
public:
  /**
     track_write. This function adds `bytes` to the number of sent bytes so
   far. This function does not throw.
      @snippet CounterType.t.cpp RWCounterTrackWrite
      @param[in] bytes: the number of bytes sent.
   **/
  inline void track_write(const std::size_t bytes) noexcept;
  /**
     track_write. This function adds `bytes` to the number of read bytes so far.
     This function does not throw.
     @snippet CounterType.t.cpp RWCounterTrackRead
     @param[in] bytes: the number of bytes read.
  **/
  inline void track_read(const std::size_t bytes) noexcept;

  /**
     get_read. This function returns the number of read bytes so far.
     This function does not throw.
     @snippet CounterType.t.cpp RWCounterGetRead
     @return the number of bytes read so far.
  **/
  inline std::size_t get_read() const noexcept;
  /**
     get_write. This function returns the number of written bytes so far.
     This function does not throw.
     @snippet CounterType.t.cpp RWCounterGetWrite
     @return the number of bytes written so far.
  **/
  inline std::size_t get_write() const noexcept;

  /**
     reset_read. This function resets the number of bytes read so far to 0.
     @snippet CounterType.t.cpp RWCounterResetRead
     This function does not throw.
  **/
  inline void reset_read() noexcept;

  /**
     reset_write. This function resets the number of bytes written so far to 0.
     @snippet CounterType.t.cpp RWCounterResetWrite
     This function does not throw.
  **/
  inline void reset_write() noexcept;

private:
  /**
      read_counter. This is the counter for the number of bytes read.
   **/
  std::size_t read_counter{};
  /**
     write_counter. This is the counter for the number of bytes written.
  **/
  std::size_t write_counter{};
};

/**
   NoCounter. This policy class implements a simple bandwidth tracking type for
   EmpWrapper that does nothing. This class should be used if optimum
performance is required.
**/
class NoCounter {
public:
  /**
     track_write. This function is a stub for adding to the write counter.
     It does nothing.
     @snippet CounterType.t.cpp NoCounterTrackWrite
   **/
  inline constexpr void track_write(const std::size_t) noexcept;
  /**
     track_read. This function is a stub for adding to the read counter.
     It does nothing.
     @snippet CounterType.t.cpp NoCounterTrackRead
   **/
  inline constexpr void track_read(const std::size_t) noexcept;
  /**
     get_read. This function is a stub for returning the read counter.
     This function only ever returns 0.
     @snippet CounterType.t.cpp NoCounterGetRead
     @return 0.
   **/
  inline constexpr std::size_t get_read() noexcept;

  /**
     get_write. This function is a stub for returning the write counter.
     This function only ever returns 0.
     @snippet CounterType.t.cpp NoCounterGetWrite
     @return 0.
   **/
  inline constexpr std::size_t get_write() noexcept;

  /**
     reset_read. This function is a stub for resetting the read counter.
     This function does nothing.
     @snippet CounterType.t.cpp NoCounterResetRead
   **/
  inline constexpr void reset_read() noexcept;
  /**
     reset_write. This function is a stub for resetting the write counter.
     This function does nothing.
     @snippet CounterType.t.cpp NoCounterResetWrite
   **/
  inline constexpr void reset_write() noexcept;
};

#include "CounterType.inl"

#endif
