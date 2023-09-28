#ifndef INCLUDED_NOBUFFER_HPP
#define INCLUDED_NOBUFFER_HPP

/**
   NoBuffer. This class acts as a policy class, indicating that no buffering
should be carried out in a particular connection. This is solely here to act as
a customisation point for code that may benefit from operating without
buffering. This class does nothing at all.
**/
class NoBuffer {
public:
  /**
     has_data. This function always returns false. This is used to indicate to
  callers that this class does not buffer.
  **/
  inline static constexpr bool has_data() noexcept;

  /**
     can_buffer. This function always returns false. This is used to indicate to
  callers that this class does not buffer.
  **/
  inline static constexpr bool can_buffer() noexcept;
};

// Inline definitions live here
#include "NoBuffer.inl"

#endif
