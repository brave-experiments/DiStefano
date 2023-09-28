#ifndef INCLUDED_EMPWRAPPER_AG2PC_HPP
#error Do not include EmpWrapperAG2PC.inl without EmpWrapperAG2PC.hpp
#endif

/*
  Warning to any future readers of this code: there's a potential headache in
  this code that you'd do well to keep in mind.

  EMP treats all booleans as individual bits. In other words, if you want to
  pass 128 bits to emp (e.g from std::array<uint8_t, 16>) then you need to
  manually pack them into an array of bools (e.g to std::array<bool, 128>). This
  can cause headaches if you aren't careful with parameters: as a general rule
  of thumb, every function in this file expects the `output_size` to refer to
  the number of _bytes_ in the output.

  An example of this can be seen in evaluate_circuit_internal: the temp_out
  array is scaled by CHAR_BIT so that EMP can represent each element in this
  way.

  If you get this wrong you're likely to have segfaults and other headaches:
  most notably, you'll almost certainly get stack overruns. This will probably
  manifest when the function returns, so be aware.
 */

constexpr unsigned
EmpWrapperAG2PC::get_secret_size(const char *const filepath) noexcept {
  // NOTE: This is deliberately pointer comparison and not strcmp or similar.
  // This is because the filepath must be one of these due to how our build
  // functions are setup, allowing this to be constexpr.
  if (filepath == EmpWrapperAG2PCConstants::CHS_256_FILEPATH)
    return 256;
  if (filepath == EmpWrapperAG2PCConstants::CHS_384_FILEPATH)
    return 384;
  return 0;
}

inline unsigned EmpWrapperAG2PC::get_size() const noexcept {
  return secret_size;
}

inline void EmpWrapperAG2PC::reset_counter() noexcept {
  wrapper.reset_read_counter();
  wrapper.reset_write_counter();
}

inline uint64_t EmpWrapperAG2PC::get_counter() const noexcept {
  return wrapper.get_read_counter() + wrapper.get_write_counter();
}
