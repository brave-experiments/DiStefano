#ifndef INCLUDED_COUNTERTYPE_HPP
#error Do not include CounterType.inl without CounterType.hpp
#endif

inline void RWCounter::track_write(const std::size_t bytes) noexcept {
  write_counter += bytes;
}

inline void RWCounter::track_read(const std::size_t bytes) noexcept {
  read_counter += bytes;
}

inline std::size_t RWCounter::get_read() const noexcept { return read_counter; }
inline std::size_t RWCounter::get_write() const noexcept {
  return write_counter;
}

inline void RWCounter::reset_read() noexcept { read_counter = 0; }
inline void RWCounter::reset_write() noexcept { write_counter = 0; }

constexpr inline void NoCounter::track_write(const std::size_t) noexcept {}
constexpr inline void NoCounter::track_read(const std::size_t) noexcept {}
constexpr inline std::size_t NoCounter::get_read() noexcept { return 0; }
constexpr inline std::size_t NoCounter::get_write() noexcept { return 0; }
constexpr inline void NoCounter::reset_read() noexcept {}
constexpr inline void NoCounter::reset_write() noexcept {}
