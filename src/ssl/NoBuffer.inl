#ifndef INCLUDED_NOBUFFER_HPP
#error Do not include NoBuffer.inl without NoBuffer.hpp
#endif

inline constexpr bool NoBuffer::has_data() noexcept { return false; }

inline constexpr bool NoBuffer::can_buffer() noexcept { return false; }
