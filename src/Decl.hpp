#ifndef INCLUDED_DECL_HPP
#define INCLUDED_DECL_HPP

#include <array>       // For std::array later.
#include <cassert>     // For assertions
#include <type_traits> // For std::is_array etc

/**
   Decl. This component contains a sequence of useful/complicated typedefs that
   are used in this project. Each typedef is explained, but the idea is to allow
us to use certain compiler builtins without being tied to a particular compiler.
**/

/**
   COMPAT_UNREACHABLE. This macro tells the compiler to assume that some code
   is unreachable. This helps the compiler deduce certain facts more easily.
   GCC compatible compilers already come with a builtin for this, but some others don't.
**/
#if defined __GNUC__
#define COMPAT_UNREACHABLE() (__builtin_unreachable())
#elif defined _MSCV_VER
#define COMPAT_UNREACHABLE() (__assume(false))
#else
[[noreturn]] inline void compat_unreachable_impl() {}
#define COMPAT_UNREACHABLE() (compat_unreachable_impl())
#endif

/**
   ASSUME. This macro tells the compiler to assume that some condition `x` is
true. This helps the compiler generate better code in a lot of situations.

   Clang already comes with a compiler builtin for this, called
__builtin_assume. By contrast, GCC doesn't: however, we can mimic it with
__builtin_unreachable.
**/
#ifdef __CLANG__
#define ASSUME(x) __builtin_assume(x)
#else
#define ASSUME(x)                                                              \
  \ do {                                                                       \
    if (!(x))                                                                  \
      COMPAT_UNREACHABLE();                                                    \
    \                                                                          \
  }                                                                            \
  while (0)
#endif

/**
   assert_and_assume. This macro accepts a condition `x` and does two things:
   1. In DEBUG builds, we assert that `x` is true, and
   2. We then assume it is true too, using the ASSUME() macro.

   This is slightly stronger than an assertion: an assertion only executes in
debug builds by definition. Here we're saying that we want the compiler to also
be able to optimise for those conditions (e.g as in a design-by-contract
setting).

   This is explained in some detail here: https://blog.regehr.org/archives/1096,
but it'll help make our code a bit nicer :).

WARNING: as with the regular assert() macro, it's very important not to put a
function call inside the brackets. This will lead to double evaluation, which is
a headache.
**/
#define assert_and_assume(x)                                                   \
  assert(x);                                                                   \
  // ASSUME(x)

namespace Decl {
/**
   is_array. This provides a type specialisation for std::is_array that works
for std::array. This is because std::is_array only works for trivial array types
(e.g T[]).
**/
template <typename T> struct is_array : std::is_array<T> {};

template <typename T, std::size_t N>
struct is_array<std::array<T, N>> : std::true_type {};

} // namespace Decl
#endif
