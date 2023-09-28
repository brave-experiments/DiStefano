#ifndef INCLUDED_EMPBLOCKSPAN_HPP
#define INCLUDED_EMPBLOCKSPAN_HPP

#include <emp-tool/utils/block.h> // Needed for block.

/**
   EmpBlockSpan. This class models a span for an emp::block.
   Conceptually, this class contains a pointer to an array of emp::blocks, and a
   size.

   The raison d'etre for this class is that C++ templates are not
   required to follow alignment rules as specified by compiler attributes.

   To see this problem consider the following example:

   \code{.cpp}
   // You can try this code out at https://godbolt.org/z/4nYe48cM8
   #include<vector>
   // Declare an int with 32 byte alignment, as opposed
   // to the natural sizeof(aligned_int) alignment.
   using aligned_int = int __attribute__((aligned(32));
   // Make a vector of aligned ints.
   std::vector<aligned_int> aligned_ints;
   \endcode


   With warnings turned on, the compiler (either GCC or Clang) will give us the
 following warning: ignoring attributes on template argument 'aligned_int' {aka
 'int'} [-Wignored-attributes].

 The reason for this is that the C++ compiler isn't required to respect the
 alignment attribute applied to aligned_int. This isn't such a problem for
 std::vector, but it may well be for other types.

 This can lead to a situation where some code expects the types to be aligned,
 whereas others simply don't. This is a pain when it comes to using generic
 code: one can simply use `new` or `delete` to circumvent this problem in C++17,
 but this means giving up useful helper functions such as `size`. To get around
 this problem, we simply roll our own class.
 @tparam owns: true if this block owns the underlying span, false otherwise.
 **/

template <bool owns = true> class EmpBlockSpan {
public:
  /**
     EmpBlockSpan. This constructor accepts no arguments and produces a
  span that contains no data and has zero size.
     @snippet EmpBlockSpan.t.cpp EmpBlockSpanDefaultConstructor
  **/
  constexpr EmpBlockSpan() noexcept : data_{}, size_{} {}

  /**
     EmpBlockSpan. This constructor accepts a block `data`, a size `size`
     and takes ownership of `data`. This constructor does not throw. Note that
  this will cause the lifetime of `data` to be bound to `this` span.
     @snippet EmpBlockSpan.t.cpp EmpBlockSpanElementConstructor
     @param[in] data: the data to wrap.
     @param[in] size: the number of elements in the block.
  **/
  constexpr EmpBlockSpan(emp::block *data, const size_t size) noexcept
      : data_{data}, size_{size} {}

  /**
     EmpBlockSpan. This constructor accepts a `size` and allocates
     an array containing exactly `size` many elements. This constructor does not
  throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockSizeOnlyConstructor
     @param[in] size: the number of elements to allocate.
  **/
  explicit EmpBlockSpan(const size_t size) noexcept : data_{}, size_{size} {
    assert(owns);
    data_ = new emp::block[size]();
  }

  /**
     EmpBlockSpan. This is a copy constructor. This function simply
     copies over the size of `other` into `this` span and deep copies
     the memory held by `other`. This constructor does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockCopyConstructor
     @param[in] other: the span to copy.
   **/
  EmpBlockSpan(const EmpBlockSpan<owns> &other) noexcept
      : data_{nullptr}, size_{other.size_} {
    if (owns) {
      data_ = new emp::block[other.size_]();
      std::copy(other.cbegin(), other.cend(), data_);
    } else {
      data_ = other.data_;
    }
  }

  /**
     ~EmpBlockSpan. This method destroys `this` span. This method is
  called every time `this` span falls out of scope. This destructor does not
  throw.
  **/
  ~EmpBlockSpan() noexcept {
    if (owns) {
      delete[] data_;
    }
  }

  /**
     data. This returns a pointer to `this` span's underlying data. This allows
     the caller to do raw access to the data held by this span.
     This function does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
     @return a pointer to the `data_` member of `this` span.
  **/
  emp::block *data() noexcept;
  /**
   data. This returns a const pointer to `this` span's underlying data. This
allows the caller to do raw access to the data held by this span. This function
does not throw and does not modify `this` span.
   @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
   @return a const pointer to the `data_` member of `this` span.
**/
  const emp::block *data() const noexcept;

  /**
     size. This function returns the number of elements held by `this` span.
     This function does not throw or modify `this` span.
     @snippet EmpBlockSpan.t.cpp EmpBlockSizeOnlyConstructor
     @return the number of elements in `this` span.
  **/
  size_t size() const noexcept;

  /**
     size_in_bytes. This function returns the number of bytes held by `this`
  span. This function does not throw or modify `this` span.
     @snippet EmpBlockSpan.t.cpp EmpBlockSizeOnlyConstructor
     @return the number of bytes held by `this` span.
  **/
  size_t size_in_bytes() const noexcept;

  /**
     empty. This function returns true if the number of elements held by `this`
  span is zero and false otherwise. This function does not throw and does not
  modify `this` span.
     @return true if the span is empty, false otherwise.
  **/
  bool empty() const noexcept;

  /**
     begin. This function returns an iterator to the beginning of `this` span's
  data. This allows the caller to do iterative operations over `this` span. This
  function does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
     @return an iterator to the first element of `this` span.
  **/
  emp::block *begin() noexcept;
  /**
     cbegin. This function returns a const iterator to the beginning of `this`
  span's data. This allows the caller to do iterative operations over `this`
  span. This function does not throw and does not modify `this` span.
     @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
     @return a constant iterator to the first element of `this` span.
  **/
  const emp::block *cbegin() const noexcept;

  /**
     end. This function returns an iterator to "one past" the end of `this`
  span's data. This allows the caller to do iterative operations over `this`
  span. This function does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
     @return an iterator to "one past" the end of `this` span's data.
  **/
  emp::block *end() noexcept;
  /**
     cend. This function returns a const iterator to "one past" the end of
  `this` span's data. This allows the caller to do iterative operations over
  `this` span. This function does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
     @return a constant iterator to "one past" the end of `this` span's data.
  **/
  const emp::block *cend() const noexcept;

  /**
     front. This function returns a reference to the first element in `this`
  span's data. This is conceptually the same as returning data[0], but it allows
  iterative operations. This function does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
     @return a reference to data[0].
  **/
  emp::block &front() noexcept;
  /**
     front. This function returns a reference to the last element in `this`
  span's data. This is conceptually the same as returning data[size-1], but it
  allows iterative operations. This function does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
     @return a reference to data[size-1].
  **/
  emp::block &back() noexcept;

  /**
     []. This function returns a reference to the element held at index `i`.
  This function does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
     @param[in] i: the position of the element to retrieve.
     @return a reference to the element at data[i].
  **/
  emp::block &operator[](const size_t i) noexcept;

  /**
   []. This function returns a const reference to the element held at index `i`.
This function does not throw or modify `this` span.
   @snippet EmpBlockSpan.t.cpp EmpBlockAccessors
   @param[in] i: the position of the element to retrieve.
   @return a const reference to the element at data[i].
**/
  const emp::block &operator[](const size_t i) const noexcept;

  /**
     init. This function  allocates a new block, containing `new_size` entries.
  This function also updates the `size` of this entry. This function returns
  true if allocating the span succeeds and false otherwise.

  Note that this function does not copy over the original data inside this span:
  if you call this function, all of the data in the old span may be thrown
  away.

  This function will delete the original array if `this` span is owning: it will
  not modify it otherwise.

  If `new_size` == 0, then this function will simply null out the `data` pointer
  and set the size to 0.


  This function does not throw.
     @snippet EmpBlockSpan.t.cpp EmpBlockInit
     @param[in] new_size: the size of the new block.
  **/
  bool init(const size_t new_size) noexcept;

private:
  /**
     data_. This is the raw pointer to the emp::block elements held by `this`
  span.
  **/
  emp::block *data_;
  /**
     size_. This is the number of elements held in data_.
  **/
  size_t size_;
};

// Inline definitions are in the following file.
#include "EmpBlockSpan.inl"

// Specialisations

/**
   EmpBlockOwningSpan. This class models a span for an emp::block.
   Conceptually, this class contains a pointer to an array of emp::blocks, and a
   size. This class owns the underlying memory.
**/

using EmpBlockOwningSpan = EmpBlockSpan<true>;

/**
   EmpBlockNonOwningSpan. This class models a non-owning span for an emp::block.
   Conceputally, this class contains a pointer to an array of emp::blocks, and a
size. This class does not own the underlying memory.
**/
using EmpBlockNonOwningSpan = EmpBlockSpan<false>;

#endif
