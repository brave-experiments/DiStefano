#ifndef INCLUDED_PACKARRAY_HPP
#define INCLUDED_PACKARRAY_HPP

#include <emp-tool/utils/block.h> // Needed for block.

/**
   PackArray. This class contains a wrapper around an aligned array of
   uint8_t.

   The reason why this class contains an aligned array is to deal with the
alignment of emp::block: given that emp::block has a custom alignment specified,
it is rather useful to be able to have an array type that is deliberately
aligned in a manner that may differ from the default alignment.
**/
class PackArray {
public:
  /**
     PackArray. This constructor accepts no arguments and produces a
  array that contains no data and has zero size.
     @snippet PackArray.t.cpp PackArrayDefaultConstructor
  **/
  constexpr PackArray() noexcept;

  /**
     PackArray. This constructor accepts a `size` and allocates
     an array containing exactly `size` many elements. This constructor does not
  throw.
     @snippet PackArray.t.cpp PackArraySizeOnlyConstructor
     @param[in] size: the number of elements to allocate.
     @remarks This constructor uses `aligned_alloc` for allocation.
  **/
  explicit PackArray(const size_t size) noexcept;

  /**
     PackArray. This is a copy constructor. This function simply
     copies over the size of `other` into `this` array and deep copies
     the memory held by `other`. This constructor does not throw.
     @snippet PackArray.t.cpp PackArrayCopyConstructor
     @param[in] other: the array to copy.
     @remarks This constructor uses `aligned_alloc` for allocation.
   **/
  PackArray(const PackArray &other) noexcept;

  /**
     ~PackArray. This method deletes `this` array. This destructor is called
  implicitly whenever PackArray goes out of scope.
     @remarks This method uses `free`, in line with the `aligned_alloc` use
  elsewhere.
  **/
  inline ~PackArray() noexcept;

  /**
     data. This returns a pointer to `this` array's underlying data. This allows
     the caller to do raw access to the data held by this array.
     This function does not throw.
     @snippet PackArray.t.cpp PackArrayAccessors
     @return a pointer to the `data_` member of `this` array.
  **/
  uint8_t *data() noexcept;
  /**
   data. This returns a const pointer to `this` array's underlying data. This
allows the caller to do raw access to the data held by this array. This function
does not throw and does not modify `this` array.
   @snippet PackArray.t.cpp PackArrayAccessors
   @return a const pointer to the `data_` member of `this` array.
**/
  const uint8_t *data() const noexcept;

  /**
     size. This function returns the number of elements held by `this` array.
     This function does not throw or modify `this` array.
     @snippet PackArray.t.cpp PackArraySizeOnlyConstructor
     @return the number of elements in `this` array.
  **/
  size_t size() const noexcept;

  /**
     size_in_bytes. This function returns the number of bytes held by `this`
  array. This function does not throw or modify `this` array.
     @snippet PackArray.t.cpp PackArraySizeOnlyConstructor
     @return the number of bytes held by `this` array.
  **/
  size_t size_in_bytes() const noexcept;

  /**
     empty. This function returns true if the number of elements held by `this`
  array is zero and false otherwise. This function does not throw and does not
  modify `this` array.
     @return true if the array is empty, false otherwise.
  **/
  bool empty() const noexcept;

  /**
     begin. This function returns an iterator to the beginning of `this` array's
  data. This allows the caller to do iterative operations over `this` array.
  This function does not throw.
     @snippet PackArray.t.cpp PackArrayAccessors
     @return an iterator to the first element of `this` array.
  **/
  uint8_t *begin() noexcept;
  /**
     cbegin. This function returns a const iterator to the beginning of `this`
  array's data. This allows the caller to do iterative operations over `this`
  array. This function does not throw and does not modify `this` array.
     @snippet PackArray.t.cpp PackArrayAccessors
     @return a constant iterator to the first element of `this` array.
  **/
  const uint8_t *cbegin() const noexcept;

  /**
     end. This function returns an iterator to "one past" the end of `this`
  array's data. This allows the caller to do iterative operations over `this`
  array. This function does not throw.
     @snippet PackArray.t.cpp PackArrayAccessors
     @return an iterator to "one past" the end of `this` array's data.
  **/
  uint8_t *end() noexcept;
  /**
     cend. This function returns a const iterator to "one past" the end of
  `this` array's data. This allows the caller to do iterative operations over
  `this` array. This function does not throw.
     @snippet PackArray.t.cpp PackArrayAccessors
     @return a constant iterator to "one past" the end of `this` array's data.
  **/
  const uint8_t *cend() const noexcept;

  /**
     front. This function returns a reference to the first element in `this`
  array's data. This is conceptually the same as returning data[0], but it
  allows iterative operations. This function does not throw.
     @snippet PackArray.t.cpp PackArrayAccessors
     @return a reference to data[0].
  **/
  uint8_t &front() noexcept;
  /**
     front. This function returns a reference to the last element in `this`
  array's data. This is conceptually the same as returning data[size-1], but it
  allows iterative operations. This function does not throw.
     @snippet PackArray.t.cpp PackArrayAccessors
     @return a reference to data[size-1].
  **/
  uint8_t &back() noexcept;

  /**
     []. This function returns a reference to the element held at index `i`.
  This function does not throw.
     @snippet PackArray.t.cpp PackArrayAccessors
     @param[in] i: the position of the element to retrieve.
     @return a reference to the element at data[i].
  **/
  uint8_t &operator[](const size_t i) noexcept;

  /**
   []. This function returns a const reference to the element held at index `i`.
This function does not throw or modify `this` array.
   @snippet PackArray.t.cpp PackArrayAccessors
   @param[in] i: the position of the element to retrieve.
   @return a const reference to the element at data[i].
**/
  const uint8_t &operator[](const size_t i) const noexcept;

  /**
     init. This function deletes any memory associated with `this` array and
  allocates a new block, containing `new_size` entries. This function also
  updates the `size` of this entry. This function returns true if allocating the
  array succeeds and false otherwise.

  Note that this function does not copy over the original data inside this
  array: if you call this function, all of the data in the old array may be
  thrown away.

  If `new_size` == 0, then this function will simply null out the `data` pointer
  and set the size to 0.


  This function does not throw.
     @snippet PackArray.t.cpp PackArrayInit
     @param[in] new_size: the size of the new block.
     @return true in case of success, false otherwise.
  **/
  bool init(const size_t new_size) noexcept;

private:
  /**
     data_. This is the raw pointer to the uint8_t elements held by `this`
  array.
  **/
  uint8_t *data_;
  /**
     size_. This is the number of elements held in data_.
  **/
  size_t size_;
};

// Inline definitions are in the following file.
#include "PackArray.inl"
#endif
