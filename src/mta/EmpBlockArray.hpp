#ifndef INCLUDED_EMPBLOCKARRAY_HPP
#define INCLUDED_EMPBLOCKARRAY_HPP

#include <emp-tool/utils/block.h> // Needed for emp::block

/**
   EmpBlockArray. This class models an array for emp::blocks.
   Conceptually, this class is identical to a std::array of emp::block.

   The raison d'etre for this class is that C++ templates are not required
   to follow alignment rules as specified by compiler attributes.

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
 this problem, we simply roll our own class for an array type here.
 @tparam size: an unsigned int denoting the number of blocks in the array.
 **/

template <unsigned size_> class EmpBlockArray {
  // C++17 and below do not allow zero-sized objects.
  static_assert(size_ != 0, "Error: cannot instantiate an empty array");

private:
  /**
     This array contains the underlying storage.
     The data in this array can be accessed directly via
     data().
  **/
  emp::block arr[size_];

public:
  /**
     IteratorType. This type defines the type of iterator that this
     array uses. This is just the same as the type of iterator used by the
     underlying array.
  **/
  using IteratorType = decltype(std::begin(arr));

  /**
     ConstIteratorType. This type defines the type of const iterator that this
     array uses. This is just the same as the type of const iterator used by the
     underlying array.
  **/
  using ConstIteratorType = decltype(std::cbegin(arr));

  /**
     ArrType. This type defines the type of the array held by this class.
  **/
  using ArrType = decltype(arr);

  /**
     EmpBlockArray. This constructor accepts no arguments and produces
     a default initialised array of size `size_`. This constructor
     does not throw.
     @snippet EmpArray.t.cpp EmpBlockArrayDefaultConstruct.
  **/
  constexpr EmpBlockArray() noexcept;

  /**
     size. This function returns the size of this array as an unsigned integer.
     This function essentially returns the `size_` template argument.
     This function does not throw or modify `this` object.
     @snippet EmpBlockArray.t.cpp EmpBlockArraySize.
     @return the number of elements in `this` array.
  **/
  constexpr unsigned size() const noexcept;

  /**
     data. This function returns a non-null const pointer to the
     underlying storage of `this` array. This function does not
     throw or modify `this` array.

     @snippet EmpBlockArray.t.cpp EmpBlockArrayData
     @return a const non-null pointer to the storage underlying `this` array.
  **/
  constexpr const emp::block *data() const noexcept;
  /**
     data. This function returns a non-null pointer to the
     underlying storage of `this` array. This function does not
     throw or modify `this` array directly, but it does allow a caller to
     directly modify `this` array.

     @snippet EmpBlockArray.t.cpp EmpBlockArrayData
     @return a non-null pointer to the storage underlying `this` array.
  **/
  constexpr emp::block *data() noexcept;

  /**
     get_arr. This function returns a reference to the underlying storage of
  `this` array. This function does not throw or modify `this` array directly,
  but it does allow a caller to directly modify `this` array.
     @return a reference to the storage underlying `this` array.
  **/
  constexpr ArrType &get_arr() noexcept;

  /**
     get_arr. This function returns a const reference to the underlying storage
  of `this` array. This function does not throw or modify `this` array directly.
     @return a reference to the storage underlying `this` array.
  **/
  constexpr const ArrType &get_arr() const noexcept;

  /**
     operator[]. This function returns a non-const reference to the array
  element at index `index`. This function does not throw. Note that this
  function allows a caller to modify the retrieved object.

     @snippet EmpBlockArray.t.cpp EmpBlockArrayOperator[].
     @param[in] index: the index of the object. In debug builds, we assert that
     index < size_.
     @return a non-const reference to the object at arr[index].
  **/
  constexpr emp::block &operator[](const unsigned int index) noexcept;

  /**
     operator[]. This function returns a const reference to the array
  element at index `index`. This function does not throw. Note that this
  function does not allow the caller to modify the retrieved object.

     @snippet EmpBlockArray.t.cpp EmpBlockArrayOperator[].
     @param[in] index: the index of the object. In debug builds, we assert that
     index < size_.
     @return a const reference to the object at arr[index].
  **/
  constexpr const emp::block &
  operator[](const unsigned int index) const noexcept;

  /**
     begin. This function returns an iterator to the beginning of `this` array's
     underlying storage. This function does not throw. This function does allow
     indirect modification of `this` array.
     @snippet EmpBlockArray.t.cpp EmpBlockArrayBegin.
     @return a non-const iterator to the beginning of this array.
  **/
  constexpr IteratorType begin() noexcept;

  /**
     cbegin. This function returns an iterator to the beginning of `this`
  array's underlying storage. This function does not throw. This function does
  not allow indirect modification of `this` array.
     @snippet EmpBlockArray.t.cpp EmpBlockArrayCBegin.
     @return a const iterator to the beginning of this array.
  **/
  constexpr ConstIteratorType cbegin() const noexcept;

  /**
     end. This function returns an iterator to the end of `this` array's
     underlying storage. This function does not throw. Note that this does
     not return an iterator to arr[size_-1]: in C++, end() returns "1 past"
     the end of the array.

     This function allows indirect modification of `this` array.
     @snippet EmpBlockArray.t.cpp EmpBlockArrayEnd.
     @return a non-const iterator to the end of this array.
  **/
  constexpr IteratorType end() noexcept;

  /**
     cend. This function returns an iterator to the end of `this` array's
     underlying storage. This function does not throw. Note that this does
     not return an iterator to arr[size_-1]: in C++, end() returns "1 past"
     the end of the array.

     This function does not allow indirect modification of `this` array.
     @snippet EmpBlockArray.t.cpp EmpBlockArrayCEnd.
     @return a non-const iterator to the end of this array.
  **/
  constexpr ConstIteratorType cend() const noexcept;
};

// Inline definitions go here.
#include "EmpBlockArray.inl"

#endif
