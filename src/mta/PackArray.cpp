#include "PackArray.hpp"

static constexpr size_t nr_bytes_to_allocate(const size_t size) noexcept {
  // This function returns the number of bytes to be allocated inside
  // aligned_alloc. Essentially, the API requirements on aligned_alloc are that
  // the size parameter is a multiple of the alignment. The naive way to do this
  // (i.e writing size * sizeof(emp::block)) leaves us with a massive
  // over-allocation, as sizeof(emp::block) > sizeof(uint8_t) by a large factor.

  // To work out how many bytes to allocate, we simply round up `size` to the
  // nearest multiple of sizeof(emp::block). This is fast because
  // sizeof(emp::block) ought to be a power of 2.
  constexpr auto size_of_block = sizeof(emp::block);

  if (size == 0) {
    return 0;
  }

  static_assert(size_of_block && ((size_of_block & (size_of_block - 1)) == 0),
                "Error: sizeof(emp::block) is not a power of 2.");
  return (size + size_of_block - 1) & -size_of_block;
}

// N.B these checks are executed at compile-time.
static_assert(nr_bytes_to_allocate(0) == 0,
              "Error: nr_bytes_to_allocate failed with size = 0");
static_assert(nr_bytes_to_allocate(1) == sizeof(emp::block),
              "Error: nr_bytes_to_allocate failed with size = 1");
static_assert(
    nr_bytes_to_allocate(sizeof(emp::block) + 1) == 2 * sizeof(emp::block),
    "Error: nr_bytes_to_allocate failed with size = sizeof(emp::block)+1");
static_assert(
    nr_bytes_to_allocate(2 * sizeof(emp::block) - 1) == 2 * sizeof(emp::block),
    "Error: nr_bytes_to_allocate failed with size = 2*sizeof(emp::block)-1");

static uint8_t *alloc(const size_t size) noexcept {
  // This function just acts as a typed wrapper around aligned_alloc.
  return static_cast<uint8_t *>(
      aligned_alloc(sizeof(emp::block), nr_bytes_to_allocate(size)));
}

PackArray::PackArray(const size_t size) noexcept
    : data_{alloc(size)}, size_(size) {}

PackArray::PackArray(const PackArray &other) noexcept {
  size_ = other.size_;
  data_ = alloc(size_);
  memcpy(this->data_, other.data_, sizeof(uint8_t) * size_);
}

uint8_t *PackArray::data() noexcept { return data_; }
const uint8_t *PackArray::data() const noexcept { return data_; }

size_t PackArray::size() const noexcept { return size_; }

bool PackArray::empty() const noexcept { return size_ == 0; }

uint8_t *PackArray::begin() noexcept { return data_; }

const uint8_t *PackArray::cbegin() const noexcept { return data_; }

uint8_t *PackArray::end() noexcept { return data_ + size_; }
const uint8_t *PackArray::cend() const noexcept { return data_ + size_; }

uint8_t &PackArray::front() noexcept { return data_[0]; }
uint8_t &PackArray::back() noexcept { return data_[size_ - 1]; }
uint8_t &PackArray::operator[](const size_t i) noexcept { return data_[i]; }

size_t PackArray::size_in_bytes() const noexcept {
  return sizeof(*data_) * size_;
}

const uint8_t &PackArray::operator[](const size_t i) const noexcept {
  return data_[i];
}

bool PackArray::init(const size_t new_size) noexcept {
  // Save on allocations: just return if they match.
  if (new_size == size_) {
    return true;
  }

  // Throw away the old data.
  // N.B must use free because of aligned_alloc.
  free(data_);

  if (new_size == 0) {
    data_ = nullptr;
    size_ = 0;
    return true;
  }

  data_ = alloc(new_size);
  size_ = new_size;
  return data_ != nullptr;
}
