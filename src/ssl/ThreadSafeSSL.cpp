#include "ThreadSafeSSL.hpp"
#include "Util.hpp" // Needed for generic I/O routines.
#include <algorithm>
#include <iostream>
// Our datagrams in this file have the following two leading entries:
// 1. The tag where the message is due to be stored, and
// 2. The number of bytes in the message.
// We arbitrarily assume this fits into 64 bits. This should be true, as we
// don't expect either party to have more than 256 threads available, or for
// anyone to be sending messages larger than 2^56 bytes long.
struct Packed {
  unsigned header : 8;
  size_t size : 56;
};

// Check the packet header fits exactly into 64 bits.
static_assert(sizeof(Packed) == sizeof(uint64_t));

ThreadSafeSSL::ThreadSafeSSL(SSL *const ssl_in) noexcept
    : count{}, socket_lock{}, ssl{ssl_in}, registered_in{},
      registered_out{}, incoming{} {
  assert(ssl);
  // N.B there's a constexpr way to do this initialisation, but it's rather
  // long. If this is too slow, we can fix it.
  std::fill(registered_in.begin(), registered_in.end(),
            ThreadSafeSSL::tombstone);
  std::fill(registered_out.begin(), registered_out.end(),
            ThreadSafeSSL::tombstone);
}

SSL *ThreadSafeSSL::get_ssl() noexcept { return ssl; }

unsigned ThreadSafeSSL::register_new_socket() noexcept {
  assert(count + 1 < ThreadSafeSSL::max_size);
  return count++;
}

unsigned ThreadSafeSSL::find_first_tombstone() const noexcept {
  // Broken out for readability.
  constexpr auto predicate = [](const uint8_t value) {
    return value == ThreadSafeSSL::tombstone;
  };

  const auto it = std::find_if(std::cbegin(registered_out),
                               std::cbegin(registered_out) + count, predicate);
  if (it == std::cbegin(registered_out) + count) {
    return ThreadSafeSSL::tombstone;
  }

  // This cast is safe because we have an upper limit on the size of
  // registered_in.
  return static_cast<unsigned>(std::distance(std::cbegin(registered_out), it));
}

void ThreadSafeSSL::recv(const unsigned tag, void *const data,
                         const unsigned nbyte) noexcept {

  // Precondition: data must be a valid pointer.
  assert(data);

  // Make sure the caller hasn't messed up.
  assert(tag < ThreadSafeSSL::max_size);
  assert(tag < count);

  // First thing we do is lock the entire class.
  std::lock_guard<std::mutex> lock(socket_lock);

  // Now we have three situations:
  // 1. We already have a message ready for us. Let's not read from the socket:
  // we'll just read from our slot and return that.
  if (incoming[tag].size() > 0) {
    auto buffer = incoming[tag].data();
    // Stop us from reading too much data.
    assert(nbyte <= incoming[tag].size());
    memcpy(data, buffer, nbyte);
    incoming[tag].erase(incoming[tag].begin(), incoming[tag].begin() + nbyte);
    return;
  }

  // The other cases are:
  // 2. We've entered this function with a thread that has never received data
  // before.
  // 3. We've entered this function with a thread that has received data.
  // before, but there's no messages in the buffer for us.
  // In any case, we need to read the header to find out.
  Packed header;
  [[maybe_unused]] const auto header_bytes =
      SSL_read(ssl, &header, sizeof(header));
  // Only in debug.
  assert(header_bytes == sizeof(header));
  
  // We actually handle both cases in a single loop.
  size_t amount_read_for_this = 0;
  while (true) {
    // This is just an abbreviation.
    const auto dest_tag = registered_in[header.header];
    // If the message is for us, we just read it already.
    if (dest_tag == tag) {
      // We might have more data to read here than we wanted. To stop us from
      // over running the buffer if that's the case, we:
      // 1. Read the first nbytes into the `data` buffer, and
      // 2. Read the rest into the buffer for this tag. This will be read into
      // the next time the tag calls this particular function.
      if (nbyte >= header.size) {
        Util::process_data(ssl,
                           static_cast<char *>(data) + amount_read_for_this,
                           header.size, SSL_read);
        amount_read_for_this += header.size;
      } else {
        // If we've hit this case then there's nothing in _our_ buffer already,
        // so we can just resize and copy from the beginning.
        Util::process_data(ssl, static_cast<char *>(data), nbyte, SSL_read);
        incoming[tag].resize(header.size - nbyte);
        Util::process_data(ssl, incoming[tag].data(), header.size - nbyte,
                           SSL_read);
        amount_read_for_this += nbyte;
      }
    } else if (dest_tag == ThreadSafeSSL::tombstone) {
      // Case 2: a new thread has appeared.
      // It's possible that we've read on a thread that has already been
      // assigned to another thread (e.g on the other side) but we've received
      // a new message anyway. We patch that here by finding the first thread on
      // this node that hasn't yet been assigned to a thread on the other node.
      const auto thread = (registered_out[tag] == ThreadSafeSSL::tombstone)
                              ? tag
                              : find_first_tombstone();
      // This will fire if there's no free threads on our side to deal with those
      // messages. 
      assert(thread != ThreadSafeSSL::tombstone);
      const auto thread_as_uint8 = static_cast<uint8_t>(thread);
      // Set up the forwarding tables.
      registered_out[thread] = header.header;
      registered_in[header.header] = thread_as_uint8;

      // Read into this tag's buffer if appropriate.
      if (thread == tag) {
        Util::process_data(ssl, static_cast<char *>(data),
                           static_cast<size_t>(header.size), SSL_read);
        amount_read_for_this = static_cast<unsigned>(header.size);
      } else {
        incoming[thread].resize(header.size);
        Util::process_data(ssl, incoming[thread].data(),
                           static_cast<size_t>(header.size), SSL_read);
      }

      // Now we have to tell the other thread who they are speaking to.
      [[maybe_unused]] const auto written_bytes =
          SSL_write(ssl, &thread_as_uint8, sizeof(thread_as_uint8));
      assert(written_bytes > 0);
    } else {
      // Otherwise, we are going to append into the buffer that the message is
      // due for. To do that, we have to reallocate enough memory to be able to
      // read into the buffer for that particular tag.
      const auto end_pos = incoming[dest_tag].size();
      incoming[dest_tag].resize(end_pos + header.size);
      Util::process_data(ssl, incoming[dest_tag].data() + end_pos,
                         static_cast<std::size_t>(nbyte), SSL_read);
    }

    // If we've read everything, then quit.
    if (amount_read_for_this == nbyte) {
      return;
    }

    // Otherwise, there must be data left, so quit.
    [[maybe_unused]] const auto head_bytes =
        SSL_read(ssl, &header, sizeof(header));
    assert(head_bytes == sizeof(header));
    // We'll deal with everything else on the next iteration.
  }
}

void ThreadSafeSSL::send(const unsigned tag, const void *const data,
                         const unsigned nbyte) noexcept {

  // Precondition: cannot send null data.
  assert(data);

  // To prevent the caller from messing up.
  assert(tag < ThreadSafeSSL::max_size);
  assert(tag < count);

  // Lock the class to prevent race conditions.
  std::lock_guard<std::mutex> lock(socket_lock);

  // This code mirrors the code in recv quite closely.
  // Here, though, we only have two cases:
  // 1. We have a thread that is new.
  // 2. We have a thread that is already established.

  // Remarkably the code is mostly the same: the difference is if we
  // need to wait for the other node to send a message back to us.

  // In either case we need to use a header for writing.
  // N.B This cast is fine as tag can fit into a uint8_t.
  Packed header{static_cast<uint8_t>(tag), nbyte};
  [[maybe_unused]] const auto bytes_written =
                     SSL_write(ssl, &header, sizeof(header));
  assert(bytes_written > 0);
  
  // Now we just write everything else out too.
  Util::process_data(ssl, static_cast<const char *>(data),
                     static_cast<size_t>(nbyte), SSL_write);

  // Now we need to check if this was the first contact with another thread or
  // not.
  if (registered_out[tag] == ThreadSafeSSL::tombstone) {
    // We just read the tag back from the other side.
    // N.B This assumes that both parties have the same endianness!
    uint8_t other_tag;
    [[maybe_unused]] const auto header_bytes =
        SSL_read(ssl, &other_tag, sizeof(other_tag));
    assert(header_bytes == sizeof(other_tag));
    // Now we set up the tables.
    registered_out[tag] = other_tag;
    // This cast is safe because we statically enforce a maximum size on
    // `tag`.
    registered_in[other_tag] = static_cast<uint8_t>(tag);
  }
}

bool ThreadSafeSSL::is_registered_in(const unsigned tag) const noexcept {
  assert(tag < ThreadSafeSSL::max_size);
  assert(tag < count);
  return registered_in[tag] != ThreadSafeSSL::tombstone;
}

bool ThreadSafeSSL::is_registered_out(const unsigned tag) const noexcept {
  assert(tag < ThreadSafeSSL::max_size);
  assert(tag < count);
  return registered_in[tag] != ThreadSafeSSL::tombstone;
}
