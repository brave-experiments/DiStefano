#ifndef EMP_FILE_IO_CHANNEL_H__
#define EMP_FILE_IO_CHANNEL_H__

#include "emp-tool/io/io_channel.h"
#include <iostream>

namespace emp {
class FileIO : public IOChannel<FileIO> {
public:
  uint64_t bytes_sent = 0;
  int mysocket = -1;
  FILE *stream = nullptr;
  char *buffer = nullptr;
  FileIO(const char *file, bool read) {
    if (read)
      stream = fopen(file, "rb+");
    else
      stream = fopen(file, "wb+");
    buffer = new char[FILE_BUFFER_SIZE];
    memset(buffer, 0, FILE_BUFFER_SIZE);
    setvbuf(stream, buffer, _IOFBF, FILE_BUFFER_SIZE);
  }

  ~FileIO() {
    fflush(stream);
    fclose(stream);
    delete[] buffer;
  }

  void flush() { fflush(stream); }

  void reset() { rewind(stream); }
  void send_data_internal(const void *data, size_t len) {
    bytes_sent += len;
    size_t sent = 0;
    while (sent < len) {
      size_t res = fwrite(sent + (const char *)data, 1, len - sent, stream);
      if (res >= 0)
        sent += res;
      else
        fprintf(stderr, "error: file_send_data %d\n", res);
    }
  }
  void recv_data_internal(void *data, size_t len2) {
    int len{len2};
    int sent = 0;
    while (sent < len) {
      int res = fread(sent + (char *)data, 1, len - sent, stream);
      if (res >= 0)
        sent += res;
      else
        fprintf(stderr, "error: file_recv_data %d\n", res);
    }
  }
};

} // namespace emp
#endif
