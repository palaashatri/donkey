#include "donkey/binary/byte_buffer.h"

#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace donkey {

/// Owns either a vector or a mapping; releases the mapping when the last
/// ByteBuffer sharing it goes away.
struct ByteBuffer::Storage {
  std::vector<std::byte> owned;
  void* mapping = nullptr;
  std::size_t mapping_size = 0;
#if defined(_WIN32)
  HANDLE file = INVALID_HANDLE_VALUE;
  HANDLE section = nullptr;
#endif

  Storage() = default;
  Storage(const Storage&) = delete;
  Storage& operator=(const Storage&) = delete;

  ~Storage() {
#if defined(_WIN32)
    if (mapping != nullptr) {
      UnmapViewOfFile(mapping);
    }
    if (section != nullptr) {
      CloseHandle(section);
    }
    if (file != INVALID_HANDLE_VALUE) {
      CloseHandle(file);
    }
#else
    if (mapping != nullptr) {
      ::munmap(mapping, mapping_size);
    }
#endif
  }
};

ByteBuffer::ByteBuffer(std::vector<std::byte> bytes) {
  auto storage = std::make_shared<Storage>();
  storage->owned = std::move(bytes);
  data_ = storage->owned.data();
  size_ = storage->owned.size();
  storage_ = std::move(storage);
}

Result<ByteBuffer> ByteBuffer::map_file(const std::string& path, std::uint64_t expected_size) {
  auto fail = [](const std::string& message) {
    return make_error<ByteBuffer>(Status::InvalidInput, "io.map_failed", message);
  };
  if (expected_size == 0) {
    return fail("cannot map an empty file");
  }
  if (expected_size > static_cast<std::uint64_t>(SIZE_MAX)) {
    return fail("file is larger than the address space");
  }
  auto storage = std::make_shared<Storage>();
#if defined(_WIN32)
  const int wide_len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
  if (wide_len <= 0) {
    return fail("path is not valid UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(wide_len), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wide.data(), wide_len);
  // No FILE_SHARE_WRITE: nobody can truncate or rewrite the file while it
  // is mapped.
  storage->file = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (storage->file == INVALID_HANDLE_VALUE) {
    return fail("could not open the file for mapping");
  }
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(storage->file, &size) ||
      static_cast<std::uint64_t>(size.QuadPart) != expected_size) {
    return fail("the file changed size while it was being opened");
  }
  storage->section = CreateFileMappingW(storage->file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (storage->section == nullptr) {
    return fail("could not create a file mapping");
  }
  storage->mapping = MapViewOfFile(storage->section, FILE_MAP_READ, 0, 0, 0);
  if (storage->mapping == nullptr) {
    return fail("could not map the file");
  }
#else
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return fail("could not open the file for mapping");
  }
  struct stat info{};
  if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
      static_cast<std::uint64_t>(info.st_size) != expected_size) {
    ::close(fd);
    return fail("the file changed size while it was being opened");
  }
  void* mapping =
      ::mmap(nullptr, static_cast<std::size_t>(expected_size), PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);  // the mapping keeps its own reference to the file
  if (mapping == MAP_FAILED) {
    return fail("could not map the file");
  }
  storage->mapping = mapping;
#endif
  storage->mapping_size = static_cast<std::size_t>(expected_size);

  ByteBuffer buffer;
  buffer.data_ = static_cast<const std::byte*>(storage->mapping);
  buffer.size_ = storage->mapping_size;
  buffer.mapped_ = true;
  buffer.storage_ = std::move(storage);
  return buffer;
}

}  // namespace donkey
