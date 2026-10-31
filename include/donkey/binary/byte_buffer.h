#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "donkey/core/result.h"

namespace donkey {

/// Immutable bytes of a loaded file. Small files are copied into memory;
/// large files are mapped read-only, so loading a 1 GiB image does not
/// allocate 1 GiB: its pages are file-backed and reclaimable by the OS.
/// Copies share the same storage.
///
/// A mapped file must not be truncated by another process while it is open:
/// on POSIX systems touching a page past the new end raises SIGBUS. On
/// Windows the file is opened without write sharing, which prevents that.
class ByteBuffer {
 public:
  ByteBuffer() = default;
  /// Takes ownership of in-memory bytes (implicit so existing code that
  /// assigns a vector keeps working).
  ByteBuffer(std::vector<std::byte> bytes);  // NOLINT(google-explicit-constructor)

  /// Map `path` read-only. `expected_size` must match the file's size.
  [[nodiscard]] static Result<ByteBuffer> map_file(const std::string& path,
                                                   std::uint64_t expected_size);

  [[nodiscard]] const std::byte* data() const noexcept { return data_; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
  [[nodiscard]] bool mapped() const noexcept { return mapped_; }
  [[nodiscard]] const std::byte& operator[](std::size_t index) const noexcept {
    return data_[index];
  }
  [[nodiscard]] const std::byte* begin() const noexcept { return data_; }
  [[nodiscard]] const std::byte* end() const noexcept { return data_ + size_; }
  [[nodiscard]] std::span<const std::byte> span() const noexcept { return {data_, size_}; }
  operator std::span<const std::byte>() const noexcept {  // NOLINT(google-explicit-constructor)
    return span();
  }
  /// Copy into an owned vector (for code that must mutate the bytes).
  [[nodiscard]] std::vector<std::byte> to_vector() const { return {begin(), end()}; }

 private:
  struct Storage;
  std::shared_ptr<const Storage> storage_;
  const std::byte* data_ = nullptr;
  std::size_t size_ = 0;
  bool mapped_ = false;
};

}  // namespace donkey
