#include "donkey/binary/isolation.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#define DONKEY_HAS_POSIX_ISOLATION 1
#else
#define DONKEY_HAS_POSIX_ISOLATION 0
#endif

namespace donkey {

bool process_isolation_available() noexcept {
#if DONKEY_HAS_POSIX_ISOLATION
  return true;
#else
  return false;
#endif
}

#if DONKEY_HAS_POSIX_ISOLATION
namespace {

constexpr std::uint32_t kMagic = 0x444B4953;  // 'DKIS'

class BufferWriter {
 public:
  void write_u8(std::uint8_t val) { buffer_.push_back(static_cast<std::byte>(val)); }
  void write_u32(std::uint32_t val) {
    for (int i = 0; i < 4; ++i) {
      buffer_.push_back(static_cast<std::byte>((val >> (i * 8)) & 0xFF));
    }
  }
  void write_u64(std::uint64_t val) {
    for (int i = 0; i < 8; ++i) {
      buffer_.push_back(static_cast<std::byte>((val >> (i * 8)) & 0xFF));
    }
  }
  void write_string(const std::string& str) {
    write_u32(static_cast<std::uint32_t>(str.size()));
    for (char c : str) {
      buffer_.push_back(static_cast<std::byte>(c));
    }
  }
  void write_bytes(std::span<const std::byte> bytes) {
    write_u64(static_cast<std::uint64_t>(bytes.size()));
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
  }

  [[nodiscard]] const std::vector<std::byte>& data() const noexcept { return buffer_; }

 private:
  std::vector<std::byte> buffer_;
};

class BufferReader {
 public:
  explicit BufferReader(std::span<const std::byte> data) : data_(data) {}

  bool ok() const noexcept { return ok_; }

  std::uint8_t read_u8() {
    if (offset_ + 1 > data_.size()) {
      ok_ = false;
      return 0;
    }
    return static_cast<std::uint8_t>(data_[offset_++]);
  }

  std::uint32_t read_u32() {
    if (offset_ + 4 > data_.size()) {
      ok_ = false;
      return 0;
    }
    std::uint32_t val = 0;
    for (int i = 0; i < 4; ++i) {
      val |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(data_[offset_++])) << (i * 8);
    }
    return val;
  }

  std::uint64_t read_u64() {
    if (offset_ + 8 > data_.size()) {
      ok_ = false;
      return 0;
    }
    std::uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
      val |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(data_[offset_++])) << (i * 8);
    }
    return val;
  }

  std::string read_string() {
    const std::uint32_t len = read_u32();
    if (!ok_ || offset_ + len > data_.size()) {
      ok_ = false;
      return {};
    }
    std::string s;
    s.resize(len);
    for (std::uint32_t i = 0; i < len; ++i) {
      s[i] = static_cast<char>(data_[offset_++]);
    }
    return s;
  }

  std::vector<std::byte> read_bytes() {
    const std::uint64_t len = read_u64();
    if (!ok_ || offset_ + len > data_.size()) {
      ok_ = false;
      return {};
    }
    std::vector<std::byte> b(data_.begin() + static_cast<std::ptrdiff_t>(offset_),
                             data_.begin() + static_cast<std::ptrdiff_t>(offset_ + len));
    offset_ += static_cast<std::size_t>(len);
    return b;
  }

 private:
  std::span<const std::byte> data_;
  std::size_t offset_ = 0;
  bool ok_ = true;
};

std::vector<std::byte> serialize_result(const Result<LoadedBinary>& result) {
  BufferWriter writer;
  writer.write_u32(kMagic);
  if (!result) {
    writer.write_u8(0);  // Error
    writer.write_u8(static_cast<std::uint8_t>(result.diagnostic().status));
    writer.write_string(result.diagnostic().code);
    writer.write_string(result.diagnostic().message);
    if (result.diagnostic().offset.has_value()) {
      writer.write_u8(1);
      writer.write_u64(result.diagnostic().offset.value());
    } else {
      writer.write_u8(0);
    }
    return writer.data();
  }

  writer.write_u8(1);  // Success
  const LoadedBinary& loaded = result.value();
  const BinaryImage& img = loaded.image;

  writer.write_string(img.path);
  writer.write_u8(static_cast<std::uint8_t>(img.format));
  writer.write_u8(static_cast<std::uint8_t>(img.architecture));
  writer.write_u8(static_cast<std::uint8_t>(img.endian));
  writer.write_u32(img.bits);
  writer.write_u64(img.image_base);
  writer.write_u64(img.entry_point);
  writer.write_u64(img.file_size);
  writer.write_string(img.sha256);
  writer.write_string(img.format_detail);
  writer.write_u8(img.partial ? 1 : 0);

  // Segments
  writer.write_u32(static_cast<std::uint32_t>(img.segments.size()));
  for (const auto& seg : img.segments) {
    writer.write_u32(seg.index);
    writer.write_string(seg.name);
    writer.write_u64(seg.file_offset);
    writer.write_u64(seg.file_size);
    writer.write_u64(seg.virtual_address);
    writer.write_u64(seg.virtual_size);
    writer.write_u8(seg.readable ? 1 : 0);
    writer.write_u8(seg.writable ? 1 : 0);
    writer.write_u8(seg.executable ? 1 : 0);
  }

  // Sections
  writer.write_u32(static_cast<std::uint32_t>(img.sections.size()));
  for (const auto& sec : img.sections) {
    writer.write_u32(sec.id.value());
    writer.write_string(sec.name);
    writer.write_string(sec.type);
    writer.write_u64(sec.file_offset);
    writer.write_u64(sec.file_size);
    writer.write_u64(sec.address);
    writer.write_u64(sec.virtual_size);
    writer.write_u64(sec.alignment);
    writer.write_u8(sec.readable ? 1 : 0);
    writer.write_u8(sec.writable ? 1 : 0);
    writer.write_u8(sec.executable ? 1 : 0);
    writer.write_u8(sec.has_file_data ? 1 : 0);
  }

  // Symbols
  writer.write_u32(static_cast<std::uint32_t>(img.symbols.size()));
  for (const auto& sym : img.symbols) {
    writer.write_u32(sym.id.value());
    writer.write_string(sym.name);
    writer.write_string(sym.module);
    writer.write_u64(sym.address);
    writer.write_u64(sym.size);
    writer.write_u8(static_cast<std::uint8_t>(sym.kind));
    writer.write_u8(static_cast<std::uint8_t>(sym.binding));
    writer.write_u8(sym.imported ? 1 : 0);
    writer.write_u8(sym.exported ? 1 : 0);
  }

  // Fat architectures
  writer.write_u32(static_cast<std::uint32_t>(img.fat_architectures.size()));
  for (auto arch : img.fat_architectures) {
    writer.write_u8(static_cast<std::uint8_t>(arch));
  }

  // Diagnostics
  writer.write_u32(static_cast<std::uint32_t>(img.diagnostics.size()));
  for (const auto& diag : img.diagnostics) {
    writer.write_u8(static_cast<std::uint8_t>(diag.status));
    writer.write_string(diag.code);
    writer.write_string(diag.message);
    if (diag.offset.has_value()) {
      writer.write_u8(1);
      writer.write_u64(diag.offset.value());
    } else {
      writer.write_u8(0);
    }
  }

  // Loaded binary data
  writer.write_bytes(loaded.data);

  return writer.data();
}

Result<LoadedBinary> deserialize_result(std::span<const std::byte> bytes) {
  BufferReader reader(bytes);
  if (reader.read_u32() != kMagic || !reader.ok()) {
    return make_error<LoadedBinary>(Status::InvalidInput, "binary.corrupt_worker_data",
                                    "worker emitted invalid payload magic", 0);
  }

  const std::uint8_t tag = reader.read_u8();
  if (tag == 0) {  // Error
    const Status status = static_cast<Status>(reader.read_u8());
    const std::string code = reader.read_string();
    const std::string msg = reader.read_string();
    std::optional<std::uint64_t> offset;
    if (reader.read_u8() == 1) {
      offset = reader.read_u64();
    }
    if (!reader.ok()) {
      return make_error<LoadedBinary>(Status::InvalidInput, "binary.corrupt_worker_data",
                                      "failed decoding worker error diagnostic", 0);
    }
    return make_error<LoadedBinary>(status, code, msg, offset);
  }

  if (tag != 1) {
    return make_error<LoadedBinary>(Status::InvalidInput, "binary.corrupt_worker_data",
                                    "unknown worker payload tag", 0);
  }

  LoadedBinary loaded;
  BinaryImage& img = loaded.image;
  img.path = reader.read_string();
  img.format = static_cast<BinaryFormat>(reader.read_u8());
  img.architecture = static_cast<Architecture>(reader.read_u8());
  img.endian = static_cast<Endian>(reader.read_u8());
  img.bits = reader.read_u32();
  img.image_base = reader.read_u64();
  img.entry_point = reader.read_u64();
  img.file_size = reader.read_u64();
  img.sha256 = reader.read_string();
  img.format_detail = reader.read_string();
  img.partial = (reader.read_u8() == 1);

  const std::uint32_t seg_count = reader.read_u32();
  img.segments.reserve(seg_count);
  for (std::uint32_t i = 0; i < seg_count; ++i) {
    Segment seg;
    seg.index = reader.read_u32();
    seg.name = reader.read_string();
    seg.file_offset = reader.read_u64();
    seg.file_size = reader.read_u64();
    seg.virtual_address = reader.read_u64();
    seg.virtual_size = reader.read_u64();
    seg.readable = (reader.read_u8() == 1);
    seg.writable = (reader.read_u8() == 1);
    seg.executable = (reader.read_u8() == 1);
    img.segments.push_back(std::move(seg));
  }

  const std::uint32_t sec_count = reader.read_u32();
  img.sections.reserve(sec_count);
  for (std::uint32_t i = 0; i < sec_count; ++i) {
    Section sec;
    sec.id = SectionId{reader.read_u32()};
    sec.name = reader.read_string();
    sec.type = reader.read_string();
    sec.file_offset = reader.read_u64();
    sec.file_size = reader.read_u64();
    sec.address = reader.read_u64();
    sec.virtual_size = reader.read_u64();
    sec.alignment = reader.read_u64();
    sec.readable = (reader.read_u8() == 1);
    sec.writable = (reader.read_u8() == 1);
    sec.executable = (reader.read_u8() == 1);
    sec.has_file_data = (reader.read_u8() == 1);
    img.sections.push_back(std::move(sec));
  }

  const std::uint32_t sym_count = reader.read_u32();
  img.symbols.reserve(sym_count);
  for (std::uint32_t i = 0; i < sym_count; ++i) {
    Symbol sym;
    sym.id = SymbolId{reader.read_u32()};
    sym.name = reader.read_string();
    sym.module = reader.read_string();
    sym.address = reader.read_u64();
    sym.size = reader.read_u64();
    sym.kind = static_cast<SymbolKind>(reader.read_u8());
    sym.binding = static_cast<SymbolBinding>(reader.read_u8());
    sym.imported = (reader.read_u8() == 1);
    sym.exported = (reader.read_u8() == 1);
    img.symbols.push_back(std::move(sym));
  }

  const std::uint32_t fat_count = reader.read_u32();
  img.fat_architectures.reserve(fat_count);
  for (std::uint32_t i = 0; i < fat_count; ++i) {
    img.fat_architectures.push_back(static_cast<Architecture>(reader.read_u8()));
  }

  const std::uint32_t diag_count = reader.read_u32();
  img.diagnostics.reserve(diag_count);
  for (std::uint32_t i = 0; i < diag_count; ++i) {
    const Status status = static_cast<Status>(reader.read_u8());
    const std::string code = reader.read_string();
    const std::string msg = reader.read_string();
    std::optional<std::uint64_t> offset;
    if (reader.read_u8() == 1) {
      offset = reader.read_u64();
    }
    img.diagnostics.push_back(Diagnostic::make(status, code, msg, offset));
  }

  loaded.data = reader.read_bytes();

  if (!reader.ok()) {
    return make_error<LoadedBinary>(Status::InvalidInput, "binary.corrupt_worker_data",
                                    "truncated payload from worker process", 0);
  }
  return loaded;
}

}  // namespace
#endif  // DONKEY_HAS_POSIX_ISOLATION

Result<LoadedBinary> load_binary_isolated(const std::string& path, const LoadOptions& options,
                                          const IsolationConfig& config) {
#if DONKEY_HAS_POSIX_ISOLATION
  int pipe_fds[2];
  if (pipe(pipe_fds) < 0) {
    return make_error<LoadedBinary>(Status::InternalError, "binary.isolation_pipe_failed",
                                    "failed to create isolation IPC pipe", 0);
  }

  const pid_t pid = fork();
  if (pid < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return make_error<LoadedBinary>(Status::InternalError, "binary.isolation_fork_failed",
                                    "failed to fork isolation worker process", 0);
  }

  if (pid == 0) {
    // Child process: untrusted execution domain
    close(pipe_fds[0]);

    if (config.timeout_seconds > 0) {
      struct rlimit rl_cpu{};
      rl_cpu.rlim_cur = config.timeout_seconds;
      rl_cpu.rlim_max = config.timeout_seconds + 1;
      setrlimit(RLIMIT_CPU, &rl_cpu);
    }

#ifdef RLIMIT_AS
    if (config.max_memory_bytes > 0) {
      struct rlimit rl_as{};
      rl_as.rlim_cur = config.max_memory_bytes;
      rl_as.rlim_max = config.max_memory_bytes;
      setrlimit(RLIMIT_AS, &rl_as);
    }
#endif

    // Hostile QA hooks
    if (config.force_worker_crash) {
      volatile int* crash_ptr = nullptr;
      *crash_ptr = 42;
    }
    if (config.force_worker_hang) {
      while (true) {
      }
    }

    const auto result = load_binary(path, options);
    const auto payload = serialize_result(result);

    std::size_t written = 0;
    while (written < payload.size()) {
      const ssize_t count = write(pipe_fds[1], payload.data() + written, payload.size() - written);
      if (count <= 0) {
        break;
      }
      written += static_cast<std::size_t>(count);
    }
    close(pipe_fds[1]);
    _exit(0);
  }

  // Parent supervisor process
  close(pipe_fds[1]);

  std::vector<std::byte> response_buffer;
  constexpr std::size_t kChunkSize = 65536;
  std::byte chunk[kChunkSize];

  const int timeout_ms =
      config.timeout_seconds > 0 ? static_cast<int>(config.timeout_seconds * 1000) : 5000;

  bool timed_out = false;
  while (true) {
    struct pollfd pfd{};
    pfd.fd = pipe_fds[0];
    pfd.events = POLLIN | POLLHUP;

    const int poll_res = poll(&pfd, 1, timeout_ms);
    if (poll_res == 0) {
      // Timeout
      timed_out = true;
      break;
    }
    if (poll_res < 0) {
      break;
    }

    const ssize_t bytes_read = read(pipe_fds[0], chunk, sizeof(chunk));
    if (bytes_read <= 0) {
      break;  // EOF
    }
    response_buffer.insert(response_buffer.end(), chunk, chunk + bytes_read);
  }
  close(pipe_fds[0]);

  if (timed_out) {
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
    return make_error<LoadedBinary>(Status::ResourceLimit, "binary.worker_timeout",
                                    "isolated parser worker exceeded resource limit or timed out",
                                    0);
  }

  int wstatus = 0;
  waitpid(pid, &wstatus, 0);

  if (WIFSIGNALED(wstatus)) {
    const int sig = WTERMSIG(wstatus);
#ifdef SIGXCPU
    if (sig == SIGXCPU) {
      return make_error<LoadedBinary>(Status::ResourceLimit, "binary.worker_timeout",
                                      "isolated parser worker exceeded CPU time limit", 0);
    }
#endif
    return make_error<LoadedBinary>(
        Status::InvalidInput, "binary.worker_crashed",
        "isolated parser worker crashed with signal " + std::to_string(sig), 0);
  }

  if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0) {
    return make_error<LoadedBinary>(
        Status::InvalidInput, "binary.worker_failed",
        "isolated parser worker exited with status " + std::to_string(WEXITSTATUS(wstatus)), 0);
  }

  return deserialize_result(response_buffer);
#else
  // Non-POSIX platforms degrade safely to in-process checked loading
  (void)config;
  auto loaded = load_binary(path, options);
  if (loaded) {
    loaded.value().image.add_diagnostic(
        Status::Unsupported, "binary.isolation_unavailable",
        "real OS process isolation is not supported on this host platform");
  }
  return loaded;
#endif
}

}  // namespace donkey
