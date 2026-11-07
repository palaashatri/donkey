#include "donkey/binary/minidump.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "donkey/core/checked.h"

namespace donkey {
namespace {

constexpr std::uint32_t kSignature = 0x504d444d;   // "MDMP", little-endian
constexpr std::uint64_t kDirectoryEntrySize = 12;  // stream type, data size, rva

constexpr std::uint32_t kThreadListStream = 3;
constexpr std::uint32_t kModuleListStream = 4;
constexpr std::uint32_t kMemoryListStream = 5;
constexpr std::uint32_t kExceptionStream = 6;
constexpr std::uint32_t kSystemInfoStream = 7;
constexpr std::uint32_t kMemory64ListStream = 9;

constexpr std::uint64_t kThreadSize = 48;
constexpr std::uint64_t kModuleSize = 108;
constexpr std::uint64_t kMemoryDescriptorSize = 16;

constexpr std::uint16_t kArchitectureX86 = 0;
constexpr std::uint16_t kArchitectureAmd64 = 9;
constexpr std::uint16_t kArchitectureArm64 = 12;

/// The x86-64 CONTEXT: the flags, the eflags word, and the registers this reader names.
constexpr std::uint64_t kAmd64ContextEflagsAt = 0x44;
constexpr std::uint64_t kAmd64ContextSize = 0x4d0;  // 1232 bytes
struct Register {
  const char* name;
  std::uint64_t offset;
};
constexpr Register kAmd64Registers[] = {
    {"eflags", kAmd64ContextEflagsAt},
    {"rax", 0x78},
    {"rcx", 0x80},
    {"rdx", 0x88},
    {"rbx", 0x90},
    {"rsp", 0x98},
    {"rbp", 0xa0},
    {"rsi", 0xa8},
    {"rdi", 0xb0},
    {"r8", 0xb8},
    {"r9", 0xc0},
    {"r10", 0xc8},
    {"r11", 0xd0},
    {"r12", 0xd8},
    {"r13", 0xe0},
    {"r14", 0xe8},
    {"r15", 0xf0},
    {"rip", 0xf8},
};
constexpr std::uint64_t kAmd64RspOffset = 0x98;
constexpr std::uint64_t kAmd64RipOffset = 0xf8;

struct Location {
  std::uint32_t size = 0;
  std::uint32_t rva = 0;
};

std::optional<Location> location(const ByteReader& reader, std::uint64_t at) {
  const auto size = reader.u32(at, Endian::Little);
  const auto rva = reader.u32(at + 4, Endian::Little);
  if (!size || !rva) {
    return std::nullopt;
  }
  return Location{size.value(), rva.value()};
}

void note(MinidumpInfo& info, Status status, std::string code, std::string message,
          std::uint64_t offset) {
  info.diagnostics.push_back(Diagnostic::make(status, std::move(code), std::move(message), offset));
  info.partial = true;
}

/// Converts UTF-16LE code units to UTF-8. An unpaired surrogate becomes U+FFFD.
std::string utf8_of(const std::vector<std::uint16_t>& units) {
  std::string out;
  for (std::size_t i = 0; i < units.size(); ++i) {
    std::uint32_t code = units[i];
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < units.size() && units[i + 1] >= 0xdc00 &&
        units[i + 1] <= 0xdfff) {
      code = 0x10000 + ((code - 0xd800) << 10U) + (units[i + 1] - 0xdc00);
      ++i;
    } else if (code >= 0xd800 && code <= 0xdfff) {
      code = 0xfffd;
    }
    if (code < 0x80) {
      out += static_cast<char>(code);
    } else if (code < 0x800) {
      out += static_cast<char>(0xc0 | (code >> 6U));
      out += static_cast<char>(0x80 | (code & 0x3fU));
    } else if (code < 0x10000) {
      out += static_cast<char>(0xe0 | (code >> 12U));
      out += static_cast<char>(0x80 | ((code >> 6U) & 0x3fU));
      out += static_cast<char>(0x80 | (code & 0x3fU));
    } else {
      out += static_cast<char>(0xf0 | (code >> 18U));
      out += static_cast<char>(0x80 | ((code >> 12U) & 0x3fU));
      out += static_cast<char>(0x80 | ((code >> 6U) & 0x3fU));
      out += static_cast<char>(0x80 | (code & 0x3fU));
    }
  }
  return out;
}

/// A MINIDUMP_STRING: a byte length, then that many bytes of UTF-16LE.
std::optional<std::string> minidump_string(const ByteReader& reader, std::uint64_t at,
                                           std::size_t max_units, bool& truncated) {
  const auto bytes = reader.u32(at, Endian::Little);
  if (!bytes || bytes.value() % 2 != 0) {
    return std::nullopt;
  }
  const std::uint64_t units = bytes.value() / 2;
  truncated = units > max_units;
  std::vector<std::uint16_t> code_units;
  for (std::uint64_t i = 0; i < std::min<std::uint64_t>(units, max_units); ++i) {
    const auto unit = reader.u16(at + 4 + 2 * i, Endian::Little);
    if (!unit) {
      return std::nullopt;
    }
    code_units.push_back(unit.value());
  }
  return utf8_of(code_units);
}

/// The registers of an AMD64 thread context, or a note when the context is too short.
void read_amd64_context(const ByteReader& reader, const Location& context, MinidumpThread& thread,
                        MinidumpInfo& info) {
  if (context.size < kAmd64ContextSize) {
    note(info, Status::Partial, "minidump.context_short",
         "a thread context is shorter than the AMD64 CONTEXT", context.rva);
    return;
  }
  for (const Register& reg : kAmd64Registers) {
    const auto value = reader.u64(context.rva + reg.offset, Endian::Little);
    if (!value) {
      note(info, Status::Partial, "minidump.context_truncated",
           "a thread context runs past the file", context.rva);
      thread.registers.clear();
      return;
    }
    thread.registers.emplace_back(reg.name, value.value());
    if (reg.offset == kAmd64RipOffset) {
      thread.pc = value.value();
    } else if (reg.offset == kAmd64RspOffset) {
      thread.sp = value.value();
    }
  }
}

}  // namespace

std::string MinidumpInfo::architecture_name() const {
  switch (processor_architecture) {
    case kArchitectureX86:
      return "x86";
    case kArchitectureAmd64:
      return "x86-64";
    case kArchitectureArm64:
      return "arm64";
    case 5:
      return "arm";
    case 6:
      return "ia64";
    default:
      return "unknown";
  }
}

bool is_minidump(std::span<const std::byte> file) noexcept {
  const ByteReader reader(file);
  const auto signature = reader.u32(0, Endian::Little);
  return signature && signature.value() == kSignature;
}

Result<MinidumpInfo> read_minidump(std::span<const std::byte> file, const MinidumpLimits& limits) {
  if (!is_minidump(file)) {
    return make_error<MinidumpInfo>(Status::InvalidInput, "minidump.not_a_minidump",
                                    "the file does not begin with the MDMP signature");
  }
  const ByteReader reader(file);
  const auto stream_count = reader.u32(8, Endian::Little);
  const auto directory_rva = reader.u32(12, Endian::Little);
  if (!stream_count || !directory_rva ||
      !checked::in_range(directory_rva.value(), stream_count.value() * kDirectoryEntrySize,
                         file.size())) {
    return make_error<MinidumpInfo>(Status::InvalidInput, "minidump.bad_directory",
                                    "the stream directory is not inside the file");
  }

  MinidumpInfo info;
  // The first stream of each type wins: a dump names each kind once.
  struct Stream {
    std::uint32_t size;
    std::uint32_t rva;
  };
  std::vector<std::pair<std::uint32_t, Stream>> streams;
  const std::uint64_t counted = std::min<std::uint64_t>(stream_count.value(), limits.max_streams);
  if (counted < stream_count.value()) {
    note(info, Status::ResourceLimit, "minidump.stream_limit", "more streams than the limit", 0);
  }
  for (std::uint64_t i = 0; i < counted; ++i) {
    const std::uint64_t at = directory_rva.value() + i * kDirectoryEntrySize;
    const auto type = reader.u32(at, Endian::Little);
    const auto size = reader.u32(at + 4, Endian::Little);
    const auto rva = reader.u32(at + 8, Endian::Little);
    if (!type || !size || !rva) {
      note(info, Status::Partial, "minidump.directory_entry", "a stream entry is truncated", at);
      break;
    }
    streams.emplace_back(type.value(), Stream{size.value(), rva.value()});
  }
  const auto find = [&streams](std::uint32_t type) -> std::optional<Stream> {
    for (const auto& [stream_type, stream] : streams) {
      if (stream_type == type) {
        return stream;
      }
    }
    return std::nullopt;
  };
  // A stream's bytes must lie in the file; one that does not is reported and skipped.
  const auto usable = [&](std::uint32_t type) -> std::optional<Stream> {
    const auto stream = find(type);
    if (!stream) {
      return std::nullopt;
    }
    if (!checked::in_range(stream->rva, stream->size, file.size())) {
      note(info, Status::Partial, "minidump.stream_out_of_range",
           "a stream runs past the end of the file", stream->rva);
      return std::nullopt;
    }
    return stream;
  };

  if (const auto system = usable(kSystemInfoStream); system && system->size >= 24) {
    const auto architecture = reader.u16(system->rva, Endian::Little);
    const auto major = reader.u32(system->rva + 8, Endian::Little);
    const auto minor = reader.u32(system->rva + 12, Endian::Little);
    const auto build = reader.u32(system->rva + 16, Endian::Little);
    if (architecture && major && minor && build) {
      info.processor_architecture = architecture.value();
      info.major_version = major.value();
      info.minor_version = minor.value();
      info.build_number = build.value();
    }
  }

  if (const auto threads = usable(kThreadListStream)) {
    const auto count = reader.u32(threads->rva, Endian::Little);
    if (!count) {
      note(info, Status::Partial, "minidump.thread_list", "the thread list is truncated",
           threads->rva);
    } else {
      if (count.value() > limits.max_threads) {
        note(info, Status::ResourceLimit, "minidump.thread_limit", "more threads than the limit",
             threads->rva);
      }
      const std::uint64_t kept = std::min<std::uint64_t>(count.value(), limits.max_threads);
      for (std::uint64_t i = 0; i < kept; ++i) {
        const std::uint64_t at = threads->rva + 4 + i * kThreadSize;
        if (!checked::in_range(at, kThreadSize, file.size())) {
          note(info, Status::Partial, "minidump.thread_list", "a thread record runs past the file",
               at);
          break;
        }
        MinidumpThread thread;
        const auto id = reader.u32(at, Endian::Little);
        const auto stack_start = reader.u64(at + 24, Endian::Little);
        const auto stack = location(reader, at + 32);
        const auto context = location(reader, at + 40);
        if (!id || !stack_start || !stack || !context) {
          note(info, Status::Partial, "minidump.thread_list", "a thread record is truncated", at);
          break;
        }
        thread.id = id.value();
        thread.stack_start = stack_start.value();
        thread.stack_size = stack->size;
        if (context->size != 0) {
          if (!checked::in_range(context->rva, context->size, file.size())) {
            note(info, Status::Partial, "minidump.context_truncated",
                 "a thread context runs past the file", context->rva);
          } else if (info.processor_architecture == kArchitectureAmd64) {
            read_amd64_context(reader, context.value(), thread, info);
          } else {
            note(info, Status::Partial, "minidump.context_architecture",
                 "the registers of this architecture are not decoded", context->rva);
          }
        }
        info.threads.push_back(std::move(thread));
      }
    }
  }

  if (const auto modules = usable(kModuleListStream)) {
    const auto count = reader.u32(modules->rva, Endian::Little);
    if (!count) {
      note(info, Status::Partial, "minidump.module_list", "the module list is truncated",
           modules->rva);
    } else {
      if (count.value() > limits.max_modules) {
        note(info, Status::ResourceLimit, "minidump.module_limit", "more modules than the limit",
             modules->rva);
      }
      const std::uint64_t kept = std::min<std::uint64_t>(count.value(), limits.max_modules);
      for (std::uint64_t i = 0; i < kept; ++i) {
        const std::uint64_t at = modules->rva + 4 + i * kModuleSize;
        const auto base = reader.u64(at, Endian::Little);
        const auto size = reader.u32(at + 8, Endian::Little);
        const auto checksum = reader.u32(at + 12, Endian::Little);
        const auto timestamp = reader.u32(at + 16, Endian::Little);
        const auto name_rva = reader.u32(at + 20, Endian::Little);
        if (!checked::in_range(at, kModuleSize, file.size()) || !base || !size || !checksum ||
            !timestamp || !name_rva) {
          note(info, Status::Partial, "minidump.module_list", "a module record runs past the file",
               at);
          break;
        }
        MinidumpModule module;
        module.base = base.value();
        module.size = size.value();
        module.checksum = checksum.value();
        module.timestamp = timestamp.value();
        bool truncated = false;
        if (const auto name =
                minidump_string(reader, name_rva.value(), limits.max_name_length, truncated)) {
          module.name = name.value();
        } else {
          note(info, Status::Partial, "minidump.module_name", "a module name is unreadable",
               name_rva.value());
        }
        if (truncated) {
          note(info, Status::ResourceLimit, "minidump.name_limit",
               "a module name is over the limit", name_rva.value());
        }
        info.modules.push_back(std::move(module));
      }
    }
  }

  // Memory: the 64-bit list (its data follows the directory in order) or the list of RVAs.
  const auto add_range = [&](std::uint64_t address, std::uint64_t size, std::uint64_t offset) {
    if (info.memory.size() >= limits.max_memory_ranges) {
      note(info, Status::ResourceLimit, "minidump.memory_limit",
           "more memory ranges than the limit", offset);
      return false;
    }
    info.memory.push_back(MinidumpMemory{address, size, offset});
    return true;
  };
  if (const auto memory64 = usable(kMemory64ListStream)) {
    const auto count = reader.u64(memory64->rva, Endian::Little);
    const auto base = reader.u64(memory64->rva + 8, Endian::Little);
    if (!count || !base) {
      note(info, Status::Partial, "minidump.memory64", "the 64-bit memory list is truncated",
           memory64->rva);
    } else {
      std::uint64_t offset = base.value();
      for (std::uint64_t i = 0; i < count.value(); ++i) {
        const std::uint64_t at = memory64->rva + 16 + i * kMemoryDescriptorSize;
        const auto start = reader.u64(at, Endian::Little);
        const auto size = reader.u64(at + 8, Endian::Little);
        if (!start || !size) {
          note(info, Status::Partial, "minidump.memory64", "a memory descriptor is truncated", at);
          break;
        }
        if (!checked::in_range(offset, size.value(), file.size())) {
          note(info, Status::Partial, "minidump.memory_truncated",
               "a memory range runs past the end of the file", offset);
          break;
        }
        if (!add_range(start.value(), size.value(), offset)) {
          break;
        }
        offset += size.value();
      }
    }
  } else if (const auto memory = usable(kMemoryListStream)) {
    const auto count = reader.u32(memory->rva, Endian::Little);
    if (!count) {
      note(info, Status::Partial, "minidump.memory_list", "the memory list is truncated",
           memory->rva);
    } else {
      for (std::uint64_t i = 0; i < count.value(); ++i) {
        const std::uint64_t at = memory->rva + 4 + i * kMemoryDescriptorSize;
        const auto start = reader.u64(at, Endian::Little);
        const auto range = location(reader, at + 8);
        if (!start || !range) {
          note(info, Status::Partial, "minidump.memory_list", "a memory descriptor is truncated",
               at);
          break;
        }
        if (!checked::in_range(range->rva, range->size, file.size())) {
          note(info, Status::Partial, "minidump.memory_truncated",
               "a memory range runs past the end of the file", range->rva);
          continue;
        }
        if (!add_range(start.value(), range->size, range->rva)) {
          break;
        }
      }
    }
  }

  if (const auto exception = usable(kExceptionStream); exception && exception->size >= 40) {
    const auto thread_id = reader.u32(exception->rva, Endian::Little);
    const auto code = reader.u32(exception->rva + 8, Endian::Little);
    const auto address = reader.u64(exception->rva + 24, Endian::Little);
    if (thread_id && code && address) {
      info.has_exception = true;
      info.exception = MinidumpException{thread_id.value(), code.value(), address.value()};
    }
  }
  return info;
}

Result<std::vector<std::byte>> read_minidump_memory(std::span<const std::byte> file,
                                                    const MinidumpInfo& info, std::uint64_t address,
                                                    std::uint64_t size) {
  for (const MinidumpMemory& range : info.memory) {
    if (address < range.address || size > range.size ||
        address - range.address > range.size - size) {
      continue;
    }
    const std::uint64_t at = range.file_offset + (address - range.address);
    if (!checked::in_range(at, size, file.size())) {
      return make_error<std::vector<std::byte>>(Status::InvalidInput, "minidump.memory_truncated",
                                                "the memory range is not inside the file");
    }
    const auto begin = file.begin() + static_cast<std::ptrdiff_t>(at);
    return std::vector<std::byte>(begin, begin + static_cast<std::ptrdiff_t>(size));
  }
  return make_error<std::vector<std::byte>>(Status::InvalidInput, "minidump.memory_absent",
                                            "the dump does not hold that memory");
}

}  // namespace donkey
