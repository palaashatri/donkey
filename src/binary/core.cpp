#include "donkey/binary/core.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/binary/byte_reader.h"

namespace donkey {
namespace {

constexpr std::uint32_t kPtNote = 4;
constexpr std::uint32_t kNtPrstatus = 1;
constexpr std::uint32_t kNtPrpsinfo = 3;
constexpr std::uint32_t kNtFile = 0x46494c45;  // "FILE"
constexpr std::uint64_t kProgramHeaderMinimum = 56;
constexpr std::uint64_t kPrstatusSize = 336;       // x86-64 elf_prstatus
constexpr std::uint64_t kPrstatusRegisters = 112;  // pr_reg follows pid, signals and times
constexpr std::uint64_t kPrstatusPid = 32;
constexpr std::uint64_t kPrpsinfoName = 40;
constexpr std::uint64_t kPrpsinfoNameLength = 16;
constexpr std::uint64_t kNtFileEntry = 24;  // start, end, file offset (in pages)
constexpr std::uint64_t kMaxPathLength = 4'096;

/// The x86-64 user_regs_struct, in the kernel's order.
constexpr const char* kX86_64Registers[] = {
    "r15",    "r14", "r13", "r12",     "rbp",     "rbx", "r11",      "r10", "r9",
    "r8",     "rax", "rcx", "rdx",     "rsi",     "rdi", "orig_rax", "rip", "cs",
    "eflags", "rsp", "ss",  "fs_base", "gs_base", "ds",  "es",       "fs",  "gs",
};
constexpr std::size_t kX86_64RegisterCount = sizeof(kX86_64Registers) / sizeof(kX86_64Registers[0]);
constexpr std::size_t kRipIndex = 16;
constexpr std::size_t kRspIndex = 19;

std::uint64_t align4(std::uint64_t value) {
  return (value + 3) & ~std::uint64_t{3};
}

std::string trim_nul(std::string_view text) {
  const std::size_t end = text.find('\0');
  return std::string(end == std::string_view::npos ? text : text.substr(0, end));
}

void note(CoreInfo& info, Status status, std::string code, std::string message,
          std::uint64_t offset) {
  info.diagnostics.push_back(Diagnostic::make(status, std::move(code), std::move(message), offset));
  info.partial = true;
}

class NoteReader {
 public:
  NoteReader(std::span<const std::byte> data, const BinaryImage& image, const CoreOptions& options,
             CoreInfo& info)
      : data_(data), image_(image), options_(options), info_(info) {}

  void read_segment(std::uint64_t begin, std::uint64_t end) {
    const ByteReader reader(data_);
    std::uint64_t at = begin;
    std::size_t notes = 0;
    while (at + 12 <= end) {
      if (++notes > options_.max_notes) {
        note(info_, Status::ResourceLimit, "core.note_limit",
             "more notes than the limit; the rest are not read", at);
        return;
      }
      const auto namesz = reader.u32(at, Endian::Little);
      const auto descsz = reader.u32(at + 4, Endian::Little);
      const auto type = reader.u32(at + 8, Endian::Little);
      if (!namesz || !descsz || !type) {
        note(info_, Status::Partial, "core.note_header", "a note header is unreadable", at);
        return;
      }
      const std::uint64_t name_at = at + 12;
      const std::uint64_t desc_at = name_at + align4(namesz.value());
      const std::uint64_t next = desc_at + align4(descsz.value());
      if (desc_at > end || next > end || next < at) {
        note(info_, Status::Partial, "core.note_truncated", "a note runs past its segment", at);
        return;
      }
      const auto name = reader.slice(name_at, namesz.value());
      const auto desc = reader.slice(desc_at, descsz.value());
      if (name && desc &&
          trim_nul(std::string_view(reinterpret_cast<const char*>(name.value().data()),
                                    name.value().size())) == "CORE") {
        handle_core_note(type.value(), desc.value());
      }
      at = next;
    }
  }

 private:
  void handle_core_note(std::uint32_t type, std::span<const std::byte> desc) {
    const ByteReader reader(desc);
    if (type == kNtPrstatus) {
      read_thread(reader, desc.size());
    } else if (type == kNtPrpsinfo) {
      const auto name = reader.slice(kPrpsinfoName, kPrpsinfoNameLength);
      if (name) {
        info_.process_name = trim_nul(std::string_view(
            reinterpret_cast<const char*>(name.value().data()), name.value().size()));
      }
    } else if (type == kNtFile) {
      read_mappings(reader, desc.size());
    }
  }

  void read_thread(const ByteReader& reader, std::uint64_t size) {
    if (info_.threads.size() >= options_.max_threads) {
      note(info_, Status::ResourceLimit, "core.thread_limit",
           "more threads than the limit; the rest are not read", 0);
      return;
    }
    if (size < kPrstatusSize) {
      note(info_, Status::Partial, "core.prstatus_size", "an NT_PRSTATUS note is too small", 0);
      return;
    }
    CoreThread thread;
    const auto signal = reader.u32(0, Endian::Little);
    const auto pid = reader.u32(kPrstatusPid, Endian::Little);
    thread.signal = signal ? static_cast<std::int32_t>(signal.value()) : 0;
    thread.pid = pid ? pid.value() : 0;
    if (image_.architecture != Architecture::X86_64) {
      // Other machines keep their layouts elsewhere; the thread is kept without names.
      note(info_, Status::Partial, "core.registers_unknown",
           "registers are decoded for x86-64 cores only", 0);
    } else {
      for (std::size_t i = 0; i < kX86_64RegisterCount; ++i) {
        const auto value = reader.u64(kPrstatusRegisters + 8 * i, Endian::Little);
        if (!value) {
          note(info_, Status::Partial, "core.registers", "a register is unreadable", 0);
          break;
        }
        thread.registers.emplace_back(kX86_64Registers[i], value.value());
      }
      if (thread.registers.size() == kX86_64RegisterCount) {
        thread.pc = thread.registers[kRipIndex].second;
        thread.sp = thread.registers[kRspIndex].second;
      }
    }
    info_.threads.push_back(std::move(thread));
  }

  void read_mappings(const ByteReader& reader, std::uint64_t size) {
    const auto count = reader.u64(0, Endian::Little);
    const auto page = reader.u64(8, Endian::Little);
    if (!count || !page) {
      note(info_, Status::Partial, "core.file_header", "NT_FILE has no count", 0);
      return;
    }
    const std::uint64_t entries_size = 16 + count.value() * kNtFileEntry;
    if (count.value() > options_.max_mappings || entries_size > size) {
      note(info_, Status::Partial, "core.file_count",
           "NT_FILE lists more mappings than its note holds, or than the limit", 0);
      return;
    }
    std::vector<CoreMapping> entries;
    entries.reserve(static_cast<std::size_t>(count.value()));
    for (std::uint64_t i = 0; i < count.value(); ++i) {
      const std::uint64_t at = 16 + i * kNtFileEntry;
      const auto start = reader.u64(at, Endian::Little);
      const auto end = reader.u64(at + 8, Endian::Little);
      const auto offset = reader.u64(at + 16, Endian::Little);
      if (!start || !end || !offset) {
        note(info_, Status::Partial, "core.file_entry", "an NT_FILE entry is unreadable", 0);
        return;
      }
      CoreMapping mapping;
      mapping.start = start.value();
      mapping.end = end.value();
      mapping.file_offset = offset.value() * page.value();
      entries.push_back(std::move(mapping));
    }
    // The file names follow the entries, one NUL-terminated string per entry, in order.
    std::uint64_t at = entries_size;
    for (CoreMapping& mapping : entries) {
      const auto text = reader.c_string(at, kMaxPathLength);
      if (!text) {
        note(info_, Status::Partial, "core.file_name", "an NT_FILE path is unreadable", at);
        break;
      }
      mapping.path = std::string(text.value());
      at += text.value().size() + 1;
      info_.mappings.push_back(std::move(mapping));
    }
  }

  std::span<const std::byte> data_;
  const BinaryImage& image_;
  CoreOptions options_;
  CoreInfo& info_;
};

}  // namespace

Result<CoreInfo> read_elf_core(const BinaryImage& image, std::span<const std::byte> data,
                               const CoreOptions& options) {
  if (image.format != BinaryFormat::Elf || image.format_detail.rfind("ET_CORE", 0) != 0) {
    return make_error<CoreInfo>(Status::InvalidInput, "core.not_a_core",
                                "the image is not an ELF core file");
  }
  if (!image.is_64_bit() || image.endian != Endian::Little) {
    return make_error<CoreInfo>(Status::Unsupported, "core.unsupported_class",
                                "ELF cores are read for 64-bit little-endian files only");
  }
  const ByteReader reader(data);
  const auto program_offset = reader.u64(32, Endian::Little);
  const auto entry_size = reader.u16(54, Endian::Little);
  const auto count = reader.u16(56, Endian::Little);
  if (!program_offset || !entry_size || !count) {
    return make_error<CoreInfo>(Status::InvalidInput, "core.header",
                                "the ELF header has no program header table");
  }
  if (entry_size.value() < kProgramHeaderMinimum) {
    return make_error<CoreInfo>(Status::InvalidInput, "core.program_header",
                                "the program header entries are too small");
  }

  CoreInfo info;
  NoteReader notes(data, image, options, info);
  for (std::uint64_t i = 0; i < count.value(); ++i) {
    const std::uint64_t at = program_offset.value() + i * entry_size.value();
    const auto type = reader.u32(at, Endian::Little);
    if (!type) {
      note(info, Status::Partial, "core.program_header", "a program header is unreadable", at);
      break;
    }
    if (type.value() != kPtNote) {
      continue;
    }
    const auto offset = reader.u64(at + 8, Endian::Little);
    const auto size = reader.u64(at + 32, Endian::Little);
    if (!offset || !size || offset.value() > data.size() ||
        size.value() > data.size() - offset.value()) {
      note(info, Status::Partial, "core.note_segment", "a PT_NOTE segment is outside the file", at);
      continue;
    }
    notes.read_segment(offset.value(), offset.value() + size.value());
  }
  return info;
}

}  // namespace donkey
