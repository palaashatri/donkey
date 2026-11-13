#include "donkey/analysis/signature_gen.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/binary/archive.h"
#include "donkey/binary/byte_reader.h"
#include "donkey/binary/image.h"

namespace donkey {
namespace {

constexpr std::uint64_t kSectionHeaderSize = 64;  // Elf64_Shdr
constexpr std::uint64_t kSymbolSize = 24;         // Elf64_Sym
constexpr std::uint64_t kRelaSize = 24;           // Elf64_Rela
constexpr std::uint64_t kMaxSymbols = 1'000'000;
constexpr std::uint64_t kMaxRelocations = 1'000'000;
constexpr std::uint64_t kMaxFunctionBytes = std::uint64_t{16} << 20;  // the signature length limit
constexpr std::uint64_t kMaxNameBytes = 4096;                         // the signature name limit
constexpr std::size_t kMaxSetSignatures = 1'000'000;
constexpr std::size_t kMaxFieldBytes = 256;

constexpr std::uint16_t kTypeRelocatable = 1;  // ET_REL
constexpr std::uint16_t kMachineX86_64 = 62;   // EM_X86_64
constexpr std::uint32_t kShtSymtab = 2;
constexpr std::uint32_t kShtRela = 4;
constexpr std::uint32_t kShtNobits = 8;
constexpr std::uint64_t kShfExecinstr = 0x4;
constexpr std::uint64_t kShfCompressed = 0x800;
constexpr std::uint8_t kSttFunc = 2;
constexpr std::uint8_t kStbLocal = 0;
constexpr std::uint8_t kStbGlobal = 1;
constexpr std::uint8_t kStbWeak = 2;
constexpr std::uint16_t kShnLoreserve = 0xff00;
constexpr std::uint32_t kRelocNone = 0;

struct Section {
  std::uint32_t type = 0;
  std::uint64_t flags = 0;
  std::uint64_t offset = 0;
  std::uint64_t size = 0;
  std::uint32_t link = 0;
  std::uint32_t info = 0;
};

/// One relocation of a section: the offset it patches, and how many bytes it patches. A width of
/// zero marks a relocation type the generator does not know.
struct Relocation {
  std::uint64_t offset = 0;
  std::uint64_t width = 0;
};

/// The bytes an x86-64 relocation type patches, or zero when the type is not one the generator
/// knows. Every known type patches a field of fixed width at the offset.
std::uint64_t x86_64_width(std::uint32_t type) {
  switch (type) {
    case 1:   // R_X86_64_64
    case 24:  // R_X86_64_PC64
    case 25:  // R_X86_64_GOTOFF64
      return 8;
    case 2:   // R_X86_64_PC32
    case 3:   // R_X86_64_GOT32
    case 4:   // R_X86_64_PLT32
    case 9:   // R_X86_64_GOTPCREL
    case 10:  // R_X86_64_32
    case 11:  // R_X86_64_32S
    case 26:  // R_X86_64_GOTPC32
    case 41:  // R_X86_64_GOTPCRELX
    case 42:  // R_X86_64_REX_GOTPCRELX
      return 4;
    case 12:  // R_X86_64_16
    case 13:  // R_X86_64_PC16
      return 2;
    case 14:  // R_X86_64_8
    case 15:  // R_X86_64_PC8
      return 1;
    default:
      return 0;
  }
}

void add_note(SignatureGenResult& result, std::string note) {
  if (result.notes.size() < kMaxSignatureNotes) {
    result.notes.push_back(std::move(note));
  }
}

/// Adds the results of one object or member to the whole result. Counters add up, notes are kept up
/// to the cap, and signatures are kept up to the set limit.
void merge(SignatureGenResult& result, SignatureGenResult&& scan) {
  result.functions += scan.functions;
  result.skipped += scan.skipped;
  result.partial = result.partial || scan.partial;
  for (std::string& note : scan.notes) {
    add_note(result, std::move(note));
  }
  for (Signature& signature : scan.set.signatures) {
    if (result.set.signatures.size() >= kMaxSetSignatures) {
      result.partial = true;
      break;
    }
    result.set.signatures.push_back(std::move(signature));
  }
}

/// The wildcards of one function: the relocations that patch bytes inside it, sorted and with any
/// overlap merged. Empty when a relocation has an unknown width or runs past the function's end;
/// the caller then skips the function and says why in `reason`.
std::vector<SignatureWildcard> function_wildcards(const std::vector<Relocation>& relocations,
                                                  std::uint64_t value, std::uint64_t size,
                                                  std::string& reason) {
  std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
  for (const Relocation& relocation : relocations) {
    if (relocation.offset < value || relocation.offset >= value + size) {
      continue;
    }
    if (relocation.width == 0) {
      reason = "a relocation of a type the generator does not know";
      return {};
    }
    if (relocation.offset - value + relocation.width > size) {
      reason = "a relocation runs past the end of the function";
      return {};
    }
    spans.emplace_back(relocation.offset - value, relocation.width);
  }
  std::sort(spans.begin(), spans.end());
  std::vector<SignatureWildcard> wildcards;
  for (const auto& [offset, length] : spans) {
    if (!wildcards.empty() &&
        offset < static_cast<std::uint64_t>(wildcards.back().offset) + wildcards.back().length) {
      const std::uint64_t end =
          std::max(static_cast<std::uint64_t>(wildcards.back().offset) + wildcards.back().length,
                   offset + length);
      wildcards.back().length = static_cast<std::uint32_t>(end - wildcards.back().offset);
      continue;
    }
    wildcards.push_back(
        SignatureWildcard{static_cast<std::uint32_t>(offset), static_cast<std::uint32_t>(length)});
  }
  return wildcards;
}

/// The signatures of one ELF relocatable object, read from `bytes` as the file holds them. The
/// object is not laid out or relocated: the bytes are the ones the compiler wrote, and the
/// relocations say which of them a link changes. Returns an error, with nothing added to `scan`'s
/// signatures, when a header or table is malformed; a single function that cannot be described
/// exactly is skipped with a note instead.
Result<bool> object_signatures(std::span<const std::byte> bytes, SignatureGenResult& scan) {
  const ByteReader reader(bytes);
  const auto magic = reader.u32(0, Endian::Little);
  if (!magic || magic.value() != 0x464c457fU) {
    return make_error<bool>(Status::InvalidInput, "sig.input", "not an ELF file");
  }
  const auto klass = reader.u8(4);
  const auto encoding = reader.u8(5);
  if (!klass || !encoding || klass.value() != 2 || encoding.value() != 1) {
    return make_error<bool>(Status::InvalidInput, "sig.machine",
                            "not a 64-bit little-endian ELF file");
  }
  const auto type = reader.u16(16, Endian::Little);
  const auto machine = reader.u16(18, Endian::Little);
  if (!type || !machine) {
    return make_error<bool>(Status::InvalidInput, "sig.truncated", "the ELF header is cut short");
  }
  if (type.value() != kTypeRelocatable) {
    return make_error<bool>(Status::InvalidInput, "sig.not_relocatable",
                            "an ELF file that is not a relocatable object");
  }
  if (machine.value() != kMachineX86_64) {
    return make_error<bool>(Status::Unsupported, "sig.machine",
                            "the object is not for x86-64, the only architecture generated");
  }
  const auto shoff = reader.u64(40, Endian::Little);
  const auto shentsize = reader.u16(58, Endian::Little);
  const auto shnum = reader.u16(60, Endian::Little);
  if (!shoff || !shentsize || !shnum) {
    return make_error<bool>(Status::InvalidInput, "sig.truncated", "the ELF header is cut short");
  }
  if (shnum.value() == 0) {
    return true;  // no sections, so no functions
  }
  if (shentsize.value() != kSectionHeaderSize) {
    return make_error<bool>(Status::InvalidInput, "sig.truncated",
                            "the section header size is not 64 bytes");
  }
  // A section count is 16 bits, so it is at most 65535; the table must also fit in the file.
  const std::uint64_t table_size = std::uint64_t{shnum.value()} * kSectionHeaderSize;
  if (shoff.value() > bytes.size() || table_size > bytes.size() - shoff.value()) {
    return make_error<bool>(Status::InvalidInput, "sig.truncated",
                            "the section table lies outside the file");
  }
  std::vector<Section> sections;
  sections.reserve(shnum.value());
  for (std::uint64_t i = 0; i < shnum.value(); ++i) {
    const std::uint64_t base = shoff.value() + i * kSectionHeaderSize;
    const auto sh_type = reader.u32(base + 4, Endian::Little);
    const auto sh_flags = reader.u64(base + 8, Endian::Little);
    const auto sh_offset = reader.u64(base + 24, Endian::Little);
    const auto sh_size = reader.u64(base + 32, Endian::Little);
    const auto sh_link = reader.u32(base + 40, Endian::Little);
    const auto sh_info = reader.u32(base + 44, Endian::Little);
    if (!sh_type || !sh_flags || !sh_offset || !sh_size || !sh_link || !sh_info) {
      return make_error<bool>(Status::InvalidInput, "sig.truncated",
                              "a section header lies outside the file");
    }
    sections.push_back(Section{sh_type.value(), sh_flags.value(), sh_offset.value(),
                               sh_size.value(), sh_link.value(), sh_info.value()});
  }

  std::size_t symtab_index = sections.size();
  for (std::size_t i = 0; i < sections.size(); ++i) {
    if (sections[i].type == kShtSymtab) {
      symtab_index = i;
      break;
    }
  }
  if (symtab_index == sections.size()) {
    return true;  // no symbol table, so no names
  }
  const Section symtab = sections[symtab_index];
  if (symtab.link >= sections.size()) {
    return make_error<bool>(Status::InvalidInput, "sig.truncated",
                            "the symbol table has no string table");
  }
  const Section strtab = sections[symtab.link];
  if (strtab.offset > bytes.size() || strtab.size > bytes.size() - strtab.offset) {
    return make_error<bool>(Status::InvalidInput, "sig.truncated",
                            "the string table lies outside the file");
  }
  if (symtab.offset > bytes.size() || symtab.size > bytes.size() - symtab.offset) {
    return make_error<bool>(Status::InvalidInput, "sig.truncated",
                            "the symbol table lies outside the file");
  }

  // Relocations, grouped by the section each one patches.
  std::map<std::size_t, std::vector<Relocation>> relocations;
  for (const Section& rela : sections) {
    if (rela.type != kShtRela) {
      continue;
    }
    if (rela.offset > bytes.size() || rela.size > bytes.size() - rela.offset) {
      return make_error<bool>(Status::InvalidInput, "sig.truncated",
                              "a relocation table lies outside the file");
    }
    if (rela.info >= sections.size()) {
      continue;  // a table for a section the file does not have
    }
    const std::uint64_t count = rela.size / kRelaSize;
    if (count > kMaxRelocations) {
      scan.partial = true;
      add_note(scan, "a relocation table is over the limit and was only read in part");
    }
    std::vector<Relocation>& patches = relocations[rela.info];
    for (std::uint64_t i = 0; i < count && i < kMaxRelocations; ++i) {
      const std::uint64_t entry = rela.offset + i * kRelaSize;
      const auto r_offset = reader.u64(entry, Endian::Little);
      const auto r_info = reader.u64(entry + 8, Endian::Little);
      if (!r_offset || !r_info) {
        return make_error<bool>(Status::InvalidInput, "sig.truncated",
                                "a relocation lies outside the file");
      }
      const auto reloc_type = static_cast<std::uint32_t>(r_info.value() & 0xffffffffU);
      if (reloc_type == kRelocNone) {
        continue;
      }
      patches.push_back(Relocation{r_offset.value(), x86_64_width(reloc_type)});
    }
  }

  // The functions, each with its bytes and wildcards: global, weak and local (static) ones.
  const std::uint64_t symbol_count = std::min(symtab.size / kSymbolSize, kMaxSymbols);
  if (symtab.size / kSymbolSize > kMaxSymbols) {
    scan.partial = true;
    add_note(scan, "the symbol table is over the limit and was only read in part");
  }
  std::vector<Signature> found;
  for (std::uint64_t i = 1; i < symbol_count; ++i) {  // entry 0 is the null symbol
    const std::uint64_t entry = symtab.offset + i * kSymbolSize;
    const auto name_offset = reader.u32(entry, Endian::Little);
    const auto info = reader.u8(entry + 4);
    const auto shndx = reader.u16(entry + 6, Endian::Little);
    const auto value = reader.u64(entry + 8, Endian::Little);
    const auto size = reader.u64(entry + 16, Endian::Little);
    if (!name_offset || !info || !shndx || !value || !size) {
      return make_error<bool>(Status::InvalidInput, "sig.truncated",
                              "a symbol lies outside the file");
    }
    const std::uint8_t kind = info.value() & 0xfU;
    const std::uint8_t binding = info.value() >> 4U;
    if (kind != kSttFunc ||
        (binding != kStbLocal && binding != kStbGlobal && binding != kStbWeak)) {
      continue;
    }
    if (shndx.value() == 0 || shndx.value() >= kShnLoreserve || size.value() == 0) {
      continue;
    }
    ++scan.functions;
    std::string name;
    std::string reason;
    if (name_offset.value() >= strtab.size) {
      reason = "its name is outside the string table";
    } else {
      const std::uint64_t room = std::min(kMaxNameBytes, strtab.size - name_offset.value());
      const auto text = reader.c_string(strtab.offset + name_offset.value(), room);
      if (!text) {
        reason = "its name is longer than the signature limit";
      } else {
        name = std::string(text.value());
      }
    }
    if (reason.empty() && name.empty()) {
      reason = "its name is empty";
    }
    if (reason.empty()) {
      if (shndx.value() >= sections.size()) {
        reason = "its section is outside the file";
      } else {
        const Section& code = sections[shndx.value()];
        if ((code.flags & kShfExecinstr) == 0) {
          reason = "it is not in an executable section";
        } else if (code.type == kShtNobits) {
          reason = "its section has no bytes in the file";
        } else if ((code.flags & kShfCompressed) != 0) {
          reason = "its section is compressed";
        } else if (size.value() > kMaxFunctionBytes) {
          reason = "it is larger than the signature limit";
        } else if (value.value() > code.size || size.value() > code.size - value.value()) {
          reason = "it lies outside its section";
        } else if (code.offset > bytes.size() || value.value() > bytes.size() - code.offset ||
                   size.value() > bytes.size() - (code.offset + value.value())) {
          reason = "its bytes lie outside the file";
        }
      }
    }
    std::vector<SignatureWildcard> wildcards;
    if (reason.empty()) {
      const auto found_relocations = relocations.find(shndx.value());
      if (found_relocations != relocations.end()) {
        wildcards =
            function_wildcards(found_relocations->second, value.value(), size.value(), reason);
      }
    }
    if (reason.empty()) {
      const std::span<const std::byte> function =
          bytes.subspan(static_cast<std::size_t>(sections[shndx.value()].offset + value.value()),
                        static_cast<std::size_t>(size.value()));
      auto signature = make_signature(function, name, wildcards);
      if (!signature) {
        reason = signature.diagnostic().message;
      } else {
        found.push_back(std::move(signature.value()));
        continue;
      }
    }
    ++scan.skipped;
    add_note(scan, name + ": " + reason);
  }
  scan.set.signatures = std::move(found);
  return true;
}

}  // namespace

Result<SignatureGenResult> generate_signatures(std::span<const std::byte> file,
                                               const SignatureGenOptions& options) {
  if (options.library.empty() || options.version.empty() || options.license.empty() ||
      options.library.size() > kMaxFieldBytes || options.version.size() > kMaxFieldBytes ||
      options.license.size() > kMaxFieldBytes) {
    return make_error<SignatureGenResult>(
        Status::InvalidInput, "sig.options",
        "the library, version and licence are required, and each is at most 256 bytes");
  }
  SignatureGenResult result;
  result.set.library = options.library;
  result.set.version = options.version;
  result.set.license = options.license;
  result.set.architecture = architecture_name(Architecture::X86_64);

  constexpr std::string_view kArchiveMagic = "!<arch>\n";
  const bool archive =
      file.size() >= kArchiveMagic.size() && std::equal(kArchiveMagic.begin(), kArchiveMagic.end(),
                                                        reinterpret_cast<const char*>(file.data()));
  if (!archive) {
    SignatureGenResult scan;
    scan.set.library = options.library;
    auto scanned = object_signatures(file, scan);
    if (!scanned) {
      return Result<SignatureGenResult>(scanned.diagnostic());
    }
    merge(result, std::move(scan));
    return result;
  }

  auto index = read_archive(file);
  if (!index) {
    return Result<SignatureGenResult>(index.diagnostic());
  }
  result.partial = index.value().partial;
  if (!index.value().note.empty()) {
    add_note(result, "archive: " + index.value().note);
  }
  for (const ArchiveMember& member : index.value().members) {
    if (member.kind != ArchiveMemberKind::Object) {
      continue;
    }
    if (member.offset > file.size() || member.size > file.size() - member.offset) {
      result.partial = true;
      ++result.skipped;
      add_note(result, member.name + ": its data lies outside the archive");
      continue;
    }
    SignatureGenResult scan;
    scan.set.library = options.library;
    auto scanned = object_signatures(file.subspan(static_cast<std::size_t>(member.offset),
                                                  static_cast<std::size_t>(member.size)),
                                     scan);
    if (!scanned) {
      ++result.skipped;
      add_note(result, member.name + ": " + scanned.diagnostic().message);
      continue;
    }
    merge(result, std::move(scan));
  }
  return result;
}

}  // namespace donkey
