#include "donkey/binary/rtti.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/demangle.h"
#include "donkey/binary/plt.h"
#include "elf_dynamic.h"

namespace donkey {
namespace {

// ELF relocation types for pointers in data (x86-64 and AArch64).
constexpr std::uint64_t kRelativeX86_64 = 8;      // R_X86_64_RELATIVE
constexpr std::uint64_t kAbs64X86_64 = 1;         // R_X86_64_64
constexpr std::uint64_t kRelativeAArch64 = 1027;  // R_AARCH64_RELATIVE
constexpr std::uint64_t kAbs64AArch64 = 257;      // R_AARCH64_ABS64

using binary::detail::kMaxRelocationEntries;
using binary::detail::kRelaEntrySize;
constexpr std::uint64_t kPointerSize = 8;
constexpr std::uint64_t kVtableHeaderSize = 16;        // offset-to-top and typeinfo
constexpr std::uint64_t kTypeinfoClassSize = 16;       // vptr, name
constexpr std::uint64_t kTypeinfoSingleSize = 24;      // ... plus one base
constexpr std::uint64_t kTypeinfoMultipleHeader = 24;  // ... flags, count, then bases
constexpr std::uint64_t kTypeinfoBaseEntrySize = 16;   // base typeinfo, offset and flags
constexpr std::string_view kPureVirtual = "__cxa_pure_virtual";

/// What a pointer-sized place in the image holds, after relocations are applied.
struct Resolved {
  enum class Kind : std::uint8_t { Value, Symbol, Unreadable };
  Kind kind = Kind::Unreadable;
  std::uint64_t value = 0;
  std::string symbol;  ///< for Kind::Symbol: the symbol the relocation names
};

struct Memory {
  const BinaryImage& image;
  std::span<const std::byte> data;
  std::map<std::uint64_t, std::uint64_t> relative;  ///< place -> addend
  std::map<std::uint64_t, std::string> symbolic;    ///< place -> symbol name

  std::optional<std::uint64_t> file_u64(std::uint64_t address) const {
    const auto offset = image.va_to_file_offset(address);
    if (!offset) {
      return std::nullopt;
    }
    const auto value = ByteReader(data).u64(offset.value(), Endian::Little);
    if (!value) {
      return std::nullopt;
    }
    return value.value();
  }

  Resolved resolve(std::uint64_t address) const {
    Resolved out;
    if (const auto it = symbolic.find(address); it != symbolic.end()) {
      out.kind = Resolved::Kind::Symbol;
      out.symbol = it->second;
      return out;
    }
    if (const auto it = relative.find(address); it != relative.end()) {
      out.kind = Resolved::Kind::Value;
      out.value = it->second;
      return out;
    }
    if (const auto value = file_u64(address)) {
      out.kind = Resolved::Kind::Value;
      out.value = *value;
    }
    return out;
  }

  /// The NUL-terminated string at `address`, bounded by `max`.
  std::optional<std::string> c_string(std::uint64_t address, std::uint64_t max) const {
    const auto offset = image.va_to_file_offset(address);
    if (!offset) {
      return std::nullopt;
    }
    const auto text = ByteReader(data).c_string(offset.value(), max);
    if (!text) {
      return std::nullopt;
    }
    return std::string(text.value());
  }
};

void note(RttiInfo& info, Status status, std::string code, std::string message,
          std::uint64_t address) {
  info.diagnostics.push_back(
      Diagnostic::make(status, std::move(code), std::move(message), address));
  info.partial = true;
}

Memory load_memory(const BinaryImage& image, std::span<const std::byte> data, RttiInfo& info) {
  Memory memory{image, data, {}, {}};
  const bool aarch64 = image.architecture == Architecture::AArch64;
  const std::uint64_t relative = aarch64 ? kRelativeAArch64 : kRelativeX86_64;
  const std::uint64_t absolute = aarch64 ? kAbs64AArch64 : kAbs64X86_64;
  std::optional<std::uint64_t> unreadable_symbol;
  const std::vector<std::string> names =
      binary::detail::dynamic_symbol_names(image, data, &unreadable_symbol);
  if (unreadable_symbol) {
    note(info, Status::Partial, "rtti.dynsym", "a dynamic symbol entry is unreadable",
         *unreadable_symbol);
  }
  const ByteReader reader(data);
  for (const Section& section : image.sections) {
    if (section.name != ".rela.dyn" || !section.has_file_data) {
      continue;
    }
    const std::uint64_t count = section.file_size / kRelaEntrySize;
    for (std::uint64_t i = 0; i < count; ++i) {
      if (i == kMaxRelocationEntries) {
        note(info, Status::Partial, "rtti.relocations_truncated",
             "the relocation table is longer than the reader keeps", section.file_offset);
        break;
      }
      const std::uint64_t entry = section.file_offset + i * kRelaEntrySize;
      const auto place = reader.u64(entry, Endian::Little);
      const auto info_word = reader.u64(entry + 8, Endian::Little);
      const auto addend = reader.u64(entry + 16, Endian::Little);
      if (!place || !info_word || !addend) {
        note(info, Status::Partial, "rtti.relocations", "a relocation entry is unreadable", entry);
        break;
      }
      const std::uint64_t type = info_word.value() & 0xffffffffU;
      const std::uint64_t symbol = info_word.value() >> 32;
      if (type == relative) {
        memory.relative[place.value()] = addend.value();
      } else if (type == absolute) {
        memory.symbolic[place.value()] = symbol < names.size() ? names[symbol] : std::string();
      }
    }
  }
  return memory;
}

/// A demangled name, or the raw name when the demangler does not read it.
std::string display_name(const std::string& raw) {
  if (is_itanium_name(raw)) {
    const auto demangled = demangle_itanium(raw);
    if (demangled) {
      return demangled.value();
    }
  }
  return raw;
}

bool class_typeinfo_name(const std::string& name) {
  // `_ZTI` then a class: a digit (a source name) or `N` (a nested name). Pointer and builtin
  // typeinfo objects start with other letters and are not classes.
  if (name.size() < 6 || name.compare(0, 4, "_ZTI") != 0) {
    return false;
  }
  const char first = name[4];
  return (first >= '0' && first <= '9') || first == 'N';
}

class Reader {
 public:
  Reader(const BinaryImage& image, std::span<const std::byte> data, const RttiOptions& options,
         RttiInfo& info)
      : image_(image),
        options_(options),
        info_(info),
        memory_(load_memory(image, data, info)),
        stubs_(plt_stub_imports(image, data)) {
    for (const Symbol& symbol : image.symbols) {
      if (symbol.name.empty() || symbol.kind == SymbolKind::Import || symbol.imported) {
        continue;
      }
      by_address_.emplace(symbol.address, &symbol);
      if (symbol.name.compare(0, 4, "_ZTV") == 0) {
        vtables_.emplace(symbol.name.substr(4), &symbol);
      }
    }
  }

  void run() {
    for (const Symbol& symbol : image_.symbols) {
      if (!class_typeinfo_name(symbol.name) || symbol.imported) {
        continue;
      }
      if (info_.classes.size() >= options_.max_classes) {
        note(info_, Status::ResourceLimit, "rtti.class_limit",
             "more classes than the limit; the rest are not read", 0);
        break;
      }
      read_class(symbol);
    }
    std::sort(info_.classes.begin(), info_.classes.end(),
              [](const RttiClass& a, const RttiClass& b) {
                return a.typeinfo_address < b.typeinfo_address;
              });
  }

 private:
  void read_class(const Symbol& typeinfo) {
    RttiClass cls;
    cls.typeinfo_symbol = typeinfo.name;
    cls.typeinfo_address = typeinfo.address;
    const std::string demangled = display_name(typeinfo.name);
    constexpr std::string_view kPrefix = "typeinfo for ";
    cls.name = demangled.compare(0, kPrefix.size(), kPrefix) == 0 ? demangled.substr(kPrefix.size())
                                                                  : demangled;
    if (typeinfo.size < kTypeinfoClassSize) {
      note(info_, Status::Partial, "rtti.typeinfo_size",
           "a typeinfo object is smaller than the ABI's header", typeinfo.address);
      return;
    }
    if (!read_bases(typeinfo, cls)) {
      return;
    }
    if (const auto vtable = vtables_.find(typeinfo.name.substr(4)); vtable != vtables_.end()) {
      cls.vtable_address = vtable->second->address;
      read_vtable(*vtable->second, cls);
    }
    info_.classes.push_back(std::move(cls));
  }

  bool read_bases(const Symbol& typeinfo, RttiClass& cls) {
    const std::uint64_t base_address = typeinfo.address;
    if (typeinfo.size == kTypeinfoClassSize) {
      cls.kind = RttiKind::Class;
      return true;
    }
    if (typeinfo.size == kTypeinfoSingleSize) {
      cls.kind = RttiKind::Single;
      return read_base_pointer(base_address + 16, cls);
    }
    cls.kind = RttiKind::Multiple;
    if (typeinfo.size < kTypeinfoMultipleHeader) {
      note(info_, Status::Partial, "rtti.typeinfo_size",
           "a multiple-inheritance typeinfo object has no base count", typeinfo.address);
      return false;
    }
    const auto count = read_u32(base_address + 20);
    if (!count) {
      note(info_, Status::Partial, "rtti.typeinfo_unreadable",
           "the base count of a typeinfo object is unreadable", typeinfo.address);
      return false;
    }
    if (typeinfo.size < kTypeinfoMultipleHeader + count.value() * kTypeinfoBaseEntrySize) {
      note(info_, Status::Partial, "rtti.typeinfo_size",
           "a typeinfo object is shorter than its base count", typeinfo.address);
      return false;
    }
    for (std::uint32_t i = 0; i < count.value(); ++i) {
      if (!read_base_pointer(base_address + kTypeinfoMultipleHeader + i * kTypeinfoBaseEntrySize,
                             cls)) {
        return false;
      }
    }
    return true;
  }

  bool read_base_pointer(std::uint64_t place, RttiClass& cls) {
    const Resolved base = memory_.resolve(place);
    if (base.kind != Resolved::Kind::Value || base.value == 0) {
      note(info_, Status::Partial, "rtti.base_unresolved",
           "a base class of a typeinfo object is not a local address", place);
      return false;
    }
    cls.bases.push_back(base.value);
    return true;
  }

  std::optional<std::uint32_t> read_u32(std::uint64_t address) const {
    const auto offset = image_.va_to_file_offset(address);
    if (!offset) {
      return std::nullopt;
    }
    const auto value = ByteReader(memory_.data).u32(offset.value(), Endian::Little);
    if (!value) {
      return std::nullopt;
    }
    return value.value();
  }

  /// The primary vtable, then one group per base subobject. A group starts with its
  /// offset-to-top followed by the typeinfo address of this class.
  void read_vtable(const Symbol& vtable, RttiClass& cls) {
    if (vtable.size < kVtableHeaderSize || vtable.size % kPointerSize != 0) {
      note(info_, Status::Partial, "rtti.vtable_size",
           "a vtable's size is not a whole number of pointers", vtable.address);
      return;
    }
    const std::uint64_t count = vtable.size / kPointerSize;
    if (count > options_.max_slots) {
      note(info_, Status::ResourceLimit, "rtti.slot_limit",
           "a vtable has more entries than the limit; it is not read", vtable.address);
      return;
    }
    std::vector<Resolved> words;
    words.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
      const Resolved word = memory_.resolve(vtable.address + i * kPointerSize);
      if (word.kind == Resolved::Kind::Unreadable) {
        note(info_, Status::Partial, "rtti.vtable_unreadable", "a vtable entry is unreadable",
             vtable.address + i * kPointerSize);
        return;
      }
      words.push_back(word);
    }
    if (words[1].kind != Resolved::Kind::Value || words[1].value != cls.typeinfo_address) {
      note(info_, Status::Partial, "rtti.vtable_typeinfo",
           "a vtable does not point at its class's typeinfo", vtable.address);
    }
    RttiVtableGroup group;
    group.offset_to_top = static_cast<std::int64_t>(words[0].value);
    std::size_t i = 2;
    while (i < words.size()) {
      const bool next_group = i + 1 < words.size() && words[i + 1].kind == Resolved::Kind::Value &&
                              words[i + 1].value == cls.typeinfo_address;
      if (next_group) {
        cls.groups.push_back(std::move(group));
        group = RttiVtableGroup{};
        group.offset_to_top = static_cast<std::int64_t>(words[i].value);
        i += 2;
        continue;
      }
      group.slots.push_back(describe_slot(words[i]));
      ++i;
    }
    cls.groups.push_back(std::move(group));
  }

  RttiSlot describe_slot(const Resolved& word) const {
    RttiSlot slot;
    if (word.kind == Resolved::Kind::Symbol) {
      slot.name = display_name(word.symbol);
      slot.pure_virtual = word.symbol == kPureVirtual;
      return slot;
    }
    slot.address = word.value;
    if (word.value == 0) {
      return slot;
    }
    if (const auto stub = stubs_.find(word.value); stub != stubs_.end()) {
      slot.name = display_name(stub->second);
      slot.pure_virtual = stub->second == kPureVirtual;
      return slot;
    }
    if (const auto it = by_address_.find(word.value); it != by_address_.end()) {
      slot.name = display_name(it->second->name);
    }
    if (slot.name.empty() && in_plt(word.value)) {
      // A stub the reader does not decode (AArch64 PLT entries): the slot is a call to an
      // import, which is not named, so `pure_virtual` cannot be decided either.
      note(info_, Status::Partial, "rtti.plt_unnamed",
           "a vtable entry calls a PLT stub that is not named", word.value);
    }
    return slot;
  }

  bool in_plt(std::uint64_t address) const {
    for (const Section& section : image_.sections) {
      if ((section.name == ".plt" || section.name == ".plt.sec" || section.name == ".plt.got") &&
          address >= section.address && address < section.address + section.file_size) {
        return true;
      }
    }
    return false;
  }

  const BinaryImage& image_;
  RttiOptions options_;
  RttiInfo& info_;
  Memory memory_;
  std::map<std::uint64_t, std::string> stubs_;
  std::map<std::uint64_t, const Symbol*> by_address_;
  std::map<std::string, const Symbol*> vtables_;  // keyed by the name after `_ZTV`
};

}  // namespace

const char* rtti_kind_name(RttiKind kind) noexcept {
  switch (kind) {
    case RttiKind::Class:
      return "class";
    case RttiKind::Single:
      return "single";
    case RttiKind::Multiple:
      return "multiple";
  }
  return "unknown";
}

Result<RttiInfo> read_itanium_rtti(const BinaryImage& image, std::span<const std::byte> data,
                                   const RttiOptions& options) {
  if (image.format != BinaryFormat::Elf || !image.is_64_bit() || image.endian != Endian::Little ||
      (image.architecture != Architecture::X86_64 && image.architecture != Architecture::AArch64)) {
    return make_error<RttiInfo>(Status::Unsupported, "rtti.unsupported_image",
                                "Itanium RTTI is read from 64-bit little-endian ELF images of "
                                "x86-64 and AArch64");
  }
  RttiInfo info;
  Reader reader(image, data, options, info);
  reader.run();
  return info;
}

const RttiClass* find_rtti_class(const RttiInfo& info, std::uint64_t typeinfo_address) noexcept {
  const auto it = std::lower_bound(
      info.classes.begin(), info.classes.end(), typeinfo_address,
      [](const RttiClass& cls, std::uint64_t address) { return cls.typeinfo_address < address; });
  if (it == info.classes.end() || it->typeinfo_address != typeinfo_address) {
    return nullptr;
  }
  return &*it;
}

}  // namespace donkey
