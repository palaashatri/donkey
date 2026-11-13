// MSVC C++ RTTI for x64 PE images (G10-T3): the complete object locators, type descriptors and
// class hierarchy descriptors that the MSVC ABI emits next to each vtable. The reader works on the
// file bytes: nothing is run, and every pointer is checked against the image before it is followed.
//
// Layout (x64, all RVAs are 32-bit offsets from the image base):
//   COL (complete object locator), 24 bytes: signature (1 on x64), offset of this vtable in the
//   complete object, constructor displacement, pTypeDescriptor, pClassDescriptor, pSelf (the COL's
//   own RVA). The vtable's slot -1 holds the COL's absolute address.
//   TypeDescriptor: vftable (8), spare (8), then the NUL-terminated decorated name (".?AVName@@").
//   ClassHierarchyDescriptor, 16 bytes: signature, attributes, numBaseClasses, pBaseClassArray.
//   BaseClassArray: numBaseClasses RVAs of BaseClassDescriptors. Entry 0 is the class itself.
//   BaseClassDescriptor, 24 bytes: pTypeDescriptor, numContainedBases, displacements (3),
//   attributes.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "donkey/binary/byte_reader.h"
#include "donkey/binary/rtti.h"

namespace donkey {
namespace {

constexpr std::uint64_t kColSize = 24;
constexpr std::uint64_t kTypeDescriptorName = 16;
// A class hierarchy descriptor is 16 bytes and a base class descriptor 24. Neither size is needed
// as a constant: every field is read through u32_at, which checks its own bounds.
constexpr std::uint64_t kPointerSize = 8;
constexpr std::uint32_t kColSignatureX64 = 1;
constexpr std::size_t kMaxNameLength = 512;
constexpr std::uint64_t kMaxBaseClasses = 256;

void note(RttiInfo& info, Status status, std::string code, std::string message,
          std::uint64_t address) {
  info.diagnostics.push_back(
      Diagnostic::make(status, std::move(code), std::move(message), address));
  info.partial = true;
}

/// The name a decorated type name stands for: ".?AVName@@" is Name, ".?AVName@ns@@" is ns::Name. A
/// name with anything but identifier characters (templates, operators, anonymous namespaces) is not
/// shown, because guessing its readable form could show a wrong name.
std::optional<std::string> class_name_from_descriptor(const std::string& decorated) {
  if (decorated.size() < 4 || decorated.compare(0, 2, ".?") != 0 ||
      (decorated[2] != 'A' ||
       (decorated[3] != 'V' && decorated[3] != 'U' && decorated[3] != 'T'))) {
    return std::nullopt;
  }
  std::vector<std::string> parts;
  std::string current;
  for (std::size_t i = 4; i < decorated.size(); ++i) {
    const char c = decorated[i];
    if (c == '@') {
      if (current.empty()) {
        break;  // the "@@" that ends the name
      }
      parts.push_back(current);
      current.clear();
      continue;
    }
    if (std::isalnum(static_cast<unsigned char>(c)) == 0 && c != '_') {
      return std::nullopt;
    }
    current.push_back(c);
  }
  if (parts.empty()) {
    return std::nullopt;
  }
  std::string name;
  for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
    if (!name.empty()) {
      name += "::";
    }
    name += *it;
  }
  return name;
}

struct ColRecord {
  std::uint64_t address = 0;          ///< the COL's virtual address
  std::uint32_t offset = 0;           ///< the vtable's offset in the complete object
  std::uint64_t type_descriptor = 0;  ///< the class's type descriptor (virtual address)
  std::uint64_t hierarchy = 0;        ///< the class hierarchy descriptor (virtual address)
};

}  // namespace

Result<RttiInfo> read_msvc_rtti(const BinaryImage& image, std::span<const std::byte> data,
                                const RttiOptions& options) {
  if (image.format != BinaryFormat::Pe || !image.is_64_bit() ||
      image.architecture != Architecture::X86_64) {
    return make_error<RttiInfo>(Status::Unsupported, "rtti.unsupported_image",
                                "MSVC RTTI is read from x64 PE images");
  }
  RttiInfo info;
  const ByteReader reader(data);
  const std::uint64_t base = image.image_base;
  const auto rva_to_va = [base](std::uint32_t rva) { return base + rva; };

  const auto u32_at = [&](std::uint64_t address) -> std::optional<std::uint32_t> {
    const auto offset = image.va_to_file_offset(address);
    if (!offset) {
      return std::nullopt;
    }
    const auto value = reader.u32(offset.value(), Endian::Little);
    return value ? std::optional<std::uint32_t>(value.value()) : std::nullopt;
  };
  const auto u64_at = [&](std::uint64_t address) -> std::optional<std::uint64_t> {
    const auto offset = image.va_to_file_offset(address);
    if (!offset) {
      return std::nullopt;
    }
    const auto value = reader.u64(offset.value(), Endian::Little);
    return value ? std::optional<std::uint64_t>(value.value()) : std::nullopt;
  };

  // 1. Every complete object locator in a read-only or data section. A candidate must carry the x64
  //    signature and name itself by its own RVA (pSelf), which a random dword almost never does.
  std::vector<ColRecord> cols;
  for (const Section& section : image.sections) {
    if (!section.readable || section.executable || !section.has_file_data || section.compressed) {
      continue;
    }
    const std::uint64_t end = section.file_size >= kColSize ? section.file_size - kColSize : 0;
    for (std::uint64_t at = 0; at <= end; at += 4) {
      const std::uint64_t address = section.address + at;
      const auto signature = u32_at(address);
      if (!signature || signature.value() != kColSignatureX64) {
        continue;
      }
      const auto self = u32_at(address + 20);
      if (!self || rva_to_va(self.value()) != address) {
        continue;
      }
      const auto type_rva = u32_at(address + 12);
      const auto hierarchy_rva = u32_at(address + 16);
      const auto offset = u32_at(address + 4);
      if (!type_rva || !hierarchy_rva || !offset) {
        continue;
      }
      ColRecord record;
      record.address = address;
      record.offset = offset.value();
      record.type_descriptor = rva_to_va(type_rva.value());
      record.hierarchy = rva_to_va(hierarchy_rva.value());
      cols.push_back(record);
      if (cols.size() > options.max_classes * 8) {
        note(info, Status::Partial, "rtti.class_limit",
             "more complete object locators than the reader keeps", address);
        break;
      }
    }
  }

  // 2. The vtables: every 8-byte place whose value is a locator's address is the slot -1 of a
  // vtable,
  //    which starts one pointer later.
  std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> vtables_of;  // COL -> vftable VAs
  {
    std::unordered_map<std::uint64_t, bool> is_col;
    for (const ColRecord& col : cols) {
      is_col[col.address] = true;
    }
    for (const Section& section : image.sections) {
      if (!section.readable || section.executable || !section.has_file_data || section.compressed) {
        continue;
      }
      for (std::uint64_t at = 0; at + kPointerSize <= section.file_size; at += kPointerSize) {
        const std::uint64_t place = section.address + at;
        const auto value = u64_at(place);
        if (value && is_col.count(value.value()) != 0) {
          vtables_of[value.value()].push_back(place + kPointerSize);
        }
      }
    }
  }

  // 3. Classes, keyed by their type descriptor. The base classes come from the hierarchy: its array
  //    lists the class itself first, then every base, each followed by the bases it contains. The
  //    direct bases are the entries that are not contained in an earlier one.
  std::map<std::uint64_t, RttiClass> classes;  // type descriptor -> class
  std::unordered_map<std::uint64_t, std::vector<const ColRecord*>> cols_of;
  for (const ColRecord& col : cols) {
    cols_of[col.type_descriptor].push_back(&col);
  }
  for (const auto& [type_descriptor, group] : cols_of) {
    if (classes.size() >= options.max_classes) {
      note(info, Status::Partial, "rtti.class_limit", "more classes than the reader keeps",
           type_descriptor);
      break;
    }
    const auto name_text = [&]() -> std::optional<std::string> {
      const auto offset = image.va_to_file_offset(type_descriptor + kTypeDescriptorName);
      if (!offset) {
        return std::nullopt;
      }
      const auto text = reader.c_string(offset.value(), kMaxNameLength);
      return text ? std::optional<std::string>(std::string(text.value())) : std::nullopt;
    }();
    if (!name_text) {
      note(info, Status::Partial, "rtti.typeinfo_unreadable",
           "a type descriptor's name is unreadable or too long", type_descriptor);
      continue;
    }
    const auto name = class_name_from_descriptor(*name_text);
    if (!name) {
      note(info, Status::Partial, "rtti.msvc_name",
           "the class name '" + *name_text + "' is not an identifier this reader shows",
           type_descriptor);
      continue;
    }
    // The class's hierarchy: any of its locators names it (they all share the descriptor).
    const std::uint64_t hierarchy = group.front()->hierarchy;
    const auto attributes = hierarchy != 0 ? u32_at(hierarchy + 4) : std::nullopt;
    const auto count = u32_at(hierarchy + 8);
    const auto array_rva = u32_at(hierarchy + 12);
    if (!attributes || !count || !array_rva || count.value() == 0 ||
        count.value() > kMaxBaseClasses) {
      note(info, Status::Partial, "rtti.base_unresolved",
           "the class hierarchy descriptor of " + name.value() + " is unreadable", hierarchy);
      continue;
    }
    struct Entry {
      std::uint64_t type = 0;
      std::uint32_t contained = 0;
    };
    std::vector<Entry> entries;
    bool readable = true;
    for (std::uint32_t i = 0; i < count.value() && readable; ++i) {
      const auto bcd_rva = u32_at(rva_to_va(array_rva.value()) + 4ULL * i);
      if (!bcd_rva) {
        readable = false;
        break;
      }
      const std::uint64_t bcd = rva_to_va(bcd_rva.value());
      const auto type_rva = u32_at(bcd);
      const auto contained = u32_at(bcd + 4);
      if (!type_rva || !contained) {
        readable = false;
        break;
      }
      entries.push_back(Entry{rva_to_va(type_rva.value()), contained.value()});
    }
    if (!readable || entries.empty() || entries.front().type != type_descriptor) {
      note(info, Status::Partial, "rtti.base_unresolved",
           "the base class array of " + name.value() +
               " is unreadable or does not start with the class",
           hierarchy);
      continue;
    }
    RttiClass cls;
    cls.name = name.value();
    cls.typeinfo_address = type_descriptor;
    for (std::size_t j = 1; j < entries.size();) {
      cls.bases.push_back(entries[j].type);
      j += 1 + entries[j].contained;
    }
    cls.kind = cls.bases.empty() ? RttiKind::Class
                                 : (cls.bases.size() == 1 ? RttiKind::Single : RttiKind::Multiple);

    // Vtable groups: one per locator, the primary (offset 0) first, slots read while they point at
    // code.
    std::vector<const ColRecord*> ordered = group;
    std::sort(ordered.begin(), ordered.end(),
              [](const ColRecord* a, const ColRecord* b) { return a->offset < b->offset; });
    for (const ColRecord* col : ordered) {
      const auto vftables = vtables_of.find(col->address);
      if (vftables == vtables_of.end() || vftables->second.empty()) {
        note(info, Status::Partial, "rtti.vtable_unreadable",
             "no vtable refers to a complete object locator of " + cls.name, col->address);
        continue;
      }
      const std::uint64_t vftable = vftables->second.front();
      if (cls.vtable_address == 0 && col->offset == 0) {
        cls.vtable_address = vftable;
      }
      RttiVtableGroup vtable_group;
      vtable_group.offset_to_top = -static_cast<std::int64_t>(col->offset);
      for (std::uint64_t slot = 0; slot < options.max_slots; ++slot) {
        const auto value = u64_at(vftable + slot * kPointerSize);
        if (!value || value.value() == 0) {
          break;
        }
        const Section* target = image.section_for_va(value.value());
        if (target == nullptr || !target->executable) {
          break;  // the table ends where the next data begins
        }
        RttiSlot out;
        out.address = value.value();
        vtable_group.slots.push_back(out);
      }
      cls.groups.push_back(std::move(vtable_group));
    }
    classes.emplace(type_descriptor, std::move(cls));
  }

  for (auto& [address, cls] : classes) {
    info.classes.push_back(std::move(cls));
  }
  std::sort(info.classes.begin(), info.classes.end(), [](const RttiClass& a, const RttiClass& b) {
    return a.typeinfo_address < b.typeinfo_address;
  });
  return info;
}

Result<RttiInfo> read_rtti(const BinaryImage& image, std::span<const std::byte> data,
                           const RttiOptions& options) {
  if (image.format == BinaryFormat::Elf) {
    return read_itanium_rtti(image, data, options);
  }
  if (image.format == BinaryFormat::Pe) {
    return read_msvc_rtti(image, data, options);
  }
  return make_error<RttiInfo>(
      Status::Unsupported, "rtti.unsupported_image",
      "C++ RTTI is read from ELF images (Itanium) and x64 PE images (MSVC)");
}

}  // namespace donkey
