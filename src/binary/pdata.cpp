#include "donkey/binary/pdata.h"

#include "donkey/binary/byte_reader.h"
#include "parsers.h"

namespace donkey {
namespace {

constexpr std::uint64_t kExceptionDirectory = 3;
constexpr std::uint64_t kRuntimeFunctionSize = 12;  // BeginAddress, EndAddress, UnwindInfo (RVAs)
constexpr std::uint8_t kUnwindChainInfo = 0x4;      // UNW_FLAG_CHAININFO, in the flags bits

}  // namespace

Result<PdataReadResult> read_pdata_of_image(const BinaryImage& image,
                                            std::span<const std::byte> file,
                                            std::size_t max_entries) {
  PdataReadResult result;
  if (image.format != BinaryFormat::Pe || image.architecture != Architecture::X86_64) {
    return result;
  }
  const ByteReader reader(file);
  auto lfanew = reader.u32(0x3c, Endian::Little);
  if (!lfanew) {
    return lfanew.diagnostic();
  }
  const std::uint64_t optional = std::uint64_t{lfanew.value()} + 4 + 20;  // after "PE\0\0" and COFF
  auto magic = reader.u16(optional, Endian::Little);
  if (!magic) {
    return magic.diagnostic();
  }
  if (magic.value() != 0x20b) {  // PE32+ only: the x64 exception directory has this layout
    return result;
  }
  auto directory_count = reader.u32(optional + 108, Endian::Little);
  if (!directory_count) {
    return directory_count.diagnostic();
  }
  if (directory_count.value() <= kExceptionDirectory) {
    return result;
  }
  const std::uint64_t entry = optional + 112 + kExceptionDirectory * 8;
  auto rva = reader.u32(entry, Endian::Little);
  auto size = reader.u32(entry + 4, Endian::Little);
  if (!rva || !size) {
    return rva ? size.diagnostic() : rva.diagnostic();
  }
  if (rva.value() == 0 || size.value() == 0) {
    return result;
  }
  auto offset = binary::detail::rva_to_file_offset(image, rva.value());
  if (!offset) {
    return offset.diagnostic();
  }
  result.entries = size.value() / kRuntimeFunctionSize;
  if (result.entries > max_entries) {
    result.entries = max_entries;
    result.truncated = true;
  }
  for (std::size_t i = 0; i < result.entries; ++i) {
    const std::uint64_t at = offset.value() + i * kRuntimeFunctionSize;
    auto begin = reader.u32(at, Endian::Little);
    auto end = reader.u32(at + 4, Endian::Little);
    auto unwind = reader.u32(at + 8, Endian::Little);
    if (!begin || !end || !unwind) {
      ++result.malformed;
      continue;
    }
    if (begin.value() == 0 || end.value() <= begin.value()) {
      ++result.malformed;
      continue;
    }
    // The first byte of UNWIND_INFO holds the version (low 3 bits) and the flags (high 5 bits).
    auto unwind_offset = binary::detail::rva_to_file_offset(image, unwind.value());
    auto flags = unwind_offset ? reader.u8(unwind_offset.value())
                               : Result<std::uint8_t>(unwind_offset.diagnostic());
    if (!flags) {
      ++result.malformed;
      continue;
    }
    if (((flags.value() >> 3U) & kUnwindChainInfo) != 0) {
      ++result.chained;
      continue;
    }
    result.functions.push_back(PdataFunction{
        image.image_base + begin.value(), static_cast<std::uint64_t>(end.value() - begin.value())});
  }
  return result;
}

}  // namespace donkey
