#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/image.h"
#include "donkey/core/result.h"

namespace donkey {

enum class InstructionClass : std::uint8_t {
  Unknown = 0,
  Call,
  Jump,
  ConditionalJump,
  Return,
  Interrupt,
  Other,
};

const char* instruction_class_name(InstructionClass value) noexcept;

struct Instruction {
  std::uint64_t address = 0;
  std::uint8_t length = 0;
  std::array<std::uint8_t, 16> bytes{};
  std::string mnemonic;
  std::string operands;
  InstructionClass classification = InstructionClass::Unknown;
  std::optional<std::uint64_t> direct_target;
  /// Absolute addresses referenced through x86 RIP-relative or absolute memory
  /// operands. AArch64 ADRP/ADD pairs are not folded yet.
  std::vector<std::uint64_t> data_references;
};

struct DecodeStream {
  std::vector<Instruction> instructions;
  /// True when decoding stopped before the requested count because of invalid
  /// bytes or a caller-supplied limit. The reason is machine-readable.
  bool truncated = false;
  std::string stop_reason;
};

/// A single architecture decoder. Capstone handles are not thread-safe, so one
/// Decoder belongs to one worker thread; callers must not share instances.
class Decoder {
 public:
  ~Decoder();
  Decoder(Decoder&& other) noexcept;
  Decoder& operator=(Decoder&& other) noexcept;
  Decoder(const Decoder&) = delete;
  Decoder& operator=(const Decoder&) = delete;

  [[nodiscard]] static Result<Decoder> create(Architecture architecture, Endian endian);

  [[nodiscard]] Result<Instruction> decode_one(std::span<const std::byte> bytes,
                                               std::uint64_t address) const;
  [[nodiscard]] Result<DecodeStream> decode(std::span<const std::byte> bytes, std::uint64_t address,
                                            std::size_t max_instructions) const;

  [[nodiscard]] Architecture architecture() const noexcept;
  [[nodiscard]] Endian endian() const noexcept;

 private:
  struct Impl;
  explicit Decoder(std::unique_ptr<Impl> impl);

  std::unique_ptr<Impl> impl_;
};

/// Lowercase hex encoding of an instruction's bytes, without separators.
[[nodiscard]] std::string instruction_bytes_hex(const Instruction& instruction);

}  // namespace donkey
