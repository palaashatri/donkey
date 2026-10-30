#include "donkey/decode/decode.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include <capstone/capstone.h>

#include "donkey/core/checked.h"

namespace donkey {
namespace {

bool is_conditional_jump(Architecture architecture, const std::string& mnemonic) {
  if (architecture == Architecture::X86 || architecture == Architecture::X86_64) {
    if (mnemonic == "jmp" || mnemonic == "call") {
      return false;
    }
    return !mnemonic.empty() && mnemonic.front() == 'j';
  }
  if (architecture == Architecture::AArch64) {
    if (mnemonic.rfind("b.", 0) == 0) {
      return true;
    }
    return mnemonic == "cbz" || mnemonic == "cbnz" || mnemonic == "tbz" || mnemonic == "tbnz";
  }
  return false;
}

}  // namespace

const char* instruction_class_name(InstructionClass value) noexcept {
  switch (value) {
    case InstructionClass::Unknown:
      return "unknown";
    case InstructionClass::Call:
      return "call";
    case InstructionClass::Jump:
      return "jump";
    case InstructionClass::ConditionalJump:
      return "conditional_jump";
    case InstructionClass::Return:
      return "return";
    case InstructionClass::Interrupt:
      return "interrupt";
    case InstructionClass::Other:
      return "other";
  }
  return "unknown";
}

struct Decoder::Impl {
  csh handle = 0;
  Architecture architecture = Architecture::Unknown;
  Endian endian = Endian::Little;
};

Decoder::Decoder(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Decoder::~Decoder() {
  if (impl_ != nullptr && impl_->handle != 0) {
    cs_close(&impl_->handle);
  }
}

Decoder::Decoder(Decoder&& other) noexcept : impl_(std::move(other.impl_)) {}

Decoder& Decoder::operator=(Decoder&& other) noexcept {
  if (this != &other) {
    if (impl_ != nullptr && impl_->handle != 0) {
      cs_close(&impl_->handle);
    }
    impl_ = std::move(other.impl_);
  }
  return *this;
}

Result<Decoder> Decoder::create(Architecture architecture, Endian endian) {
  cs_arch capstone_arch = CS_ARCH_ALL;
  cs_mode mode = CS_MODE_LITTLE_ENDIAN;
  switch (architecture) {
    case Architecture::X86:
      capstone_arch = CS_ARCH_X86;
      mode = CS_MODE_32;
      break;
    case Architecture::X86_64:
      capstone_arch = CS_ARCH_X86;
      mode = CS_MODE_64;
      break;
    case Architecture::AArch64:
      capstone_arch = CS_ARCH_ARM64;
      mode = CS_MODE_ARM;
      break;
    default:
      return make_error<Decoder>(Status::Unsupported, "decode.unsupported_architecture",
                                 "no decoder is available for this architecture");
  }
  if (endian == Endian::Big && architecture == Architecture::AArch64) {
    mode = static_cast<cs_mode>(mode | CS_MODE_BIG_ENDIAN);
  } else if (endian == Endian::Big &&
             (architecture == Architecture::X86 || architecture == Architecture::X86_64)) {
    return make_error<Decoder>(Status::Unsupported, "decode.big_endian_x86",
                               "x86 images are always little-endian");
  }

  csh handle = 0;
  const cs_err opened = cs_open(capstone_arch, mode, &handle);
  if (opened != CS_ERR_OK) {
    return make_error<Decoder>(Status::Unsupported, "decode.capstone_open_failed",
                               cs_strerror(opened));
  }
  if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
    cs_close(&handle);
    return make_error<Decoder>(Status::InternalError, "decode.capstone_detail_failed",
                               "could not enable instruction details");
  }

  auto impl = std::make_unique<Impl>();
  impl->handle = handle;
  impl->architecture = architecture;
  impl->endian = endian;
  return Decoder(std::move(impl));
}

Architecture Decoder::architecture() const noexcept {
  return impl_ != nullptr ? impl_->architecture : Architecture::Unknown;
}

Endian Decoder::endian() const noexcept {
  return impl_ != nullptr ? impl_->endian : Endian::Little;
}

Result<Instruction> Decoder::decode_one(std::span<const std::byte> bytes,
                                        std::uint64_t address) const {
  if (impl_ == nullptr || impl_->handle == 0) {
    return make_error<Instruction>(Status::InternalError, "decode.invalid_decoder",
                                   "decoder is not initialized", address);
  }
  if (bytes.empty()) {
    return make_error<Instruction>(Status::InvalidInput, "decode.empty_input",
                                   "no bytes available to decode", address);
  }
  const std::size_t available = std::min<std::size_t>(bytes.size(), 16);
  cs_insn* instruction = nullptr;
  const std::size_t count =
      cs_disasm(impl_->handle, reinterpret_cast<const std::uint8_t*>(bytes.data()), available,
                address, 1, &instruction);
  if (count == 0 || instruction == nullptr) {
    return make_error<Instruction>(
        Status::InvalidInput, "decode.invalid_instruction",
        std::string("invalid instruction: ") + cs_strerror(cs_errno(impl_->handle)), address);
  }

  Instruction result;
  result.address = instruction->address;
  result.length = static_cast<std::uint8_t>(instruction->size);
  std::memcpy(result.bytes.data(), instruction->bytes,
              std::min<std::size_t>(instruction->size, result.bytes.size()));
  result.mnemonic = instruction->mnemonic;
  result.operands = instruction->op_str;
  result.classification = InstructionClass::Other;

  if (cs_insn_group(impl_->handle, instruction, CS_GRP_CALL)) {
    result.classification = InstructionClass::Call;
  } else if (cs_insn_group(impl_->handle, instruction, CS_GRP_RET) ||
             cs_insn_group(impl_->handle, instruction, CS_GRP_IRET)) {
    result.classification = InstructionClass::Return;
  } else if (cs_insn_group(impl_->handle, instruction, CS_GRP_INT)) {
    result.classification = InstructionClass::Interrupt;
  } else if (cs_insn_group(impl_->handle, instruction, CS_GRP_JUMP)) {
    result.classification = is_conditional_jump(impl_->architecture, result.mnemonic)
                                ? InstructionClass::ConditionalJump
                                : InstructionClass::Jump;
  }

  if (result.classification == InstructionClass::Call ||
      result.classification == InstructionClass::Jump ||
      result.classification == InstructionClass::ConditionalJump) {
    const bool x86 =
        impl_->architecture == Architecture::X86 || impl_->architecture == Architecture::X86_64;
    if (x86 && instruction->detail != nullptr && instruction->detail->x86.op_count > 0) {
      const cs_x86_op& operand = instruction->detail->x86.operands[0];
      if (operand.type == X86_OP_IMM) {
        result.direct_target = static_cast<std::uint64_t>(operand.imm);
      }
    } else if (impl_->architecture == Architecture::AArch64 && instruction->detail != nullptr &&
               instruction->detail->arm64.op_count > 0) {
      // Direct branch targets are the trailing immediate operand: `b.eq target`,
      // `cbz x, target`, `tbz x, #bit, target`. Reading operands[0] would miss
      // cbz/cbnz/tbz/tbnz, whose first operand is the tested register.
      const int branch_operand_count = instruction->detail->arm64.op_count;
      const cs_arm64_op& branch_operand =
          instruction->detail->arm64.operands[branch_operand_count - 1];
      if (branch_operand.type == ARM64_OP_IMM) {
        result.direct_target = static_cast<std::uint64_t>(branch_operand.imm);
      }
    }
  }

  if (impl_->architecture == Architecture::X86 || impl_->architecture == Architecture::X86_64) {
    if (instruction->detail != nullptr) {
      for (int i = 0; i < instruction->detail->x86.op_count; ++i) {
        const cs_x86_op& operand = instruction->detail->x86.operands[i];
        Operand parsed;
        switch (operand.type) {
          case X86_OP_REG:
            parsed.kind = OperandKind::Register;
            parsed.reg = cs_reg_name(impl_->handle, operand.reg);
            parsed.size = static_cast<std::uint8_t>(operand.size);
            break;
          case X86_OP_IMM:
            parsed.kind = OperandKind::Immediate;
            parsed.immediate = operand.imm;
            parsed.size = static_cast<std::uint8_t>(operand.size);
            break;
          case X86_OP_MEM:
            parsed.kind = OperandKind::Memory;
            parsed.size = static_cast<std::uint8_t>(operand.size);
            if (operand.mem.base != X86_REG_INVALID) {
              parsed.memory.base = cs_reg_name(impl_->handle, operand.mem.base);
            }
            if (operand.mem.index != X86_REG_INVALID) {
              parsed.memory.index = cs_reg_name(impl_->handle, operand.mem.index);
            }
            parsed.memory.scale = operand.mem.scale;
            parsed.memory.displacement = operand.mem.disp;
            parsed.memory.size = parsed.size;
            break;
          default:
            break;
        }
        result.structured_operands.push_back(std::move(parsed));

        if (operand.type != X86_OP_MEM) {
          continue;
        }
        if (operand.mem.base == X86_REG_RIP) {
          const std::uint64_t resolved =
              address + instruction->size + static_cast<std::uint64_t>(operand.mem.disp);
          result.data_references.push_back(resolved);
        } else if (impl_->architecture == Architecture::X86 &&
                   operand.mem.base == X86_REG_INVALID && operand.mem.index == X86_REG_INVALID) {
          result.data_references.push_back(static_cast<std::uint64_t>(operand.mem.disp));
        }
      }
    }
  } else if (impl_->architecture == Architecture::AArch64 && instruction->detail != nullptr) {
    for (int i = 0; i < instruction->detail->arm64.op_count; ++i) {
      const cs_arm64_op& operand = instruction->detail->arm64.operands[i];
      Operand parsed;
      switch (operand.shift.type) {
        case ARM64_SFT_LSL:
          parsed.shift = ShiftKind::Lsl;
          break;
        case ARM64_SFT_LSR:
          parsed.shift = ShiftKind::Lsr;
          break;
        case ARM64_SFT_ASR:
          parsed.shift = ShiftKind::Asr;
          break;
        case ARM64_SFT_ROR:
          parsed.shift = ShiftKind::Ror;
          break;
        default:
          break;
      }
      parsed.shift_amount = static_cast<std::uint8_t>(operand.shift.value & 0xFFU);
      switch (operand.type) {
        case ARM64_OP_REG:
          parsed.kind = OperandKind::Register;
          parsed.reg = cs_reg_name(impl_->handle, operand.reg);
          // cs_arm64_op has no size field; the lifter infers width from the
          // register name (x0 = 64-bit, w0 = 32-bit).
          break;
        case ARM64_OP_IMM:
          parsed.kind = OperandKind::Immediate;
          parsed.immediate = operand.imm;
          break;
        case ARM64_OP_MEM:
          parsed.kind = OperandKind::Memory;
          if (operand.mem.base != ARM64_REG_INVALID) {
            parsed.memory.base = cs_reg_name(impl_->handle, operand.mem.base);
          }
          if (operand.mem.index != ARM64_REG_INVALID) {
            parsed.memory.index = cs_reg_name(impl_->handle, operand.mem.index);
          }
          parsed.memory.displacement = operand.mem.disp;
          parsed.memory.size = parsed.size;
          parsed.memory.writeback = instruction->detail->arm64.writeback;
          parsed.memory.post_index = instruction->detail->arm64.post_index;
          break;
        default:
          break;
      }
      result.structured_operands.push_back(std::move(parsed));
    }
  }

  cs_free(instruction, count);
  return result;
}

Result<DecodeStream> Decoder::decode(std::span<const std::byte> bytes, std::uint64_t address,
                                     std::size_t max_instructions) const {
  DecodeStream stream;
  std::size_t offset = 0;
  while (offset < bytes.size() && stream.instructions.size() < max_instructions) {
    auto instruction = decode_one(bytes.subspan(offset), address + offset);
    if (!instruction) {
      stream.truncated = true;
      stream.stop_reason = instruction.diagnostic().code;
      break;
    }
    offset += instruction.value().length;
    stream.instructions.push_back(std::move(instruction.value()));
  }
  if (offset < bytes.size() && stream.instructions.size() >= max_instructions) {
    stream.truncated = true;
    stream.stop_reason = "decode.instruction_limit";
  }
  return stream;
}

std::string instruction_bytes_hex(const Instruction& instruction) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(static_cast<std::size_t>(instruction.length) * 2);
  for (std::uint8_t i = 0; i < instruction.length && i < instruction.bytes.size(); ++i) {
    out.push_back(kHex[instruction.bytes[i] >> 4U]);
    out.push_back(kHex[instruction.bytes[i] & 0x0FU]);
  }
  return out;
}

}  // namespace donkey
