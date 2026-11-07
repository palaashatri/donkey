#include "donkey/decode/decode.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <string>
#include <utility>

#include <capstone/capstone.h>

#include "donkey/core/checked.h"

namespace donkey {
namespace {

// The RISC-V branches and jumps whose target is an offset from the instruction (`jal`, `j`, the
// conditional branches and their compressed forms). `jalr` and `c.jr` are indirect.
bool is_direct_riscv_branch(const std::string& mnemonic) {
  static const std::array<const char*, 14> kDirect = {"j",      "c.j",    "jal",  "c.jal", "beq",
                                                      "bne",    "blt",    "bge",  "bltu",  "bgeu",
                                                      "c.beqz", "c.bnez", "beqz", "bnez"};
  return std::find_if(kDirect.begin(), kDirect.end(),
                      [&mnemonic](const char* name) { return mnemonic == name; }) != kDirect.end();
}

// Capstone's group flags miss some MIPS32 and PowerPC32 control transfers: `jal` has none, `jr $ra`
// and `blr` are plain jumps, and PowerPC `bl` is a jump. For those two architectures the class is
// refined from the mnemonic and operands, and for PowerPC from the link bit (bit 0 of the
// instruction word), which `bl`, `bcl`, `bclrl` and `bcctrl` set.
InstructionClass refine_mips_or_ppc_class(const cs_insn& insn, Architecture architecture,
                                          Endian endian, const std::string& mnemonic,
                                          InstructionClass from_groups) {
  if (architecture == Architecture::Mips32) {
    static const std::array<const char*, 10> kLinking = {
        "jal", "jalx", "jalr", "jalr.hb", "bal", "balc", "bltzal", "bgezal", "bltzall", "bgezall"};
    for (const char* linking : kLinking) {
      if (mnemonic == linking) {
        return InstructionClass::Call;
      }
    }
    if (mnemonic == "jr" && insn.detail != nullptr && insn.detail->mips.op_count == 1 &&
        insn.detail->mips.operands[0].type == MIPS_OP_REG &&
        insn.detail->mips.operands[0].reg == MIPS_REG_RA) {
      return InstructionClass::Return;
    }
    return from_groups;
  }
  // PowerPC32: every instruction is 4 bytes, so the link bit is in the last byte when big-endian
  // and in the first when little-endian.
  if ((from_groups != InstructionClass::Jump && from_groups != InstructionClass::ConditionalJump) ||
      insn.size != 4) {
    return from_groups;
  }
  const std::uint8_t link_byte = endian == Endian::Big ? insn.bytes[3] : insn.bytes[0];
  if ((link_byte & 1U) != 0) {
    return InstructionClass::Call;
  }
  if (mnemonic == "blr") {
    return InstructionClass::Return;
  }
  return from_groups;
}

bool is_conditional_jump(Architecture architecture, const std::string& mnemonic) {
  if (architecture == Architecture::Mips32) {
    // `b`, `bal`, `bc`, `balc`, `j`, `jal`, `jalr` and `jr` always transfer control. The other
    // branch mnemonics test a register or a condition (`beq`, `bnez`, `bc1t`), so they fall
    // through.
    if (mnemonic == "b" || mnemonic == "bal" || mnemonic == "bc" || mnemonic == "balc" ||
        mnemonic == "j" || mnemonic == "jal" || mnemonic == "jalr" || mnemonic == "jr") {
      return false;
    }
    return !mnemonic.empty() && mnemonic.front() == 'b';
  }
  if (architecture == Architecture::Ppc32) {
    // `b`, `ba`, `bl`, `bla`, `bctr`, `bctrl`, `blr` and `blrl` always transfer control. The other
    // forms (`bc`, `bt`, `bf`, `bdnz`, and the conditional `bcctr`/`bclr`) can fall through.
    if (mnemonic == "b" || mnemonic == "ba" || mnemonic == "bl" || mnemonic == "bla" ||
        mnemonic == "bctr" || mnemonic == "bctrl" || mnemonic == "blr" || mnemonic == "blrl") {
      return false;
    }
    return !mnemonic.empty() && mnemonic.front() == 'b';
  }
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
  if (architecture == Architecture::Arm) {
    // A32: `b`, `bl` and `bx` are unconditional. A condition code after the `b` makes the branch
    // conditional (`beq`, `blt`, `bhi`), and so does one after the link bit (`bleq`). The suffix
    // is tested whole first: `lt` is a condition, not a link bit followed by `t`.
    static const std::array<const char*, 14> kConditions = {
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"};
    if (mnemonic.empty() || mnemonic.front() != 'b') {
      return false;
    }
    const auto is_condition = [](const std::string& suffix) {
      return std::find_if(kConditions.begin(), kConditions.end(), [&suffix](const char* condition) {
               return suffix == condition;
             }) != kConditions.end();
    };
    const std::string rest = mnemonic.substr(1);
    if (is_condition(rest)) {
      return true;
    }
    return rest.size() > 1 && rest.front() == 'l' && is_condition(rest.substr(1));
  }
  if (architecture == Architecture::RiscV64) {
    // The conditional branches of the base and compressed sets.
    return mnemonic == "beq" || mnemonic == "bne" || mnemonic == "blt" || mnemonic == "bge" ||
           mnemonic == "bltu" || mnemonic == "bgeu" || mnemonic == "c.beqz" || mnemonic == "c.bnez";
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
    case Architecture::Arm:
      // A32 only: Thumb code would decode as garbage, so Thumb is not decoded (see the docs).
      if (endian == Endian::Big) {
        return make_error<Decoder>(Status::Unsupported, "decode.big_endian_arm",
                                   "big-endian ARM images are not decoded");
      }
      capstone_arch = CS_ARCH_ARM;
      mode = CS_MODE_ARM;
      break;
    case Architecture::Mips32:
      // MIPS32 in either byte order. Branch delay slots are not modelled here (decoding only).
      capstone_arch = CS_ARCH_MIPS;
      mode = static_cast<cs_mode>(
          CS_MODE_MIPS32 | (endian == Endian::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
      break;
    case Architecture::Ppc32:
      capstone_arch = CS_ARCH_PPC;
      mode = static_cast<cs_mode>(
          CS_MODE_32 | (endian == Endian::Big ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN));
      break;
    case Architecture::RiscV64:
      // With the compressed set, so the 16-bit instructions compilers emit by default decode too.
      if (endian == Endian::Big) {
        return make_error<Decoder>(Status::Unsupported, "decode.big_endian_riscv",
                                   "big-endian RISC-V images are not decoded");
      }
      capstone_arch = CS_ARCH_RISCV;
      mode = static_cast<cs_mode>(CS_MODE_RISCV64 | CS_MODE_RISCVC);
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

  if ((impl_->architecture == Architecture::Mips32 || impl_->architecture == Architecture::Ppc32) &&
      instruction->detail != nullptr) {
    result.classification = refine_mips_or_ppc_class(
        *instruction, impl_->architecture, impl_->endian, result.mnemonic, result.classification);
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
    } else if (impl_->architecture == Architecture::Arm && instruction->detail != nullptr &&
               instruction->detail->arm.op_count > 0) {
      // A32 branches take their target as the immediate operand (`b #0x...`).
      for (int i = instruction->detail->arm.op_count - 1; i >= 0; --i) {
        const cs_arm_op& operand = instruction->detail->arm.operands[i];
        if (operand.type == ARM_OP_IMM) {
          result.direct_target = static_cast<std::uint64_t>(operand.imm);
          break;
        }
      }
    } else if ((impl_->architecture == Architecture::Mips32 ||
                impl_->architecture == Architecture::Ppc32) &&
               instruction->detail != nullptr) {
      // The target is the last immediate operand, and Capstone gives it as an address.
      const bool mips = impl_->architecture == Architecture::Mips32;
      const std::uint8_t operand_count =
          mips ? instruction->detail->mips.op_count : instruction->detail->ppc.op_count;
      for (int i = static_cast<int>(operand_count) - 1; i >= 0; --i) {
        if (mips) {
          const cs_mips_op& operand = instruction->detail->mips.operands[i];
          if (operand.type == MIPS_OP_IMM) {
            result.direct_target = static_cast<std::uint64_t>(operand.imm);
            break;
          }
        } else {
          const cs_ppc_op& operand = instruction->detail->ppc.operands[i];
          if (operand.type == PPC_OP_IMM) {
            result.direct_target = static_cast<std::uint64_t>(operand.imm);
            break;
          }
        }
      }
    } else if (impl_->architecture == Architecture::RiscV64 && instruction->detail != nullptr &&
               instruction->detail->riscv.op_count > 0 && is_direct_riscv_branch(result.mnemonic)) {
      // RISC-V gives a branch's immediate as an offset from the instruction, not an address.
      // Only the direct forms have one: `jalr` takes its immediate from a register.
      for (int i = instruction->detail->riscv.op_count - 1; i >= 0; --i) {
        const cs_riscv_op& operand = instruction->detail->riscv.operands[i];
        if (operand.type == RISCV_OP_IMM) {
          result.direct_target = instruction->address + static_cast<std::uint64_t>(operand.imm);
          break;
        }
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
      switch (operand.ext) {
        case ARM64_EXT_UXTB:
          parsed.extend = ExtendKind::Uxtb;
          break;
        case ARM64_EXT_UXTH:
          parsed.extend = ExtendKind::Uxth;
          break;
        case ARM64_EXT_UXTW:
          parsed.extend = ExtendKind::Uxtw;
          break;
        case ARM64_EXT_UXTX:
          parsed.extend = ExtendKind::Uxtx;
          break;
        case ARM64_EXT_SXTB:
          parsed.extend = ExtendKind::Sxtb;
          break;
        case ARM64_EXT_SXTH:
          parsed.extend = ExtendKind::Sxth;
          break;
        case ARM64_EXT_SXTW:
          parsed.extend = ExtendKind::Sxtw;
          break;
        case ARM64_EXT_SXTX:
          parsed.extend = ExtendKind::Sxtx;
          break;
        default:
          break;
      }
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
        case ARM64_OP_FP:
          // A floating-point immediate (fmov, fcmp with #0.0). The value is kept as
          // the bits of the double; the lifter converts it to the width it needs.
          parsed.kind = OperandKind::Immediate;
          parsed.immediate = std::bit_cast<std::int64_t>(operand.fp);
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
  // The smallest instruction slot: fixed 4-byte words on AArch64, 32-bit ARM, MIPS32 and PowerPC32,
  // 2 for Thumb/compressed RISC-V, 1 byte for variable-length x86.
  std::size_t slot = 1;
  if (impl_ != nullptr) {
    switch (impl_->architecture) {
      case Architecture::AArch64:
      case Architecture::Arm:
      case Architecture::Mips32:
      case Architecture::Ppc32:
        slot = 4;
        break;
      case Architecture::RiscV64:
        slot = 2;
        break;
      default:
        break;
    }
  }
  std::size_t offset = 0;
  while (offset < bytes.size() && stream.instructions.size() < max_instructions) {
    auto instruction = decode_one(bytes.subspan(offset), address + offset);
    if (!instruction) {
      if (instruction.diagnostic().code != "decode.invalid_instruction") {
        stream.truncated = true;
        stream.stop_reason = instruction.diagnostic().code;
        break;
      }
      const std::size_t skip = std::min(slot, bytes.size() - offset);
      if (stream.invalid_bytes == 0) {
        stream.first_invalid_address = address + offset;
      }
      stream.invalid_bytes += skip;
      offset += skip;
      continue;
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
