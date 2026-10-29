#include "donkey/core/status.h"

#include <utility>

#include "donkey/core/ids.h"

namespace donkey {

const char* status_name(Status status) noexcept {
  switch (status) {
    case Status::Success:
      return "Success";
    case Status::Partial:
      return "Partial";
    case Status::Unsupported:
      return "Unsupported";
    case Status::InvalidInput:
      return "InvalidInput";
    case Status::ResourceLimit:
      return "ResourceLimit";
    case Status::Cancelled:
      return "Cancelled";
    case Status::PermissionDenied:
      return "PermissionDenied";
    case Status::CorruptProject:
      return "CorruptProject";
    case Status::InternalError:
      return "InternalError";
  }
  return "InternalError";
}

const char* address_space_name(AddressSpace space) noexcept {
  switch (space) {
    case AddressSpace::FileOffset:
      return "file_offset";
    case AddressSpace::ImageRva:
      return "image_rva";
    case AddressSpace::ImageVa:
      return "image_va";
    case AddressSpace::RuntimeVirtualAddress:
      return "runtime_va";
  }
  return "unknown";
}

Diagnostic Diagnostic::make(Status status, std::string code, std::string message,
                            std::optional<std::uint64_t> offset) {
  Diagnostic diagnostic;
  diagnostic.status = status;
  diagnostic.code = std::move(code);
  diagnostic.message = std::move(message);
  diagnostic.offset = offset;
  return diagnostic;
}

}  // namespace donkey
