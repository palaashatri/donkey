#pragma once

#include <optional>
#include <stdexcept>
#include <utility>

#include "donkey/core/status.h"

namespace donkey {

/// Result carries either a value or a Diagnostic. It is deliberately not
/// std::expected (C++23) because the project targets C++20.
template <typename T>
class [[nodiscard]] Result {
 public:
  using value_type = T;

  Result(T value) : value_(std::move(value)) {}  // NOLINT(google-explicit-constructor)
  Result(Diagnostic diagnostic) : diagnostic_(std::move(diagnostic)) {
    if (diagnostic_->status == Status::Success) {
      diagnostic_->status = Status::InternalError;
      diagnostic_->code = "result.invalid_success_diagnostic";
    }
  }

  [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return has_value(); }

  T& value() & {
    require_value();
    return *value_;
  }
  const T& value() const& {
    require_value();
    return *value_;
  }
  T&& value() && {
    require_value();
    return std::move(*value_);
  }

  [[nodiscard]] const Diagnostic& diagnostic() const& {
    require_diagnostic();
    return *diagnostic_;
  }

  [[nodiscard]] Status status() const noexcept {
    return has_value() ? Status::Success : diagnostic_->status;
  }

 private:
  void require_value() const {
    if (!value_) {
      throw std::logic_error("Result::value() called on an error result");
    }
  }
  void require_diagnostic() const {
    if (!diagnostic_) {
      throw std::logic_error("Result::diagnostic() called on a value result");
    }
  }

  std::optional<T> value_;
  std::optional<Diagnostic> diagnostic_;
};

/// Void result: either success or a diagnostic.
template <>
class [[nodiscard]] Result<void> {
 public:
  Result() noexcept = default;
  Result(Diagnostic diagnostic) : diagnostic_(std::move(diagnostic)) {}  // NOLINT

  [[nodiscard]] bool has_value() const noexcept { return !diagnostic_.has_value(); }
  explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] Status status() const noexcept {
    return diagnostic_ ? diagnostic_->status : Status::Success;
  }
  [[nodiscard]] const Diagnostic& diagnostic() const& { return *diagnostic_; }

 private:
  std::optional<Diagnostic> diagnostic_;
};

using VoidResult = Result<void>;

template <typename T>
[[nodiscard]] Result<T> make_error(Status status, std::string code, std::string message,
                                   std::optional<std::uint64_t> offset = std::nullopt) {
  return Result<T>(Diagnostic::make(status, std::move(code), std::move(message), offset));
}

[[nodiscard]] inline VoidResult make_void_error(
    Status status, std::string code, std::string message,
    std::optional<std::uint64_t> offset = std::nullopt) {
  return VoidResult(Diagnostic::make(status, std::move(code), std::move(message), offset));
}

}  // namespace donkey
