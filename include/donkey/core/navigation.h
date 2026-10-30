#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace donkey {

/// Thread-host history stack tracking address navigation across disasm, graph,
/// and pseudocode views.
class NavigationHistory {
 public:
  NavigationHistory() = default;

  void navigate_to(std::uint64_t address) {
    if (address == 0 || current_address_ == address) {
      return;
    }
    if (!is_navigating_) {
      if (history_index_ + 1 < history_.size()) {
        history_.erase(history_.begin() + static_cast<std::ptrdiff_t>(history_index_ + 1),
                       history_.end());
      }
      if (history_.empty() && current_address_ != 0) {
        history_.push_back(current_address_);
      }
      history_.push_back(address);
      history_index_ = history_.size() - 1;
    }
    current_address_ = address;
  }

  [[nodiscard]] bool can_nav_back() const noexcept {
    return !history_.empty() && history_index_ > 0;
  }

  [[nodiscard]] bool can_nav_forward() const noexcept {
    return !history_.empty() && history_index_ + 1 < history_.size();
  }

  [[nodiscard]] std::uint64_t current_address() const noexcept { return current_address_; }

  std::optional<std::uint64_t> nav_back() {
    if (can_nav_back()) {
      is_navigating_ = true;
      --history_index_;
      current_address_ = history_[history_index_];
      is_navigating_ = false;
      return current_address_;
    }
    return std::nullopt;
  }

  std::optional<std::uint64_t> nav_forward() {
    if (can_nav_forward()) {
      is_navigating_ = true;
      ++history_index_;
      current_address_ = history_[history_index_];
      is_navigating_ = false;
      return current_address_;
    }
    return std::nullopt;
  }

  void clear() {
    history_.clear();
    history_index_ = 0;
    current_address_ = 0;
    is_navigating_ = false;
  }

 private:
  std::vector<std::uint64_t> history_;
  std::size_t history_index_ = 0;
  std::uint64_t current_address_ = 0;
  bool is_navigating_ = false;
};

}  // namespace donkey
