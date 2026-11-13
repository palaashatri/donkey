#include "names.h"

#include "donkey/binary/demangle.h"

namespace donkey::ui {

std::string readable_name(std::string_view raw) {
  if (is_itanium_name(raw)) {
    auto demangled = demangle_itanium(raw);
    if (demangled) {
      return demangled.value();
    }
  } else if (is_msvc_name(raw)) {
    auto demangled = demangle_msvc(raw);
    if (demangled) {
      return demangled.value();
    }
  }
  return std::string(raw);
}

const std::string& cached_readable_name(std::unordered_map<std::string, std::string>& cache,
                                        const std::string& raw) {
  const auto found = cache.find(raw);
  if (found != cache.end()) {
    return found->second;
  }
  return cache.emplace(raw, readable_name(raw)).first->second;
}

}  // namespace donkey::ui
