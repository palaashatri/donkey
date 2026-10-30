#include "donkey/core/version.h"

#ifndef DONKEY_VERSION
#define DONKEY_VERSION "0.0.0-unknown"
#endif

namespace donkey {

std::string_view version() noexcept {
  return DONKEY_VERSION;
}

}  // namespace donkey
