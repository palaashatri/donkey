#pragma once

// File reading for tests. A sized read instead of istreambuf_iterator: GCC
// reports false -Wnull-dereference warnings for the inlined iterator at -O3.

#include <cstddef>
#include <istream>

namespace donkey_test {

template <typename Container>
Container read_stream(std::istream& in) {
  in.seekg(0, std::ios::end);
  const std::streamoff end = in.tellg();
  in.seekg(0, std::ios::beg);
  Container out(end > 0 ? static_cast<std::size_t>(end) : 0, typename Container::value_type{});
  if (!out.empty()) {
    in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    out.resize(static_cast<std::size_t>(in.gcount()));
  }
  return out;
}

}  // namespace donkey_test
