#pragma once

#include <string>
#include <string_view>

namespace donkey::cli {

// Runs newline-separated JSON-RPC requests through a fresh session with no project, and returns
// the response lines, each followed by a newline. This is the request handling of
// `donkey-cli serve` without stdin, for fuzz/fuzz_rpc.cpp.
std::string serve_text(std::string_view input);

}  // namespace donkey::cli
