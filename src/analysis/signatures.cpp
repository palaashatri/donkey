#include "donkey/analysis/signatures.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

#include "donkey/binary/separate_debug.h"

namespace donkey {
namespace {

constexpr std::size_t kPrefixMax = 32;
constexpr std::uint64_t kMaxFunctionBytes = 16U * 1024U * 1024U;
constexpr std::size_t kMaxNameBytes = 4096;
constexpr std::size_t kMaxTextBytes = 256;
constexpr std::size_t kMaxArchitectureBytes = 32;

Diagnostic field_error(const std::string& message) {
  return Diagnostic::make(Status::InvalidInput, "sig.field", message, std::nullopt);
}

Diagnostic value_error(const std::string& message) {
  return Diagnostic::make(Status::InvalidInput, "sig.value", message, std::nullopt);
}

/// Whether byte `index` lies in a wildcard. The wildcards are sorted, so the walk stops early.
bool wildcard_at(std::span<const SignatureWildcard> wildcards, std::uint64_t index) {
  for (const SignatureWildcard& span : wildcards) {
    if (index < span.offset) {
      return false;
    }
    if (index < static_cast<std::uint64_t>(span.offset) + span.length) {
      return true;
    }
  }
  return false;
}

/// The CRC-32 a function's tail gives under a signature's wildcards: the bytes after the prefix,
/// with every wildcard byte replaced by zero.
std::uint32_t tail_crc(std::span<const std::byte> function, std::size_t prefix_size,
                       std::span<const SignatureWildcard> wildcards) {
  std::vector<std::byte> tail(function.begin() + static_cast<std::ptrdiff_t>(prefix_size),
                              function.end());
  for (std::size_t i = 0; i < tail.size(); ++i) {
    if (wildcard_at(wildcards, prefix_size + i)) {
      tail[i] = std::byte{0};
    }
  }
  return gnu_crc32(tail);
}

/// Whether a function of exactly the signature's length matches it.
bool matches(const Signature& signature, std::span<const std::byte> function) {
  const std::size_t prefix_size = signature.prefix.size();
  for (std::size_t i = 0; i < prefix_size; ++i) {
    if (!wildcard_at(signature.wildcards, i) && function[i] != signature.prefix[i]) {
      return false;
    }
  }
  return tail_crc(function, prefix_size, signature.wildcards) == signature.crc32;
}

bool valid_wildcards(const std::vector<SignatureWildcard>& wildcards, std::uint64_t length) {
  std::uint64_t previous_end = 0;
  for (const SignatureWildcard& span : wildcards) {
    if (span.length == 0 || span.offset < previous_end ||
        static_cast<std::uint64_t>(span.offset) + span.length > length) {
      return false;
    }
    previous_end = static_cast<std::uint64_t>(span.offset) + span.length;
  }
  return true;
}

std::string hex_text(std::span<const std::byte> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const std::byte value : bytes) {
    const auto byte = static_cast<unsigned>(std::to_integer<std::uint8_t>(value));
    out.push_back(kDigits[byte >> 4U]);
    out.push_back(kDigits[byte & 0xFU]);
  }
  return out;
}

Result<std::vector<std::byte>> parse_hex(std::string_view text, std::size_t max_bytes,
                                         const char* what) {
  if (text.size() % 2 != 0 || text.size() / 2 > max_bytes) {
    return make_error<std::vector<std::byte>>(Status::InvalidInput, "sig.value",
                                              std::string(what) +
                                                  " is not an even-length hex "
                                                  "string of the right size");
  }
  std::vector<std::byte> out;
  out.reserve(text.size() / 2);
  for (std::size_t i = 0; i < text.size(); i += 2) {
    unsigned value = 0;
    for (std::size_t k = 0; k < 2; ++k) {
      const char c = text[i + k];
      unsigned digit = 0;
      if (c >= '0' && c <= '9') {
        digit = static_cast<unsigned>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        digit = static_cast<unsigned>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        digit = static_cast<unsigned>(c - 'A' + 10);
      } else {
        return make_error<std::vector<std::byte>>(Status::InvalidInput, "sig.value",
                                                  std::string(what) + " has a non-hex character");
      }
      value = value * 16U + digit;
    }
    out.push_back(static_cast<std::byte>(value));
  }
  return out;
}

/// An integer that the JSON text spells as an integer (no fraction or exponent) within `max`.
Result<std::uint64_t> integer_field(const JsonValue& value, std::uint64_t max, const char* what) {
  if (!value.is_number()) {
    return make_error<std::uint64_t>(Status::InvalidInput, "sig.field",
                                     std::string(what) + " must be a number");
  }
  std::uint64_t parsed = 0;
  const std::string& text = value.text;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (result.ec != std::errc() || result.ptr != text.data() + text.size() || parsed > max) {
    return make_error<std::uint64_t>(Status::InvalidInput, "sig.value",
                                     std::string(what) + " is not an integer in range");
  }
  return parsed;
}

Result<std::string> string_field(const JsonValue* value, std::size_t max_bytes, bool required,
                                 const char* what) {
  if (value == nullptr) {
    if (required) {
      return make_error<std::string>(Status::InvalidInput, "sig.field",
                                     std::string(what) + " is missing");
    }
    return std::string();
  }
  if (!value->is_string()) {
    return make_error<std::string>(Status::InvalidInput, "sig.field",
                                   std::string(what) + " must be a string");
  }
  if (value->text.size() > max_bytes) {
    return make_error<std::string>(Status::InvalidInput, "sig.value",
                                   std::string(what) + " is too long");
  }
  if (required && value->text.empty()) {
    return make_error<std::string>(Status::InvalidInput, "sig.value",
                                   std::string(what) + " must not be empty");
  }
  return value->text;
}

void append_json_string(std::string& out, std::string_view text) {
  out.push_back('"');
  for (const char c : text) {
    const auto byte = static_cast<unsigned char>(c);
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (byte < 0x20) {
      char escape[8];
      std::snprintf(escape, sizeof(escape), "\\u%04x", static_cast<unsigned>(byte));
      out += escape;
    } else {
      out.push_back(c);
    }
  }
  out.push_back('"');
}

}  // namespace

Result<Signature> make_signature(std::span<const std::byte> function_bytes, std::string name,
                                 std::vector<SignatureWildcard> wildcards) {
  if (function_bytes.empty() || function_bytes.size() > kMaxFunctionBytes) {
    return make_error<Signature>(Status::InvalidInput, "sig.value",
                                 "a function must be between 1 byte and 16 MiB");
  }
  if (name.empty() || name.size() > kMaxNameBytes) {
    return make_error<Signature>(Status::InvalidInput, "sig.value",
                                 "a signature needs a name of 1 to 4096 bytes");
  }
  if (!valid_wildcards(wildcards, function_bytes.size())) {
    return make_error<Signature>(Status::InvalidInput, "sig.value",
                                 "wildcards must be non-empty, sorted, non-overlapping and inside "
                                 "the function");
  }
  Signature signature;
  signature.name = std::move(name);
  signature.length = static_cast<std::uint32_t>(function_bytes.size());
  const std::size_t prefix_size = std::min(kPrefixMax, function_bytes.size());
  signature.prefix.assign(function_bytes.begin(),
                          function_bytes.begin() + static_cast<std::ptrdiff_t>(prefix_size));
  for (std::size_t i = 0; i < prefix_size; ++i) {
    if (wildcard_at(wildcards, i)) {
      signature.prefix[i] = std::byte{0};
    }
  }
  signature.crc32 = tail_crc(function_bytes, prefix_size, wildcards);
  signature.wildcards = std::move(wildcards);
  return signature;
}

Result<SignatureSet> parse_signature_set(std::string_view json, const JsonLimits& limits) {
  auto root = parse_json(json, limits);
  if (!root) {
    return root.diagnostic();
  }
  const JsonValue& document = root.value();
  if (!document.is_object()) {
    return Diagnostic::make(Status::InvalidInput, "sig.format", "a signature set is a JSON object",
                            std::nullopt);
  }
  const JsonValue* format = document.find("format");
  if (format == nullptr || !format->is_string() || format->text != kSignatureFormat) {
    return Diagnostic::make(Status::Unsupported, "sig.format",
                            std::string("the signature format must be ") + kSignatureFormat,
                            std::nullopt);
  }
  SignatureSet set;
  auto library = string_field(document.find("library"), kMaxTextBytes, true, "library");
  if (!library) return library.diagnostic();
  set.library = library.value();
  auto version = string_field(document.find("version"), kMaxTextBytes, true, "version");
  if (!version) return version.diagnostic();
  set.version = version.value();
  auto license = string_field(document.find("license"), kMaxTextBytes, true, "license");
  if (!license) return license.diagnostic();
  set.license = license.value();
  auto architecture =
      string_field(document.find("architecture"), kMaxArchitectureBytes, true, "architecture");
  if (!architecture) return architecture.diagnostic();
  set.architecture = architecture.value();

  const JsonValue* list = document.find("signatures");
  if (list == nullptr || !list->is_array()) {
    return field_error("signatures must be an array");
  }
  set.signatures.reserve(list->items.size());
  for (const JsonValue& entry : list->items) {
    if (!entry.is_object()) {
      return field_error("each signature must be an object");
    }
    Signature signature;
    auto name = string_field(entry.find("name"), kMaxNameBytes, true, "signature name");
    if (!name) return name.diagnostic();
    signature.name = name.value();
    const JsonValue* length = entry.find("length");
    const JsonValue* prefix = entry.find("prefix");
    const JsonValue* wildcards = entry.find("wildcards");
    const JsonValue* crc = entry.find("crc32");
    if (length == nullptr || prefix == nullptr || wildcards == nullptr || crc == nullptr) {
      return field_error("a signature needs length, prefix, wildcards and crc32");
    }
    auto parsed_length = integer_field(*length, kMaxFunctionBytes, "length");
    if (!parsed_length) return parsed_length.diagnostic();
    if (parsed_length.value() == 0) {
      return value_error("a signature length must be at least 1");
    }
    signature.length = static_cast<std::uint32_t>(parsed_length.value());
    if (!prefix->is_string()) {
      return field_error("prefix must be a hex string");
    }
    const std::size_t expected_prefix = std::min<std::size_t>(kPrefixMax, signature.length);
    auto prefix_bytes = parse_hex(prefix->text, expected_prefix, "prefix");
    if (!prefix_bytes) return prefix_bytes.diagnostic();
    if (prefix_bytes.value().size() != expected_prefix) {
      return value_error("the prefix must be min(32, length) bytes");
    }
    signature.prefix = std::move(prefix_bytes.value());
    if (!wildcards->is_array()) {
      return field_error("wildcards must be an array of [offset, length] pairs");
    }
    for (const JsonValue& pair : wildcards->items) {
      if (!pair.is_array() || pair.items.size() != 2) {
        return field_error("each wildcard is an [offset, length] pair");
      }
      auto offset = integer_field(pair.items[0], kMaxFunctionBytes, "wildcard offset");
      if (!offset) return offset.diagnostic();
      auto span_length = integer_field(pair.items[1], kMaxFunctionBytes, "wildcard length");
      if (!span_length) return span_length.diagnostic();
      signature.wildcards.push_back(
          SignatureWildcard{static_cast<std::uint32_t>(offset.value()),
                            static_cast<std::uint32_t>(span_length.value())});
    }
    if (!valid_wildcards(signature.wildcards, signature.length)) {
      return value_error(
          "wildcards must be non-empty, sorted, non-overlapping and inside the "
          "function");
    }
    auto parsed_crc = integer_field(*crc, std::numeric_limits<std::uint32_t>::max(), "crc32");
    if (!parsed_crc) return parsed_crc.diagnostic();
    signature.crc32 = static_cast<std::uint32_t>(parsed_crc.value());
    set.signatures.push_back(std::move(signature));
  }
  return set;
}

std::string write_signature_set(const SignatureSet& set) {
  std::string out = "{\n  \"format\": ";
  append_json_string(out, kSignatureFormat);
  out += ",\n  \"library\": ";
  append_json_string(out, set.library);
  out += ",\n  \"version\": ";
  append_json_string(out, set.version);
  out += ",\n  \"license\": ";
  append_json_string(out, set.license);
  out += ",\n  \"architecture\": ";
  append_json_string(out, set.architecture);
  out += ",\n  \"signatures\": [";
  for (std::size_t i = 0; i < set.signatures.size(); ++i) {
    const Signature& signature = set.signatures[i];
    out += i == 0 ? "\n    {" : ",\n    {";
    out += "\"name\": ";
    append_json_string(out, signature.name);
    out += ", \"length\": " + std::to_string(signature.length);
    out += ", \"prefix\": \"" + hex_text(signature.prefix) + "\"";
    out += ", \"wildcards\": [";
    for (std::size_t w = 0; w < signature.wildcards.size(); ++w) {
      out += (w == 0 ? "" : ", ") + std::string("[") +
             std::to_string(signature.wildcards[w].offset) + ", " +
             std::to_string(signature.wildcards[w].length) + "]";
    }
    out += "], \"crc32\": " + std::to_string(signature.crc32) + "}";
  }
  out += set.signatures.empty() ? "]\n}\n" : "\n  ]\n}\n";
  return out;
}

Result<std::vector<SignatureMatch>> identify_functions(const SignatureSet& set,
                                                       const BinaryImage& image,
                                                       std::span<const std::byte> file,
                                                       std::span<const SignatureFunction> functions,
                                                       std::span<const std::uint64_t> user_named) {
  if (set.architecture != architecture_name(image.architecture)) {
    return make_error<std::vector<SignatureMatch>>(Status::Unsupported, "sig.architecture",
                                                   "the signature set is for " + set.architecture +
                                                       " and the image is " +
                                                       architecture_name(image.architecture));
  }
  // Signatures grouped by length: a function can only match one of its own length.
  std::unordered_map<std::uint32_t, std::vector<const Signature*>> by_length;
  for (const Signature& signature : set.signatures) {
    by_length[signature.length].push_back(&signature);
  }
  const std::set<std::uint64_t> named(user_named.begin(), user_named.end());

  std::vector<SignatureMatch> out;
  for (const SignatureFunction& function : functions) {
    if (function.end <= function.address || named.contains(function.address)) {
      continue;
    }
    const std::uint64_t length = function.end - function.address;
    if (length > kMaxFunctionBytes) {
      continue;
    }
    const auto group = by_length.find(static_cast<std::uint32_t>(length));
    if (group == by_length.end()) {
      continue;
    }
    auto offset = image.va_to_file_offset(function.address);
    if (!offset || offset.value() > file.size() || length > file.size() - offset.value()) {
      continue;
    }
    const std::span<const std::byte> bytes =
        file.subspan(static_cast<std::size_t>(offset.value()), static_cast<std::size_t>(length));
    std::vector<const Signature*> candidates;
    for (const Signature* signature : group->second) {
      if (matches(*signature, bytes)) {
        candidates.push_back(signature);
      }
    }
    if (candidates.empty()) {
      continue;
    }
    SignatureMatch match;
    match.address = function.address;
    match.candidates = candidates.size();
    const std::string& first = candidates.front()->name;
    const bool same_name = std::all_of(candidates.begin(), candidates.end(),
                                       [&first](const Signature* s) { return s->name == first; });
    if (same_name) {
      match.name = first;
      match.provenance = "signature " + set.library + " " + set.version;
    } else {
      match.ambiguous = true;
    }
    out.push_back(std::move(match));
  }
  return out;
}

Result<std::vector<SignatureMatch>> identify_at_starts(const SignatureSet& set,
                                                       const BinaryImage& image,
                                                       std::span<const std::byte> file,
                                                       std::span<const std::uint64_t> starts,
                                                       std::span<const std::uint64_t> user_named) {
  if (set.architecture != architecture_name(image.architecture)) {
    return make_error<std::vector<SignatureMatch>>(Status::Unsupported, "sig.architecture",
                                                   "the signature set is for " + set.architecture +
                                                       " and the image is " +
                                                       architecture_name(image.architecture));
  }
  std::unordered_map<std::uint32_t, std::vector<const Signature*>> by_length;
  for (const Signature& signature : set.signatures) {
    if (signature.length <= kMaxFunctionBytes) {
      by_length[signature.length].push_back(&signature);
    }
  }
  std::vector<std::uint32_t> lengths;
  for (const auto& [length, group] : by_length) {
    lengths.push_back(length);
  }
  std::sort(lengths.begin(), lengths.end(), std::greater<>());  // longest first
  const std::set<std::uint64_t> named(user_named.begin(), user_named.end());

  std::vector<SignatureMatch> out;
  for (const std::uint64_t start : starts) {
    if (named.contains(start)) {
      continue;
    }
    auto offset = image.va_to_file_offset(start);
    if (!offset || offset.value() > file.size()) {
      continue;
    }
    // The longest length whose signatures match here wins; the others are not reported.
    for (const std::uint32_t length : lengths) {
      if (length > file.size() - offset.value()) {
        continue;
      }
      const std::span<const std::byte> bytes =
          file.subspan(static_cast<std::size_t>(offset.value()), length);
      std::vector<const Signature*> candidates;
      for (const Signature* signature : by_length[length]) {
        if (matches(*signature, bytes)) {
          candidates.push_back(signature);
        }
      }
      if (candidates.empty()) {
        continue;
      }
      SignatureMatch match;
      match.address = start;
      match.length = length;
      match.candidates = candidates.size();
      const std::string& first = candidates.front()->name;
      const bool same_name = std::all_of(candidates.begin(), candidates.end(),
                                         [&first](const Signature* s) { return s->name == first; });
      if (same_name) {
        match.name = first;
        match.provenance = "signature " + set.library + " " + set.version;
      } else {
        match.ambiguous = true;
      }
      out.push_back(std::move(match));
      break;
    }
  }
  return out;
}

}  // namespace donkey
