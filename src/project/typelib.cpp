#include "donkey/project/typelib.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "donkey/core/sha256.h"
#include "donkey/project/cdecl.h"

namespace donkey {
namespace {

constexpr std::string_view kFormatName = "donkey-typelib";
constexpr std::string_view kFormatLine = "donkey-typelib 1";

// Keys in the order of `Key`, so a key's index is its enum value.
enum class Key : std::uint8_t {
  Library,
  LibraryVersion,
  Platform,
  Architecture,
  Abi,
  DataModel,
  PointerSize,
  LongSize,
  CharIsSigned,
  Source,
  SourceSha256,
  Licence,
  LicenceFile,
  LicenceSha256,
  Generator,
  GeneratorCommand,
  Preprocessor,
  Created,
  BodySha256,
  Declarations,
  SourceFile,
  Macro,
  Skipped,
  Note,
};

constexpr std::size_t kKeyCount = 24;
constexpr std::size_t kSingleKeyCount = 20;

struct KeyInfo {
  std::string_view name;
  bool repeated;
};

constexpr std::array<KeyInfo, kKeyCount> kKeys = {{
    {"library", false},
    {"library_version", false},
    {"platform", false},
    {"architecture", false},
    {"abi", false},
    {"data_model", false},
    {"pointer_size", false},
    {"long_size", false},
    {"char_is_signed", false},
    {"source", false},
    {"source_sha256", false},
    {"licence", false},
    {"licence_file", false},
    {"licence_sha256", false},
    {"generator", false},
    {"generator_command", false},
    {"preprocessor", false},
    {"created", false},
    {"body_sha256", false},
    {"declarations", false},
    {"source_file", true},
    {"macro", true},
    {"skipped", true},
    {"note", true},
}};

/// Order of the repeated records: source_file, macro, skipped, note. A single key has rank 0.
int record_rank(Key key) {
  switch (key) {
    case Key::SourceFile:
      return 1;
    case Key::Macro:
      return 2;
    case Key::Skipped:
      return 3;
    case Key::Note:
      return 4;
    default:
      return 0;
  }
}

// ---- helpers -----------------------------------------------------------------------------

std::string line_text(std::uint64_t line) {
  return "line " + std::to_string(line);
}

template <typename T>
Result<T> refuse(Status status, std::string code, std::string message) {
  return make_error<T>(status, std::move(code), std::move(message));
}

VoidResult refuse_void(Status status, std::string code, std::string message) {
  return make_void_error(status, std::move(code), std::move(message));
}

bool is_printable(std::string_view text) {
  for (const char c : text) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20 || byte > 0x7e) {
      return false;
    }
  }
  return true;
}

bool is_digit(char c) {
  return c >= '0' && c <= '9';
}

bool is_identifier(std::string_view text) {
  if (text.empty() || is_digit(text.front())) {
    return false;
  }
  for (const char c : text) {
    const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    if (!letter && !is_digit(c)) {
      return false;
    }
  }
  return true;
}

/// A decimal number of at most `max_digits` digits. Empty and signed text is refused.
std::optional<std::uint64_t> parse_decimal(std::string_view text, std::size_t max_digits) {
  if (text.empty() || text.size() > max_digits) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (!is_digit(c)) {
      return std::nullopt;
    }
    value = value * 10 + static_cast<std::uint64_t>(c - '0');
  }
  return value;
}

bool is_sha256(std::string_view text) {
  if (text.size() != 64) {
    return false;
  }
  for (const char c : text) {
    const bool hex = is_digit(c) || (c >= 'a' && c <= 'f');
    if (!hex) {
      return false;
    }
  }
  return true;
}

bool is_leap_year(std::uint64_t year) {
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

bool is_date(std::string_view text) {
  if (text.size() != 10 || text[4] != '-' || text[7] != '-') {
    return false;
  }
  for (const std::size_t i : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U}) {
    if (!is_digit(text[i])) {
      return false;
    }
  }
  const std::uint64_t year = *parse_decimal(text.substr(0, 4), 4);
  const std::uint64_t month = *parse_decimal(text.substr(5, 2), 2);
  const std::uint64_t day = *parse_decimal(text.substr(8, 2), 2);
  static constexpr std::array<std::uint64_t, 12> kDays = {31, 28, 31, 30, 31, 30,
                                                          31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12 || day < 1) {
    return false;
  }
  std::uint64_t limit = kDays[month - 1];
  if (month == 2 && is_leap_year(year)) {
    limit = 29;
  }
  return day <= limit;
}

/// A path relative to the source: no leading slash, no backslash, no colon, and no empty,
/// `.` or `..` segment.
bool is_relative_path(std::string_view path) {
  if (path.empty() || path.front() == '/' || path.find_first_of("\\:") != std::string_view::npos) {
    return false;
  }
  std::size_t start = 0;
  while (true) {
    const std::size_t slash = path.find('/', start);
    const std::string_view segment = path.substr(
        start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
    if (segment.empty() || segment == "." || segment == "..") {
      return false;
    }
    if (slash == std::string_view::npos) {
      return true;
    }
    start = slash + 1;
  }
}

/// The message of a located parser error, with its line moved into the library file. The
/// parser counts lines in the C text; the text starts after the header's empty line.
std::string relocate_message(std::string message, std::uint64_t separator_line) {
  constexpr std::string_view kPrefix = "line ";
  if (!std::string_view(message).starts_with(kPrefix)) {
    return message;
  }
  const std::size_t comma = message.find(',');
  if (comma == std::string::npos) {
    return message;
  }
  const auto body_line =
      parse_decimal(std::string_view(message).substr(kPrefix.size(), comma - kPrefix.size()), 10);
  if (!body_line) {
    return message;
  }
  return line_text(separator_line + *body_line) + message.substr(comma);
}

/// The file line of the byte at `offset` in the C text (the text's first line is the line after
/// the separator).
std::uint64_t file_line_of(std::string_view body, std::size_t offset, std::uint64_t separator) {
  std::uint64_t newlines = 0;
  for (std::size_t i = 0; i < offset && i < body.size(); ++i) {
    if (body[i] == '\n') {
      ++newlines;
    }
  }
  return separator + 1 + newlines;
}

// ---- header state ------------------------------------------------------------------------

struct Header {
  TypeLibrary library;
  std::uint32_t seen = 0;                       ///< a bit per single key
  std::array<std::uint64_t, kKeyCount> line{};  ///< where each key was given first
  int last_rank = 0;
  std::set<std::string> paths;
};

/// One header value line. `value` is non-empty and printable (checked by the caller).
VoidResult apply_single(Header& header, Key key, std::uint64_t line_no, std::string_view value) {
  TypeLibrary& lib = header.library;
  const std::string name(kKeys[static_cast<std::size_t>(key)].name);
  const auto bad = [&](std::string reason) {
    return refuse_void(Status::InvalidInput, "typelib.bad_value",
                       line_text(line_no) + ": " + name + ": " + std::move(reason));
  };
  const auto one_of = [&](std::initializer_list<std::string_view> options) {
    for (const std::string_view option : options) {
      if (value == option) {
        return true;
      }
    }
    return false;
  };

  switch (key) {
    case Key::Library:
      lib.library = std::string(value);
      return Result<void>();
    case Key::LibraryVersion:
      lib.library_version = std::string(value);
      return Result<void>();
    case Key::Platform:
      if (!one_of({"linux", "freebsd", "windows", "macos"})) {
        return bad("expected linux, freebsd, windows or macos");
      }
      lib.platform = std::string(value);
      return Result<void>();
    case Key::Architecture:
      if (!one_of({"x86_64", "aarch64"})) {
        return bad("expected x86_64 or aarch64");
      }
      lib.architecture = std::string(value);
      return Result<void>();
    case Key::Abi:
      if (!one_of({"sysv", "aapcs64", "win64"})) {
        return bad("expected sysv, aapcs64 or win64");
      }
      lib.abi = std::string(value);
      return Result<void>();
    case Key::DataModel:
      if (!one_of({"LP64", "LLP64"})) {
        return bad("expected LP64 or LLP64");
      }
      lib.data_model = std::string(value);
      return Result<void>();
    case Key::PointerSize: {
      const auto size = parse_decimal(value, 2);
      if (!size || (*size != 4 && *size != 8)) {
        return bad("expected 4 or 8");
      }
      lib.pointer_size = *size;
      return Result<void>();
    }
    case Key::LongSize: {
      const auto size = parse_decimal(value, 2);
      if (!size || (*size != 4 && *size != 8)) {
        return bad("expected 4 or 8");
      }
      lib.long_size = *size;
      return Result<void>();
    }
    case Key::CharIsSigned:
      if (!one_of({"true", "false"})) {
        return bad("expected true or false");
      }
      lib.char_is_signed = value == "true";
      return Result<void>();
    case Key::Source:
      lib.source = std::string(value);
      return Result<void>();
    case Key::SourceSha256:
      if (!is_sha256(value)) {
        return bad("expected 64 lowercase hex digits");
      }
      lib.source_sha256 = std::string(value);
      return Result<void>();
    case Key::Licence:
      lib.licence = std::string(value);
      return Result<void>();
    case Key::LicenceFile:
      lib.licence_file = std::string(value);
      return Result<void>();
    case Key::LicenceSha256:
      if (!is_sha256(value)) {
        return bad("expected 64 lowercase hex digits");
      }
      lib.licence_sha256 = std::string(value);
      return Result<void>();
    case Key::Generator:
      lib.generator = std::string(value);
      return Result<void>();
    case Key::GeneratorCommand:
      lib.generator_command = std::string(value);
      return Result<void>();
    case Key::Preprocessor:
      lib.preprocessor = std::string(value);
      return Result<void>();
    case Key::Created:
      if (!is_date(value)) {
        return bad("expected a date as YYYY-MM-DD");
      }
      lib.created = std::string(value);
      return Result<void>();
    case Key::BodySha256:
      if (!is_sha256(value)) {
        return bad("expected 64 lowercase hex digits");
      }
      lib.body_sha256 = std::string(value);
      return Result<void>();
    case Key::Declarations: {
      const auto count = parse_decimal(value, 9);
      if (!count) {
        return bad("expected a decimal count");
      }
      if (*count > kMaxTypeLibraryDeclarations) {
        return refuse_void(Status::ResourceLimit, "typelib.too_many_declarations",
                           line_text(line_no) + ": declarations: " + std::to_string(*count) +
                               " is over the limit of " +
                               std::to_string(kMaxTypeLibraryDeclarations));
      }
      lib.declarations = *count;
      return Result<void>();
    }
    default:
      return refuse_void(Status::InternalError, "typelib.internal",
                         "a single key without a handler");
  }
}

VoidResult apply_repeated(Header& header, Key key, std::uint64_t line_no, std::string_view value) {
  TypeLibrary& lib = header.library;
  const auto bad = [&](std::string reason) {
    return refuse_void(Status::InvalidInput, "typelib.bad_value",
                       line_text(line_no) + ": " +
                           std::string(kKeys[static_cast<std::size_t>(key)].name) + ": " +
                           std::move(reason));
  };

  switch (key) {
    case Key::SourceFile: {
      const std::size_t space = value.rfind(' ');
      if (space == std::string_view::npos) {
        return bad("expected '<path> <sha256>'");
      }
      const std::string_view path = value.substr(0, space);
      const std::string_view sha = value.substr(space + 1);
      if (!is_relative_path(path)) {
        return bad("the path must be relative, with no '..' or '.' segment");
      }
      if (!is_sha256(sha)) {
        return bad("the hash must be 64 lowercase hex digits");
      }
      if (!header.paths.insert(std::string(path)).second) {
        return refuse_void(
            Status::InvalidInput, "typelib.duplicate_path",
            line_text(line_no) + ": source_file: '" + std::string(path) + "' is listed twice");
      }
      lib.source_files.push_back({std::string(path), std::string(sha)});
      return Result<void>();
    }
    case Key::Macro: {
      const std::size_t equals = value.find('=');
      if (equals == std::string_view::npos || !is_identifier(value.substr(0, equals))) {
        return bad("expected 'NAME=value'");
      }
      lib.macros.push_back(
          {std::string(value.substr(0, equals)), std::string(value.substr(equals + 1))});
      return Result<void>();
    }
    case Key::Skipped: {
      const std::size_t separator = value.find(": ");
      if (separator == std::string_view::npos || separator == 0 || separator + 2 >= value.size()) {
        return bad("expected '<name>: <reason>'");
      }
      lib.skipped.push_back(
          {std::string(value.substr(0, separator)), std::string(value.substr(separator + 2))});
      return Result<void>();
    }
    case Key::Note:
      lib.notes.push_back(std::string(value));
      return Result<void>();
    default:
      return refuse_void(Status::InternalError, "typelib.internal",
                         "a repeated key without a handler");
  }
}

/// One header line other than the format line and the empty line.
VoidResult apply_header_line(Header& header, std::uint64_t line_no, std::string_view line) {
  const std::size_t colon = line.find(':');
  if (colon == std::string_view::npos || colon + 1 >= line.size() || line[colon + 1] != ' ') {
    return refuse_void(Status::InvalidInput, "typelib.format",
                       line_text(line_no) + ": a header line is 'key: value'");
  }
  const std::string_view key_text = line.substr(0, colon);
  const std::string_view value = line.substr(colon + 2);

  std::optional<std::size_t> index;
  for (std::size_t i = 0; i < kKeyCount; ++i) {
    if (kKeys[i].name == key_text) {
      index = i;
      break;
    }
  }
  if (!index) {
    return refuse_void(Status::InvalidInput, "typelib.unknown_key",
                       line_text(line_no) + ": unknown key '" + std::string(key_text) + "'");
  }
  const Key key = static_cast<Key>(*index);
  if (value.empty()) {
    return refuse_void(Status::InvalidInput, "typelib.bad_value",
                       line_text(line_no) + ": " + std::string(key_text) + ": the value is empty");
  }
  if (!is_printable(value)) {
    return refuse_void(Status::InvalidInput, "typelib.bad_value",
                       line_text(line_no) + ": " + std::string(key_text) +
                           ": the value has a character outside printable ASCII");
  }

  const int rank = record_rank(key);
  if (rank < header.last_rank) {
    return refuse_void(Status::InvalidInput, "typelib.record_order",
                       line_text(line_no) + ": '" + std::string(key_text) +
                           "' is out of order; the header lists every single key, then "
                           "source_file, macro, skipped and note records, in that order");
  }
  header.last_rank = rank;

  if (!kKeys[*index].repeated) {
    const std::uint32_t bit = 1U << *index;
    if ((header.seen & bit) != 0) {
      return refuse_void(Status::InvalidInput, "typelib.duplicate_key",
                         line_text(line_no) + ": '" + std::string(key_text) +
                             "' is given twice; first at line " +
                             std::to_string(header.line[*index]));
    }
    header.seen |= bit;
    header.line[*index] = line_no;
    return apply_single(header, key, line_no, value);
  }
  return apply_repeated(header, key, line_no, value);
}

/// The checks that need more than one key: the ABI against the data model and the
/// architecture, and the sizes against the data model.
VoidResult check_abi(const Header& header) {
  const TypeLibrary& lib = header.library;
  const auto at = [&](Key key) { return header.line[static_cast<std::size_t>(key)]; };
  const auto mismatch = [](std::uint64_t line, std::string reason) {
    return refuse_void(Status::InvalidInput, "typelib.data_model_mismatch",
                       line_text(line) + ": " + std::move(reason));
  };
  const auto bad = [](std::uint64_t line, std::string reason) {
    return refuse_void(Status::InvalidInput, "typelib.bad_value",
                       line_text(line) + ": " + std::move(reason));
  };

  if ((lib.abi == "sysv" || lib.abi == "aapcs64") && lib.data_model != "LP64") {
    return mismatch(at(Key::Abi), lib.abi + " needs the LP64 data model");
  }
  if (lib.abi == "win64" && lib.data_model != "LLP64") {
    return mismatch(at(Key::Abi), "win64 needs the LLP64 data model");
  }
  if (lib.data_model == "LP64" && lib.long_size != 8) {
    return mismatch(at(Key::LongSize), "LP64 has an 8-byte long");
  }
  if (lib.data_model == "LLP64" && lib.long_size != 4) {
    return mismatch(at(Key::LongSize), "LLP64 has a 4-byte long");
  }
  if (lib.pointer_size != 8) {
    return mismatch(at(Key::PointerSize), "LP64 and LLP64 have 8-byte pointers");
  }
  if (lib.abi == "sysv" && lib.architecture != "x86_64") {
    return bad(at(Key::Abi), "sysv is the x86-64 System V ABI");
  }
  if (lib.abi == "aapcs64" && lib.architecture != "aarch64") {
    return bad(at(Key::Abi), "aapcs64 is the AArch64 procedure call standard");
  }
  if (lib.abi == "win64" && (lib.architecture != "x86_64" || lib.platform != "windows")) {
    return bad(at(Key::Abi), "win64 is the x86-64 Windows ABI, for platform windows");
  }
  return Result<void>();
}

/// A parser refusal, carried over with its position moved into the library file. The parser's
/// final whole-set check (`cdecl.invalid_type`) is this reader's `typelib.invalid_types`.
template <typename T>
Result<T> passthrough(const Diagnostic& diagnostic, std::uint64_t separator_line) {
  std::string code =
      diagnostic.code == "cdecl.invalid_type" ? "typelib.invalid_types" : diagnostic.code;
  return make_error<T>(diagnostic.status, std::move(code),
                       relocate_message(diagnostic.message, separator_line));
}

/// The C text: the parser, then the duplicate and validity checks on what it returned.
Result<std::vector<TypeDefinition>> read_body(const Header& header, std::string_view body,
                                              std::uint64_t separator_line,
                                              const TypeTable& known) {
  using Out = std::vector<TypeDefinition>;
  const TypeLibrary& lib = header.library;

  if (const std::size_t cr = body.find('\r'); cr != std::string_view::npos) {
    return refuse<Out>(Status::InvalidInput, "typelib.carriage_return",
                       line_text(file_line_of(body, cr, separator_line)) +
                           ": the C text has a CR byte; line endings must be LF");
  }

  const auto digest = Sha256::digest(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(body.data()), body.size()));
  const std::string actual = Sha256::hex(digest);
  if (actual != lib.body_sha256) {
    return refuse<Out>(Status::InvalidInput, "typelib.body_hash",
                       line_text(header.line[static_cast<std::size_t>(Key::BodySha256)]) +
                           ": the C text hashes to " + actual + ", not body_sha256");
  }

  CDeclarationOptions options;
  options.pointer_size = lib.pointer_size;
  options.long_size = lib.long_size;
  options.char_is_signed = lib.char_is_signed;
  options.bit_fields = bit_field_layout(lib.abi, lib.platform);

  // A library parses on its own, against the built-in names only, so the table it is read into
  // cannot change what its text means (a typedef there could otherwise shadow a built-in name).
  // Its declared count is that parse's count.
  std::vector<CDeclaredName> declared;
  auto parsed = parse_c_declarations(body, TypeTable{}, options, &declared);
  if (!parsed) {
    return passthrough<Out>(parsed.diagnostic(), separator_line);
  }
  std::vector<TypeDefinition> types = std::move(parsed.value());
  if (types.size() != lib.declarations) {
    return refuse<Out>(Status::InvalidInput, "typelib.declaration_count",
                       line_text(header.line[static_cast<std::size_t>(Key::Declarations)]) +
                           ": the header declares " + std::to_string(lib.declarations) +
                           " but the C text has " + std::to_string(types.size()));
  }

  // The types are moved up to take their ids from `known.next_id()`, so they do not collide with
  // the table they join. Every id the parse returns (and every reference, except 0 for void) lies
  // in the run it allocated from an empty table.
  const std::uint64_t base = TypeTable{}.next_id().value();
  const std::uint64_t first = known.next_id().value();
  if (first < base || first > std::numeric_limits<std::uint64_t>::max() - types.size()) {
    return refuse<Out>(Status::InvalidInput, "typelib.invalid_types",
                       "the type table has no room for the library's type ids");
  }
  const auto rebase = [&](TypeId id) {
    return id.valid() ? TypeId(id.value() - base + first) : id;
  };
  for (TypeDefinition& definition : types) {
    definition.id = rebase(definition.id);
    definition.target = rebase(definition.target);
    for (TypeField& field : definition.fields) {
      field.type = rebase(field.type);
    }
  }

  // C keeps two name spaces apart: the tags of structs, unions and enums, and the ordinary names
  // of typedefs, enumeration constants and functions. One spelling may be a tag and an ordinary
  // name at once (`struct stat` and the function `stat`, or `typedef struct point point`). Within
  // one name space a name is declared once: a function and another ordinary name with one spelling
  // is typelib.type_and_function, and any other repeat is typelib.duplicate_name. The parser lists
  // each declared name with its name space, so a typedef that names an untagged struct (whose type
  // takes the typedef's name) is an ordinary name, not a tag.
  std::map<std::string, TypeKind> tags;
  std::map<std::string, TypeKind> ordinary;
  for (const CDeclaredName& name : declared) {
    if (name.completes) {
      continue;  // the definition of a tag named earlier by a forward reference
    }
    std::map<std::string, TypeKind>& space = name.space == CNameSpace::Tag ? tags : ordinary;
    const auto [entry, inserted] = space.emplace(name.name, name.kind);
    if (inserted) {
      continue;
    }
    if (name.space == CNameSpace::Ordinary &&
        (entry->second == TypeKind::Function) != (name.kind == TypeKind::Function)) {
      return refuse<Out>(Status::InvalidInput, "typelib.type_and_function",
                         "'" + name.name +
                             "' is used both as a function and as a typedef or enumeration "
                             "constant");
    }
    return refuse<Out>(
        Status::InvalidInput, "typelib.duplicate_name",
        "'" + name.name + "' is declared more than once" +
            (name.space == CNameSpace::Tag ? " as a struct, union or enum tag" : ""));
  }

  TypeTable check = known;
  for (const TypeDefinition& definition : types) {
    check.put(definition);
  }
  if (const VoidResult valid = check.validate(); !valid) {
    return refuse<Out>(
        Status::InvalidInput, "typelib.invalid_types",
        "the declarations do not form a valid type set: " + valid.diagnostic().message);
  }

  for (TypeDefinition& definition : types) {
    definition.provenance = TypeProvenance::Library;
  }
  return types;
}

}  // namespace

CBitFieldLayout bit_field_layout(std::string_view abi, std::string_view platform) noexcept {
  if (abi == "sysv") {
    return CBitFieldLayout::SystemV;
  }
  if (abi == "aapcs64" && (platform == "linux" || platform == "freebsd")) {
    return CBitFieldLayout::Aapcs64;
  }
  return CBitFieldLayout::Unmodelled;
}

Result<TypeLibrary> read_type_library(std::string_view text, const TypeTable& known) {
  if (text.size() > kMaxTypeLibraryBytes) {
    return refuse<TypeLibrary>(Status::ResourceLimit, "typelib.too_large",
                               "the library is larger than 4 MiB");
  }

  Header header;
  std::size_t pos = 0;
  std::uint64_t line_no = 0;
  std::uint64_t separator = 0;
  std::size_t body_start = std::string_view::npos;

  while (pos < text.size()) {
    ++line_no;
    const std::size_t newline = text.find('\n', pos);
    const std::size_t end = newline == std::string_view::npos ? text.size() : newline;
    const std::size_t next = newline == std::string_view::npos ? text.size() : newline + 1;
    const std::string_view line = text.substr(pos, end - pos);
    pos = next;

    if (line.find('\r') != std::string_view::npos) {
      return refuse<TypeLibrary>(Status::InvalidInput, "typelib.carriage_return",
                                 line_text(line_no) + ": a CR byte; line endings must be LF");
    }
    if (line_no == 1) {
      if (line == kFormatLine) {
        continue;
      }
      if (line.starts_with(kFormatName) && line.size() > kFormatName.size() &&
          line[kFormatName.size()] == ' ') {
        return refuse<TypeLibrary>(Status::InvalidInput, "typelib.version",
                                   "line 1: format version '" +
                                       std::string(line.substr(kFormatName.size() + 1)) +
                                       "' is not supported; this reader reads version 1");
      }
      return refuse<TypeLibrary>(Status::InvalidInput, "typelib.format",
                                 "line 1: the first line must be 'donkey-typelib 1'");
    }

    if (line.empty()) {
      separator = line_no;
      body_start = next;
      break;
    }
    if (line.size() > kMaxTypeLibraryHeaderLineBytes) {
      return refuse<TypeLibrary>(Status::ResourceLimit, "typelib.line_too_long",
                                 line_text(line_no) + ": a header line is over 256 bytes");
    }
    if (line_no > kMaxTypeLibraryHeaderLines) {
      return refuse<TypeLibrary>(Status::ResourceLimit, "typelib.too_many_lines",
                                 "the header has more than 4096 lines");
    }
    if (auto applied = apply_header_line(header, line_no, line); !applied) {
      return make_error<TypeLibrary>(applied.diagnostic().status, applied.diagnostic().code,
                                     applied.diagnostic().message);
    }
  }

  if (line_no == 0) {
    return refuse<TypeLibrary>(Status::InvalidInput, "typelib.format",
                               "line 1: the file is empty; the first line must be "
                               "'donkey-typelib 1'");
  }
  if (body_start == std::string_view::npos) {
    return refuse<TypeLibrary>(
        Status::InvalidInput, "typelib.format",
        line_text(line_no) + ": the header must end with an empty line before the C text");
  }

  for (std::size_t i = 0; i < kSingleKeyCount; ++i) {
    if ((header.seen & (1U << i)) == 0) {
      return refuse<TypeLibrary>(
          Status::InvalidInput, "typelib.missing_key",
          line_text(separator) + ": the header has no '" + std::string(kKeys[i].name) + "' line");
    }
  }
  if (auto abi = check_abi(header); !abi) {
    return make_error<TypeLibrary>(abi.diagnostic().status, abi.diagnostic().code,
                                   abi.diagnostic().message);
  }

  auto types = read_body(header, text.substr(body_start), separator, known);
  if (!types) {
    return make_error<TypeLibrary>(types.diagnostic().status, types.diagnostic().code,
                                   types.diagnostic().message);
  }

  TypeLibrary library = std::move(header.library);
  library.types = std::move(types.value());
  return library;
}

Result<TypeLibrary> load_type_library(const std::filesystem::path& path) {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(path, ec) || ec) {
    return refuse<TypeLibrary>(Status::InvalidInput, "typelib.io",
                               "the type library is not a readable regular file");
  }
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) {
    return refuse<TypeLibrary>(Status::InvalidInput, "typelib.io",
                               "the type library's size cannot be read");
  }
  if (size > kMaxTypeLibraryBytes) {
    return refuse<TypeLibrary>(Status::ResourceLimit, "typelib.too_large",
                               "the library is larger than 4 MiB; it was not read");
  }

  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return refuse<TypeLibrary>(Status::InvalidInput, "typelib.io",
                               "the type library cannot be opened");
  }
  // One byte past the size: a file that grew since it was measured is refused, not read in part.
  std::string text(static_cast<std::size_t>(size) + 1, '\0');
  in.read(text.data(), static_cast<std::streamsize>(text.size()));
  const auto count = static_cast<std::size_t>(in.gcount());
  // A read of size + 1 bytes from a file of exactly `size` bytes sets eofbit and failbit, so only
  // badbit and a short count mean the file could not be read.
  if (in.bad() || count < size) {
    return refuse<TypeLibrary>(Status::InvalidInput, "typelib.io",
                               "the type library could not be read completely");
  }
  if (count > size) {
    return refuse<TypeLibrary>(Status::ResourceLimit, "typelib.too_large",
                               "the library grew while it was read; it was refused");
  }
  text.resize(count);
  return read_type_library(text, TypeTable{});
}

}  // namespace donkey
