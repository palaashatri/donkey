#include "donkey/project/typelib_gen.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/core/sha256.h"
#include "donkey/project/cdecl.h"

namespace donkey {
namespace {

bool is_ident_char(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}

bool is_ident_start(char c) {
  return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_';
}

/// Words that never change a type, removed from a declaration.
bool dropped_word(std::string_view word) {
  static const std::set<std::string_view> kDropped{"restrict",      "__restrict",   "__restrict__",
                                                   "__extension__", "__inline",     "__inline__",
                                                   "_Noreturn",     "__volatile__", "__const"};
  return kDropped.contains(word);
}

/// The index just past the character or string literal that opens at `at` (a ' or "), escapes
/// included; the end of the text when it is not closed.
std::size_t skip_literal(std::string_view text, std::size_t at) {
  const char quote = text[at];
  for (++at; at < text.size(); ++at) {
    if (text[at] == '\\') {
      ++at;  // the escaped character, whatever it is
    } else if (text[at] == quote) {
      return at + 1;
    }
  }
  return text.size();
}

bool opens_literal(char c) {
  return c == '\'' || c == '"';
}

/// An assembler label (`__asm__("name")`) renames the symbol and never the type: removed.
bool dropped_asm(std::string_view word) {
  return word == "__asm__" || word == "__asm" || word == "asm";
}

/// Attribute words: their parenthesised argument is examined, not dropped blindly.
bool attribute_word(std::string_view word) {
  return word == "__attribute__" || word == "__attribute" || word == "__declspec";
}

/// GCC and MSVC attributes that change neither a type nor its layout: diagnostics, optimisation
/// hints, linkage and visibility. Any other attribute (`aligned`, `packed`, `vector_size`, `mode`,
/// `transparent_union`, one this list does not know) may change the type, so a declaration that
/// carries it is kept with its attribute and skipped, never kept without it.
bool type_neutral_attribute(std::string_view name) {
  while (name.size() > 4 && name.starts_with("__") && name.ends_with("__")) {
    name = name.substr(2, name.size() - 4);
  }
  static const std::set<std::string_view> kNeutral{"noreturn",
                                                   "nothrow",
                                                   "leaf",
                                                   "const",
                                                   "pure",
                                                   "malloc",
                                                   "nonnull",
                                                   "returns_nonnull",
                                                   "warn_unused_result",
                                                   "format",
                                                   "format_arg",
                                                   "deprecated",
                                                   "unavailable",
                                                   "visibility",
                                                   "unused",
                                                   "used",
                                                   "cold",
                                                   "hot",
                                                   "returns_twice",
                                                   "sentinel",
                                                   "alloc_size",
                                                   "alloc_align",
                                                   "access",
                                                   "noinline",
                                                   "always_inline",
                                                   "gnu_inline",
                                                   "artificial",
                                                   "weak",
                                                   "error",
                                                   "warning",
                                                   "nonstring",
                                                   "noclone",
                                                   "flatten",
                                                   "no_instrument_function",
                                                   "dllimport",
                                                   "dllexport",
                                                   "noalias",
                                                   "restrict"};
  return kNeutral.contains(name);
}

/// The index just past the parenthesised group that starts at the first '(' at or after `at`.
/// Delimiters inside a character or string literal are not counted.
std::size_t skip_group(std::string_view text, std::size_t at) {
  while (at < text.size() && std::isspace(static_cast<unsigned char>(text[at])) != 0) {
    ++at;
  }
  if (at >= text.size() || text[at] != '(') {
    return at;
  }
  int depth = 0;
  while (at < text.size()) {
    if (opens_literal(text[at])) {
      at = skip_literal(text, at);
      continue;
    }
    if (text[at] == '(') {
      ++depth;
    } else if (text[at] == ')' && --depth == 0) {
      return at + 1;
    }
    ++at;
  }
  return at;
}

/// Whether every attribute named in the group `text[from, to)` (`((a, b(1), c))`) is type-neutral.
/// The names are the identifiers at the group's second level of parentheses.
bool neutral_attribute_group(std::string_view text, std::size_t from, std::size_t to,
                             bool declspec) {
  int depth = 0;
  std::size_t at = from;
  while (at < to) {
    const char c = text[at];
    if (opens_literal(c)) {
      at = skip_literal(text, at);
      continue;
    }
    if (c == '(') {
      ++depth;
    } else if (c == ')') {
      --depth;
    } else if (is_ident_start(c)) {
      std::size_t end = at + 1;
      while (end < to && is_ident_char(text[end])) {
        ++end;
      }
      // __attribute__((name ...)) puts a name at depth 2; __declspec(name) at depth 1.
      if (depth == (declspec ? 1 : 2) && !type_neutral_attribute(text.substr(at, end - at))) {
        return false;
      }
      at = end;
      continue;
    }
    ++at;
  }
  return true;
}

/// One declaration on one line: dropped words removed, every run of white space one space.
std::string normalised(std::string_view text) {
  std::string out;
  std::size_t i = 0;
  bool space = false;
  while (i < text.size()) {
    const char c = text[i];
    if (std::isspace(static_cast<unsigned char>(c)) != 0) {
      space = true;
      ++i;
      continue;
    }
    std::string_view piece;
    std::size_t next = i + 1;
    if (opens_literal(c)) {
      // A literal is copied as it is: its spaces and delimiters are not C text.
      next = skip_literal(text, i);
      piece = text.substr(i, next - i);
    } else if (is_ident_start(c)) {
      while (next < text.size() && is_ident_char(text[next])) {
        ++next;
      }
      const std::string_view word = text.substr(i, next - i);
      if (dropped_word(word)) {
        i = next;
        space = true;
        continue;
      }
      if (dropped_asm(word)) {
        i = skip_group(text, next);
        space = true;
        continue;
      }
      if (attribute_word(word)) {
        const std::size_t end = skip_group(text, next);
        if (neutral_attribute_group(text, next, end, word == "__declspec")) {
          i = end;
          space = true;
          continue;
        }
        // Kept, written as `__attribute__((...))` (or `__declspec(...)`) without inner spaces:
        // make_type_library skips the declaration and names the attribute.
        if (space && !out.empty()) {
          out.push_back(' ');
        }
        space = false;
        out.append(word == "__attribute" ? std::string_view("__attribute__") : word);
        for (std::size_t k = next; k < end; ++k) {
          if (std::isspace(static_cast<unsigned char>(text[k])) == 0) {
            out.push_back(text[k]);
          }
        }
        i = end;
        continue;
      }
      piece = word;
    } else {
      piece = text.substr(i, 1);
    }
    // No space before `,`, `)`, `]` and `;`, or after `(` and `[`.
    const bool closes = piece == "," || piece == ")" || piece == "]" || piece == ";";
    const bool after_open = !out.empty() && (out.back() == '(' || out.back() == '[');
    if (space && !out.empty() && !closes && !after_open) {
      out.push_back(' ');
    }
    space = false;
    out.append(piece);
    i = next;
  }
  return out;
}

/// The name a skipped declaration is listed under: a tag, a function's name, or a typedef's name.
std::string name_of(const std::string& declaration) {
  std::vector<std::pair<std::string, int>> words;  // identifier and its paren depth
  int depth = 0;
  std::size_t first_paren = std::string::npos;
  std::string before_first_paren;
  for (std::size_t i = 0; i < declaration.size();) {
    const char c = declaration[i];
    if (c == '(') {
      if (depth == 0 && first_paren == std::string::npos) {
        first_paren = i;
        before_first_paren = words.empty() ? std::string() : words.back().first;
      }
      ++depth;
    } else if (c == ')') {
      --depth;
    }
    if (is_ident_start(c)) {
      std::size_t j = i;
      while (j < declaration.size() && is_ident_char(declaration[j])) {
        ++j;
      }
      words.emplace_back(declaration.substr(i, j - i), depth);
      i = j;
      continue;
    }
    ++i;
  }
  if (words.empty()) {
    return "unnamed";
  }
  const std::string& head = words.front().first;
  if ((head == "struct" || head == "union" || head == "enum") && words.size() > 1 &&
      declaration.find('{') != std::string::npos &&
      declaration.find('{') > declaration.find(words[1].first)) {
    return words[1].first;
  }
  if (head == "typedef") {
    // `typedef void (*handler)(int);`: the first identifier inside the first group.
    if (first_paren != std::string::npos && first_paren + 1 < declaration.size() &&
        declaration.find('*', first_paren) == first_paren + 1) {
      for (const auto& [word, at_depth] : words) {
        if (at_depth == 1 && declaration.find(word, first_paren) != std::string::npos) {
          return word;
        }
      }
    }
    for (auto it = words.rbegin(); it != words.rend(); ++it) {
      if (it->second == 0) {
        return it->first;
      }
    }
  }
  if (!before_first_paren.empty()) {
    return before_first_paren;
  }
  for (auto it = words.rbegin(); it != words.rend(); ++it) {
    if (it->second == 0) {
      return it->first;
    }
  }
  return words.back().first;
}

/// Printable ASCII with no ':' (a skipped record is `skipped: <name>: <reason>`), at most `limit`
/// bytes.
std::string record_text(std::string_view text, std::size_t limit, bool allow_colon) {
  std::string out;
  for (const char c : text) {
    if (out.size() >= limit) {
      break;
    }
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20 || byte > 0x7e || (!allow_colon && c == ':')) {
      out.push_back(' ');
    } else {
      out.push_back(c);
    }
  }
  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  return out.empty() ? std::string("unnamed") : out;
}

std::string hex_digest(std::string_view text) {
  return Sha256::hex(
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

}  // namespace

std::vector<std::string> split_c_declarations(std::string_view preprocessed) {
  std::vector<std::string> out;
  std::string current;
  int braces = 0;
  int parens = 0;
  bool line_start = true;
  for (std::size_t i = 0; i < preprocessed.size(); ++i) {
    const char c = preprocessed[i];
    if (line_start && c == '#') {
      // A line the preprocessor kept (`# 1 "file"`, a pragma): not C text.
      while (i < preprocessed.size() && preprocessed[i] != '\n') {
        ++i;
      }
      continue;
    }
    // A directive's '#' may follow spaces or tabs.
    line_start = c == '\n' || (line_start && (c == ' ' || c == '\t'));
    if (opens_literal(c)) {
      // A literal's contents are not delimiters.
      const std::size_t end = skip_literal(preprocessed, i);
      current.append(preprocessed.substr(i, end - i));
      i = end - 1;
      continue;
    }
    if (c == '/' && i + 1 < preprocessed.size() &&
        (preprocessed[i + 1] == '*' || preprocessed[i + 1] == '/')) {
      // A comment (input preprocessed with -C keeps them) is one space, as C reads it; its
      // contents are not delimiters, and a line comment keeps the line break that ends it.
      if (preprocessed[i + 1] == '*') {
        const std::size_t close = preprocessed.find("*/", i + 2);
        i = close == std::string_view::npos ? preprocessed.size() : close + 1;
      } else {
        const std::size_t newline = preprocessed.find('\n', i + 2);
        i = (newline == std::string_view::npos ? preprocessed.size() : newline) - 1;
      }
      current.push_back(' ');
      continue;
    }
    current.push_back(c);
    if (c == '(') {
      ++parens;
    } else if (c == ')') {
      parens = std::max(0, parens - 1);
    } else if (c == '{') {
      ++braces;
    } else if (c == '}') {
      braces = std::max(0, braces - 1);
      if (braces == 0 && parens == 0) {
        // A function definition ends at its closing brace, with no ';' after it: `) { ... }`.
        const std::string text = normalised(current);
        const std::size_t open = text.find('{');
        const std::size_t before =
            open == std::string::npos ? std::string::npos : text.find_last_not_of(' ', open - 1);
        if (open != std::string::npos && open > 0 && before != std::string::npos &&
            text[before] == ')') {
          out.push_back(text);
          current.clear();
        }
      }
    } else if (c == ';' && braces == 0 && parens == 0) {
      std::string text = normalised(current);
      if (text != ";") {
        out.push_back(std::move(text));
      }
      current.clear();
    }
  }
  const std::string rest = normalised(current);
  if (!rest.empty()) {
    out.push_back(rest);
  }
  return out;
}

namespace {

/// The first pragma of the text that may change a type's layout, or an empty string. Only the
/// pragmas known to change no type or layout are allowed: `pack`, `ms_struct`,
/// `scalar_storage_order` and any pragma not listed here are refused, because dropping them would
/// keep the declarations after them with a layout the compiler did not use.
std::string layout_pragma(std::string_view preprocessed) {
  bool line_start = true;
  for (std::size_t i = 0; i < preprocessed.size(); ++i) {
    const char c = preprocessed[i];
    if (line_start && c == '#') {
      std::size_t end = preprocessed.find('\n', i);
      if (end == std::string_view::npos) {
        end = preprocessed.size();
      }
      std::string_view line = preprocessed.substr(i + 1, end - i - 1);
      const auto trim = [](std::string_view& text) {
        while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
          text.remove_prefix(1);
        }
      };
      trim(line);
      if (line.starts_with("pragma") && (line.size() == 6 || line[6] == ' ' || line[6] == '\t')) {
        line.remove_prefix(6);
        trim(line);
        static constexpr std::string_view kHarmless[] = {"once",
                                                         "GCC diagnostic",
                                                         "clang diagnostic",
                                                         "GCC system_header",
                                                         "GCC visibility",
                                                         "GCC poison",
                                                         "GCC warning",
                                                         "GCC error",
                                                         "message",
                                                         "STDC",
                                                         "weak",
                                                         "redefine_extname"};
        const bool harmless =
            std::any_of(std::begin(kHarmless), std::end(kHarmless), [&](std::string_view known) {
              return line.starts_with(known) &&
                     (line.size() == known.size() || line[known.size()] == ' ' ||
                      line[known.size()] == '\t' || line[known.size()] == '(');
            });
        if (!harmless) {
          return std::string(line.substr(0, std::min<std::size_t>(line.size(), 80)));
        }
      }
      i = end;
      line_start = true;
      continue;
    }
    // A directive's '#' may follow spaces or tabs.
    line_start = c == '\n' || (line_start && (c == ' ' || c == '\t'));
  }
  return {};
}

}  // namespace

Result<TypeLibraryMakeResult> make_type_library(std::string_view preprocessed,
                                                const TypeLibraryMakeOptions& options) {
  if (const std::string pragma = layout_pragma(preprocessed); !pragma.empty()) {
    return make_error<TypeLibraryMakeResult>(
        Status::InvalidInput, "typelib_make.pragma",
        "'#pragma " + pragma +
            "' may change the layout of the declarations after it, which the generator does not "
            "model");
  }
  CDeclarationOptions parse_options;
  parse_options.pointer_size = options.pointer_size;
  parse_options.long_size = options.long_size;
  parse_options.char_is_signed = options.char_is_signed;
  parse_options.bit_fields = bit_field_layout(options.abi, options.platform);

  TypeLibraryMakeResult made;
  std::set<std::string> tags;
  std::set<std::string> ordinary;
  std::string body;
  std::size_t kept_lines = 0;  // lines of the kept text (one per declaration)
  std::size_t kept_names = 0;  // names the kept text lists
  for (const std::string& declaration : split_c_declarations(preprocessed)) {
    std::string name = record_text(name_of(declaration), 96, false);
    if (declaration.find('{') != std::string::npos && declaration.back() == '}') {
      made.skipped.push_back({name, "a function definition (only declarations are kept)"});
      continue;
    }
    if (const std::size_t attribute =
            std::min(declaration.find("__attribute__"), declaration.find("__declspec"));
        attribute != std::string::npos) {
      // normalised() kept it: an attribute that may change the type, which the subset does not
      // model. The declaration is not kept without it.
      const std::size_t group_end =
          skip_group(declaration, declaration.find('(', attribute) == std::string::npos
                                      ? declaration.size()
                                      : declaration.find('(', attribute));
      made.skipped.push_back(
          {name,
           "an attribute that may change the type is not modelled: " +
               declaration.substr(attribute, std::min<std::size_t>(group_end - attribute, 80))});
      continue;
    }
    // The kept text and this declaration parse together, from an empty table, as the reader parses
    // the library: a tag the kept text named only by a forward reference (`struct stat *` in a
    // member) is completed here, and a second complete definition is refused.
    const std::string trial_body = body + declaration + "\n";
    std::vector<CDeclaredName> all_names;
    auto whole = parse_c_declarations(trial_body, TypeTable{}, parse_options, &all_names);
    if (!whole) {
      // The parse's position is in the whole text: a line past the kept text's lines is in this
      // declaration, and is given relative to it ("line 1" is its first line); one inside the kept
      // text means the declaration conflicts with what was kept.
      const Diagnostic& failure = whole.diagnostic();
      std::string message = failure.message;
      bool in_declaration = false;
      if (message.starts_with("line ")) {
        std::size_t digits_end = 5;
        while (digits_end < message.size() &&
               std::isdigit(static_cast<unsigned char>(message[digits_end])) != 0) {
          ++digits_end;
        }
        if (digits_end > 5 && digits_end - 5 <= 9) {
          const std::size_t line = std::stoul(message.substr(5, digits_end - 5));
          if (line > kept_lines) {
            in_declaration = true;
            message = "line " + std::to_string(line - kept_lines) + message.substr(digits_end);
          }
        }
      }
      // The parser names the declarator it refused ("'optind' declares a variable"): that name,
      // not a guess from the text, identifies the record.
      if (const std::size_t open = message.find('\''); open != std::string::npos &&
                                                       open + 1 < message.size() &&
                                                       is_ident_start(message[open + 1])) {
        const std::size_t close = message.find('\'', open + 1);
        const std::string_view after = close == std::string::npos
                                           ? std::string_view()
                                           : std::string_view(message).substr(close + 1);
        // Only the messages that quote the declarator itself: "'x' declares a variable", "'x' is
        // already defined". Others quote a type or a token.
        if (after.starts_with(" declares") || after.starts_with(" is already defined")) {
          name = record_text(message.substr(open + 1, close - open - 1), 96, false);
        }
      }
      made.skipped.push_back(
          {name,
           failure.code + (in_declaration ? " " : " (with the kept declarations) ") + message});
      continue;
    }
    const std::vector<CDeclaredName> names(
        all_names.begin() + static_cast<std::ptrdiff_t>(std::min(kept_names, all_names.size())),
        all_names.end());
    if (names.empty()) {
      made.skipped.push_back({name, "declares no type, typedef or function"});
      continue;
    }
    bool repeated = false;
    for (const CDeclaredName& declared : names) {
      const auto& space = declared.space == CNameSpace::Tag ? tags : ordinary;
      repeated = repeated || (!declared.completes && space.contains(declared.name));
    }
    if (repeated) {
      made.skipped.push_back({name, "declared again (the first declaration is kept)"});
      continue;
    }
    for (const CDeclaredName& declared : names) {
      (declared.space == CNameSpace::Tag ? tags : ordinary).insert(declared.name);
    }
    kept_lines +=
        static_cast<std::size_t>(std::count(declaration.begin(), declaration.end(), '\n')) + 1;
    kept_names = all_names.size();
    body = trial_body;
    ++made.kept;
  }
  if (made.kept == 0) {
    return make_error<TypeLibraryMakeResult>(Status::InvalidInput, "typelib_make.empty",
                                             "no declaration of the input was kept");
  }
  // The header holds one line per record: stay well inside the reader's line bound.
  const std::size_t records = options.source_files.size() + options.macros.size() +
                              made.skipped.size() + options.notes.size();
  if (records + 32 > kMaxTypeLibraryHeaderLines) {
    return make_error<TypeLibraryMakeResult>(
        Status::ResourceLimit, "typelib_make.too_many_skipped",
        std::to_string(made.skipped.size()) +
            " skipped declarations do not fit the header; generate from fewer headers");
  }
  auto declared = parse_c_declarations(body, TypeTable{}, parse_options);
  if (!declared) {
    return Result<TypeLibraryMakeResult>(declared.diagnostic());
  }

  std::string text = "donkey-typelib 1\n";
  const auto key = [&text](std::string_view name, const std::string& value) {
    text += std::string(name) + ": " + value + "\n";
  };
  key("library", options.library);
  key("library_version", options.library_version);
  key("platform", options.platform);
  key("architecture", options.architecture);
  key("abi", options.abi);
  key("data_model", options.data_model);
  key("pointer_size", std::to_string(options.pointer_size));
  key("long_size", std::to_string(options.long_size));
  key("char_is_signed", options.char_is_signed ? "true" : "false");
  key("source", options.source);
  key("source_sha256", options.source_sha256);
  key("licence", options.licence);
  key("licence_file", options.licence_file);
  key("licence_sha256", options.licence_sha256);
  key("generator", std::string(kTypeLibraryGenerator));
  key("generator_command", options.generator_command);
  key("preprocessor", options.preprocessor);
  key("created", options.created);
  key("body_sha256", hex_digest(body));
  key("declarations", std::to_string(declared.value().size()));
  for (const TypeLibrarySourceFile& file : options.source_files) {
    text += "source_file: " + file.path + " " + file.sha256 + "\n";
  }
  for (const TypeLibraryMacro& macro : options.macros) {
    text += "macro: " + macro.name + "=" + macro.value + "\n";
  }
  for (TypeLibrarySkipped& skipped : made.skipped) {
    // `skipped: ` + name + `: ` + reason stays within the header line bound.
    const std::size_t room = kMaxTypeLibraryHeaderLineBytes - 11 - skipped.name.size();
    skipped.reason = record_text(skipped.reason, room, true);
    text += "skipped: " + skipped.name + ": " + skipped.reason + "\n";
  }
  for (const std::string& note : options.notes) {
    text += "note: " + record_text(note, kMaxTypeLibraryHeaderLineBytes - 6, true) + "\n";
  }
  text += "\n";
  text += body;

  // The library must read back: a text the reader refuses is never written.
  auto check = read_type_library(text, TypeTable{});
  if (!check) {
    return Result<TypeLibraryMakeResult>(check.diagnostic());
  }
  made.text = std::move(text);
  return made;
}

}  // namespace donkey
