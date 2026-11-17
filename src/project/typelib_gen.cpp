#include "donkey/project/typelib_gen.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
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
  static const std::set<std::string_view> kDropped{
      "restrict", "__restrict", "__restrict__", "__extension__", "__inline", "__inline__",
      "_Noreturn", "__volatile__", "__const"};
  return kDropped.contains(word);
}

/// Words followed by a parenthesised argument that is removed with them.
bool dropped_call(std::string_view word) {
  return word == "__attribute__" || word == "__attribute" || word == "__asm__" ||
         word == "__asm" || word == "asm" || word == "__declspec";
}

/// The index just past the parenthesised group that starts at the first '(' at or after `at`.
std::size_t skip_group(std::string_view text, std::size_t at) {
  while (at < text.size() && std::isspace(static_cast<unsigned char>(text[at])) != 0) {
    ++at;
  }
  if (at >= text.size() || text[at] != '(') {
    return at;
  }
  int depth = 0;
  for (; at < text.size(); ++at) {
    if (text[at] == '(') {
      ++depth;
    } else if (text[at] == ')' && --depth == 0) {
      return at + 1;
    }
  }
  return at;
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
    if (is_ident_start(c)) {
      while (next < text.size() && is_ident_char(text[next])) {
        ++next;
      }
      const std::string_view word = text.substr(i, next - i);
      if (dropped_word(word)) {
        i = next;
        space = true;
        continue;
      }
      if (dropped_call(word)) {
        i = skip_group(text, next);
        space = true;
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
  return Sha256::hex(std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()),
                                                text.size()));
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
    line_start = c == '\n';
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

Result<TypeLibraryMakeResult> make_type_library(std::string_view preprocessed,
                                                const TypeLibraryMakeOptions& options) {
  CDeclarationOptions parse_options;
  parse_options.pointer_size = options.pointer_size;
  parse_options.long_size = options.long_size;
  parse_options.char_is_signed = options.char_is_signed;

  TypeLibraryMakeResult made;
  TypeTable kept_types;
  std::set<std::string> tags;
  std::set<std::string> ordinary;
  std::string body;
  for (const std::string& declaration : split_c_declarations(preprocessed)) {
    const std::string name = record_text(name_of(declaration), 96, false);
    if (declaration.find('{') != std::string::npos &&
        declaration.back() == '}') {
      made.skipped.push_back({name, "a function definition (only declarations are kept)"});
      continue;
    }
    std::vector<CDeclaredName> names;
    auto parsed = parse_c_declarations(declaration, kept_types, parse_options, &names);
    if (!parsed) {
      made.skipped.push_back(
          {name, parsed.diagnostic().code + " " + parsed.diagnostic().message});
      continue;
    }
    if (names.empty()) {
      made.skipped.push_back({name, "declares no type, typedef or function"});
      continue;
    }
    bool repeated = false;
    for (const CDeclaredName& declared : names) {
      const auto& space = declared.space == CNameSpace::Tag ? tags : ordinary;
      repeated = repeated || space.contains(declared.name);
    }
    if (repeated) {
      made.skipped.push_back({name, "declared again (the first declaration is kept)"});
      continue;
    }
    // The kept text must parse on its own, as the reader parses it: a struct with a member of a
    // type that was skipped (an incomplete type) parses against the kept table, which knows the
    // type from a pointer, but not as part of the whole text.
    const std::string trial_body = body + declaration + "\n";
    auto whole = parse_c_declarations(trial_body, TypeTable{}, parse_options);
    if (!whole) {
      made.skipped.push_back(
          {name, whole.diagnostic().code + " (with the kept declarations) " +
                     whole.diagnostic().message});
      continue;
    }
    TypeTable trial = kept_types;
    for (const TypeDefinition& definition : parsed.value()) {
      trial.put(definition);
    }
    for (const CDeclaredName& declared : names) {
      (declared.space == CNameSpace::Tag ? tags : ordinary).insert(declared.name);
    }
    kept_types = std::move(trial);
    body += declaration;
    body += '\n';
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
