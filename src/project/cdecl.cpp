#include "donkey/project/cdecl.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace donkey {
namespace {

// ---- diagnostics ----------------------------------------------------------------------

template <typename T>
Result<T> located(std::uint32_t line, std::uint32_t column, std::string code,
                  const std::string& message) {
  return make_error<T>(
      Status::InvalidInput, std::move(code),
      "line " + std::to_string(line) + ", column " + std::to_string(column) + ": " + message);
}

/// Carries a failure from one result type to another, keeping its code and message.
template <typename T, typename U>
Result<T> propagate(const Result<U>& failed) {
  const Diagnostic& diagnostic = failed.diagnostic();
  return make_error<T>(diagnostic.status, diagnostic.code, diagnostic.message);
}

// ---- lexical analysis -----------------------------------------------------------------

struct Token {
  enum class Kind : std::uint8_t { Identifier, Number, Symbol, End };
  Kind kind = Kind::End;
  std::string text;
  std::uint64_t number = 0;
  std::uint32_t line = 1;
  std::uint32_t column = 1;
};

bool is_identifier_start(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool is_digit(char c) {
  return c >= '0' && c <= '9';
}

bool is_hex_digit(char c) {
  return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

std::uint64_t hex_value(char c) {
  if (is_digit(c)) {
    return static_cast<std::uint64_t>(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return static_cast<std::uint64_t>(c - 'a' + 10);
  }
  return static_cast<std::uint64_t>(c - 'A' + 10);
}

/// Reads an integer literal starting at `i`. Integer suffixes are skipped: they do not
/// change a type in this subset.
Result<void> scan_number(std::string_view text, std::size_t& i, Token& token) {
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  const std::size_t start = i;
  std::uint64_t value = 0;
  const bool hex =
      text[i] == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X');
  if (hex) {
    i += 2;
    if (i >= text.size() || !is_hex_digit(text[i])) {
      return located<void>(token.line, token.column, "cdecl.bad_number",
                           "a hexadecimal number needs digits");
    }
    while (i < text.size() && is_hex_digit(text[i])) {
      if (value > (kMax >> 4U)) {
        return located<void>(token.line, token.column, "cdecl.number_too_large",
                             "the number does not fit in 64 bits");
      }
      value = value * 16 + hex_value(text[i]);
      ++i;
    }
  } else {
    if (text[i] == '0' && i + 1 < text.size() && is_digit(text[i + 1])) {
      return located<void>(token.line, token.column, "cdecl.octal_unsupported",
                           "octal numbers are not supported");
    }
    while (i < text.size() && is_digit(text[i])) {
      const auto digit = static_cast<std::uint64_t>(text[i] - '0');
      if (value > (kMax - digit) / 10) {
        return located<void>(token.line, token.column, "cdecl.number_too_large",
                             "the number does not fit in 64 bits");
      }
      value = value * 10 + digit;
      ++i;
    }
  }
  while (i < text.size() &&
         (text[i] == 'u' || text[i] == 'U' || text[i] == 'l' || text[i] == 'L')) {
    ++i;
  }
  token.kind = Token::Kind::Number;
  token.text = std::string(text.substr(start, i - start));
  token.number = value;
  return Result<void>();
}

/// Splits the text into tokens, each with its line and column. Comments are skipped.
/// A preprocessor line is an error rather than something to ignore.
Result<std::vector<Token>> tokenize(std::string_view text) {
  std::vector<Token> tokens;
  std::uint32_t line = 1;
  std::size_t line_start = 0;  // offset of the first byte of the current line
  bool at_line_start = true;
  std::size_t i = 0;
  const auto column_at = [&](std::size_t offset) {
    return static_cast<std::uint32_t>(offset - line_start + 1);
  };

  while (true) {
    while (i < text.size()) {
      const char c = text[i];
      if (c == '\n') {
        ++i;
        ++line;
        line_start = i;
        at_line_start = true;
      } else if (c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v') {
        ++i;
      } else if (c == '/' && i + 1 < text.size() && text[i + 1] == '/') {
        while (i < text.size() && text[i] != '\n') {
          ++i;
        }
      } else if (c == '/' && i + 1 < text.size() && text[i + 1] == '*') {
        const std::uint32_t start_line = line;
        const std::uint32_t start_column = column_at(i);
        i += 2;
        bool closed = false;
        while (i < text.size()) {
          if (text[i] == '*' && i + 1 < text.size() && text[i + 1] == '/') {
            i += 2;
            closed = true;
            break;
          }
          if (text[i] == '\n') {
            ++line;
            line_start = i + 1;
            at_line_start = true;
          }
          ++i;
        }
        if (!closed) {
          return located<std::vector<Token>>(start_line, start_column, "cdecl.unterminated_comment",
                                             "a comment is not closed");
        }
      } else {
        break;
      }
    }

    if (i >= text.size()) {
      Token end;
      end.line = line;
      end.column = column_at(i);
      tokens.push_back(end);
      return tokens;
    }

    Token token;
    token.line = line;
    token.column = column_at(i);
    const char c = text[i];
    if (c == '#' && at_line_start) {
      return located<std::vector<Token>>(token.line, token.column, "cdecl.preprocessor",
                                         "preprocessor directives are not supported");
    }
    at_line_start = false;

    if (is_identifier_start(c)) {
      const std::size_t start = i;
      while (i < text.size() && (is_identifier_start(text[i]) || is_digit(text[i]))) {
        ++i;
      }
      token.kind = Token::Kind::Identifier;
      token.text = std::string(text.substr(start, i - start));
    } else if (is_digit(c)) {
      if (auto number = scan_number(text, i, token); !number) {
        return propagate<std::vector<Token>>(number);
      }
    } else if (c == '.' && i + 2 < text.size() && text[i + 1] == '.' && text[i + 2] == '.') {
      token.kind = Token::Kind::Symbol;
      token.text = "...";
      i += 3;
    } else if (std::string_view("{}()[];,*=:-+").find(c) != std::string_view::npos) {
      token.kind = Token::Kind::Symbol;
      token.text = std::string(1, c);
      ++i;
    } else {
      return located<std::vector<Token>>(
          token.line, token.column, "cdecl.bad_character",
          std::string("the character '") + c + "' is not part of the C subset");
    }
    tokens.push_back(std::move(token));
  }
}

/// Keywords that cannot be a type name or a declarator name in this subset.
bool is_keyword(const std::string& word) {
  static const std::set<std::string, std::less<>> kKeywords = {
      "auto",    "break",    "case",      "char",     "const",          "continue",     "default",
      "do",      "double",   "else",      "enum",     "extern",         "float",        "for",
      "goto",    "if",       "inline",    "int",      "long",           "register",     "restrict",
      "return",  "short",    "signed",    "sizeof",   "static",         "struct",       "switch",
      "typedef", "union",    "unsigned",  "void",     "volatile",       "while",        "_Bool",
      "_Atomic", "_Complex", "_Noreturn", "_Alignas", "_Static_assert", "_Thread_local"};
  return kKeywords.count(word) != 0;
}

struct FixedInteger {
  std::uint64_t size = 0;
  bool is_signed = false;
};

/// The fixed-width names of <stdint.h> and <stddef.h>.
std::optional<FixedInteger> fixed_width_integer(const std::string& word,
                                                const CDeclarationOptions& options) {
  if (word == "int8_t") return FixedInteger{1, true};
  if (word == "uint8_t") return FixedInteger{1, false};
  if (word == "int16_t") return FixedInteger{2, true};
  if (word == "uint16_t") return FixedInteger{2, false};
  if (word == "int32_t") return FixedInteger{4, true};
  if (word == "uint32_t") return FixedInteger{4, false};
  if (word == "int64_t") return FixedInteger{8, true};
  if (word == "uint64_t") return FixedInteger{8, false};
  if (word == "intptr_t" || word == "ptrdiff_t") return FixedInteger{options.pointer_size, true};
  if (word == "uintptr_t" || word == "size_t") return FixedInteger{options.pointer_size, false};
  return std::nullopt;
}

std::optional<std::uint64_t> round_up_checked(std::uint64_t value, std::uint64_t alignment) {
  if (value > std::numeric_limits<std::uint64_t>::max() - (alignment - 1)) {
    return std::nullopt;
  }
  return (value + alignment - 1) / alignment * alignment;
}

// ---- parsing --------------------------------------------------------------------------

struct SizeAlign {
  std::uint64_t size = 0;
  std::uint64_t alignment = 1;
};

struct DeclSpec {
  TypeId type{};  ///< invalid for void
  bool is_typedef = false;
  /// Set when the specifiers define an untagged struct, union or enum, so that
  /// `typedef struct { ... } name;` can name it after the typedef.
  TypeId anonymous{};
};

struct TagRef {
  TypeId id{};
  bool anonymous = false;
};

struct Declarator {
  std::string name;
  TypeId type{};
  bool is_function = false;
  std::uint32_t line = 1;
  std::uint32_t column = 1;
};

struct Suffix {
  bool is_function = false;
  bool unknown_count = false;
  std::uint64_t count = 0;
  std::vector<TypeField> parameters;
  bool variadic = false;
  std::uint32_t line = 1;
  std::uint32_t column = 1;
};

class Parser {
 public:
  Parser(std::vector<Token> tokens, const TypeTable& known, const CDeclarationOptions& options)
      : tokens_(std::move(tokens)), options_(options), working_(known), next_(known.next_id()) {
    for (const TypeDefinition& definition : known.list()) {
      if (definition.name.empty()) {
        continue;
      }
      switch (definition.kind) {
        case TypeKind::Struct:
          struct_tags_.emplace(definition.name, definition.id);
          break;
        case TypeKind::Union:
          union_tags_.emplace(definition.name, definition.id);
          break;
        case TypeKind::Enum:
          enum_tags_.emplace(definition.name, definition.id);
          break;
        case TypeKind::Typedef:
          typedef_names_.emplace(definition.name, definition.id);
          break;
        case TypeKind::Integer:
        case TypeKind::Float:
          scalars_.emplace(definition.name, definition.id);
          break;
        default:
          break;
      }
    }
  }

  Result<std::vector<TypeDefinition>> run() {
    while (!at_end()) {
      if (auto declared = parse_external_declaration(); !declared) {
        return propagate<std::vector<TypeDefinition>>(declared);
      }
    }
    return out_;
  }

 private:
  // ---- tokens ---------------------------------------------------------------------

  [[nodiscard]] const Token& peek(std::size_t ahead = 0) const {
    const std::size_t index = pos_ + ahead;
    return tokens_[index < tokens_.size() ? index : tokens_.size() - 1];
  }

  void advance() {
    if (pos_ + 1 < tokens_.size()) {
      ++pos_;
    }
  }

  [[nodiscard]] bool at_end() const { return peek().kind == Token::Kind::End; }

  [[nodiscard]] bool at_symbol(const char* symbol, std::size_t ahead = 0) const {
    return peek(ahead).kind == Token::Kind::Symbol && peek(ahead).text == symbol;
  }

  [[nodiscard]] bool at_word(const char* word) const {
    return peek().kind == Token::Kind::Identifier && peek().text == word;
  }

  template <typename T>
  Result<T> unexpected(const std::string& expected) const {
    const Token& token = peek();
    const std::string found =
        token.kind == Token::Kind::End ? "the end of the input" : "'" + token.text + "'";
    return located<T>(token.line, token.column, "cdecl.unexpected_token",
                      "expected " + expected + ", found " + found);
  }

  Result<void> expect(const char* symbol) {
    if (!at_symbol(symbol)) {
      return unexpected<void>(std::string("'") + symbol + "'");
    }
    advance();
    return Result<void>();
  }

  template <typename T>
  Result<T> nesting_error(const Token& at) const {
    return located<T>(at.line, at.column, "cdecl.nesting",
                      "the declaration nests deeper than 64 levels");
  }

  // ---- the type table being built ---------------------------------------------------

  TypeId add(TypeDefinition definition) {
    definition.id = next_;
    next_ = TypeId(next_.value() + 1);
    working_.put(definition);
    out_.push_back(definition);
    return definition.id;
  }

  /// Replaces a type this parse created. Types from the known table are never replaced.
  void replace(const TypeDefinition& definition) {
    working_.put(definition);
    for (TypeDefinition& existing : out_) {
      if (existing.id == definition.id) {
        existing = definition;
        return;
      }
    }
    out_.push_back(definition);
  }

  /// Whether the type has a size: an object of it can be declared. A struct or union
  /// still being defined is not complete, and neither is a function or void.
  [[nodiscard]] bool is_complete(TypeId id, int depth = 0) const {
    if (!id.valid() || depth > kMaxCDeclarationNesting) {
      return false;
    }
    const TypeDefinition* definition = working_.find(id);
    if (definition == nullptr) {
      return false;
    }
    switch (definition->kind) {
      case TypeKind::Struct:
      case TypeKind::Union:
        return incomplete_.count(id) == 0;
      case TypeKind::Array:
      case TypeKind::Typedef:
        return is_complete(definition->target, depth + 1);
      case TypeKind::Function:
      case TypeKind::Void:
        return false;
      default:
        return true;
    }
  }

  [[nodiscard]] std::optional<SizeAlign> measure(TypeId id) const {
    if (!is_complete(id)) {
      return std::nullopt;
    }
    const auto size = working_.size_of(id);
    const auto alignment = working_.alignment_of(id);
    if (!size || !alignment) {
      return std::nullopt;
    }
    return SizeAlign{size.value(), alignment.value()};
  }

  TypeId make_pointer(TypeId target) {
    TypeDefinition pointer;
    pointer.kind = TypeKind::Pointer;
    pointer.size = options_.pointer_size;
    pointer.target = target;
    return add(std::move(pointer));
  }

  Result<TypeId> make_array(TypeId element, std::uint64_t count, std::uint32_t line,
                            std::uint32_t column) {
    if (!is_complete(element)) {
      return located<TypeId>(line, column, "cdecl.incomplete_type",
                             "an array needs an element type with a known size");
    }
    TypeDefinition array;
    array.kind = TypeKind::Array;
    array.target = element;
    array.count = count;
    return add(std::move(array));
  }

  /// A parameter of array or function type is adjusted to a pointer, as in C.
  TypeId decay(TypeId type) {
    const TypeDefinition* definition = working_.find(type);
    if (definition == nullptr) {
      return type;
    }
    if (definition->kind == TypeKind::Array) {
      return make_pointer(definition->target);
    }
    if (definition->kind == TypeKind::Function) {
      return make_pointer(type);
    }
    return type;
  }

  /// An integer or float type with the given name and layout. A matching type that
  /// the known table already has is reused, so the output does not duplicate it.
  TypeId scalar(const std::string& name, TypeKind kind, std::uint64_t size, bool is_signed) {
    const auto cached = scalars_.find(name);
    if (cached != scalars_.end()) {
      const TypeDefinition* existing = working_.find(cached->second);
      if (existing != nullptr && existing->kind == kind && existing->size == size &&
          existing->is_signed == is_signed) {
        return cached->second;
      }
    }
    TypeDefinition definition;
    definition.kind = kind;
    definition.name = name;
    definition.size = size;
    definition.is_signed = is_signed;
    const TypeId id = add(std::move(definition));
    scalars_[name] = id;
    return id;
  }

  // ---- declaration specifiers -----------------------------------------------------

  Result<DeclSpec> parse_decl_specifiers() {
    int shorts = 0;
    int longs = 0;
    int keywords = 0;
    bool is_signed = false;
    bool is_unsigned = false;
    bool is_char = false;
    bool is_int = false;
    bool is_void = false;
    bool is_bool = false;
    bool is_float = false;
    bool is_double = false;
    bool is_typedef = false;
    std::optional<TypeId> named;
    TypeId anonymous{};
    const std::uint32_t line = peek().line;
    const std::uint32_t column = peek().column;

    while (peek().kind == Token::Kind::Identifier) {
      const std::string word = peek().text;
      if (word == "const" || word == "volatile" || word == "restrict" || word == "_Atomic" ||
          word == "extern" || word == "static" || word == "inline") {
        advance();  // qualifiers and storage classes that do not change the type here
        continue;
      }
      if (word == "typedef") {
        is_typedef = true;
        advance();
        continue;
      }
      const bool base_keyword = word == "void" || word == "_Bool" || word == "char" ||
                                word == "short" || word == "int" || word == "long" ||
                                word == "float" || word == "double" || word == "signed" ||
                                word == "unsigned";
      if (base_keyword) {
        if (named) {
          break;  // a typedef name already supplies the type
        }
        ++keywords;
        if (word == "void") is_void = true;
        if (word == "_Bool") is_bool = true;
        if (word == "char") is_char = true;
        if (word == "short") ++shorts;
        if (word == "int") is_int = true;
        if (word == "long") ++longs;
        if (word == "float") is_float = true;
        if (word == "double") is_double = true;
        if (word == "signed") is_signed = true;
        if (word == "unsigned") is_unsigned = true;
        advance();
        continue;
      }
      if (word == "struct" || word == "union" || word == "enum") {
        if (named || keywords > 0) {
          return located<DeclSpec>(peek().line, peek().column, "cdecl.bad_specifiers",
                                   "a type has two type specifiers");
        }
        auto tag = parse_tag(word);
        if (!tag) {
          return propagate<DeclSpec>(tag);
        }
        named = tag.value().id;
        if (tag.value().anonymous) {
          anonymous = tag.value().id;
        }
        continue;
      }
      if (named || keywords > 0) {
        break;  // this identifier is the declarator's name
      }
      if (const auto typedef_name = typedef_names_.find(word);
          typedef_name != typedef_names_.end()) {
        named = typedef_name->second;
        advance();
        continue;
      }
      if (const auto fixed = fixed_width_integer(word, options_)) {
        named = scalar(word, TypeKind::Integer, fixed->size, fixed->is_signed);
        advance();
        continue;
      }
      break;
    }

    DeclSpec spec;
    spec.is_typedef = is_typedef;
    spec.anonymous = anonymous;
    if (named) {
      if (keywords > 0) {
        return located<DeclSpec>(line, column, "cdecl.bad_specifiers",
                                 "a type name cannot be combined with other type specifiers");
      }
      spec.type = *named;
      return spec;
    }
    if (keywords == 0) {
      if (peek().kind == Token::Kind::Identifier && !is_keyword(peek().text)) {
        return located<DeclSpec>(peek().line, peek().column, "cdecl.unknown_type",
                                 "'" + peek().text + "' is not a type");
      }
      return unexpected<DeclSpec>("a type name");
    }

    if (is_void || is_bool || is_float) {
      if (keywords != 1) {
        return located<DeclSpec>(line, column, "cdecl.bad_specifiers",
                                 "this type takes no other type specifier");
      }
      if (is_void) {
        spec.type = TypeId{};
      } else if (is_bool) {
        spec.type = scalar("_Bool", TypeKind::Integer, 1, false);
      } else {
        spec.type = scalar("float", TypeKind::Float, 4, false);
      }
      return spec;
    }
    if (is_double) {
      if (is_char || is_int || shorts > 0 || is_signed || is_unsigned || longs > 1) {
        return located<DeclSpec>(line, column, "cdecl.bad_specifiers",
                                 "'double' takes only 'long' as well");
      }
      spec.type = longs == 1 ? scalar("long double", TypeKind::Float, 16, false)
                             : scalar("double", TypeKind::Float, 8, false);
      return spec;
    }
    if (is_char && (shorts > 0 || longs > 0 || is_int)) {
      return located<DeclSpec>(line, column, "cdecl.bad_specifiers",
                               "'char' takes only 'signed' or 'unsigned'");
    }
    if ((is_signed && is_unsigned) || shorts > 1 || longs > 2 || (shorts > 0 && longs > 0)) {
      return located<DeclSpec>(line, column, "cdecl.bad_specifiers",
                               "these integer type specifiers do not combine");
    }
    if (is_char) {
      if (is_unsigned) {
        spec.type = scalar("unsigned char", TypeKind::Integer, 1, false);
      } else if (is_signed) {
        spec.type = scalar("signed char", TypeKind::Integer, 1, true);
      } else {
        spec.type = scalar("char", TypeKind::Integer, 1, options_.char_is_signed);
      }
      return spec;
    }
    if (shorts > 0) {
      spec.type =
          scalar(is_unsigned ? "unsigned short" : "short", TypeKind::Integer, 2, !is_unsigned);
      return spec;
    }
    if (longs == 2) {
      spec.type = scalar(is_unsigned ? "unsigned long long" : "long long", TypeKind::Integer, 8,
                         !is_unsigned);
      return spec;
    }
    if (longs == 1) {
      spec.type = scalar(is_unsigned ? "unsigned long" : "long", TypeKind::Integer,
                         options_.long_size, !is_unsigned);
      return spec;
    }
    spec.type = scalar(is_unsigned ? "unsigned int" : "int", TypeKind::Integer, 4, !is_unsigned);
    return spec;
  }

  /// `struct tag { ... }`, `struct tag`, the same for `union`, and `enum`.
  Result<TagRef> parse_tag(const std::string& keyword) {
    advance();  // the keyword
    const std::uint32_t line = peek().line;
    const std::uint32_t column = peek().column;
    std::string tag;
    if (peek().kind == Token::Kind::Identifier && !is_keyword(peek().text)) {
      tag = peek().text;
      advance();
    }
    const bool defines = at_symbol("{");

    if (keyword == "enum") {
      if (defines) {
        auto id = parse_enum_body(tag, line, column);
        if (!id) {
          return propagate<TagRef>(id);
        }
        return TagRef{id.value(), tag.empty()};
      }
      if (tag.empty()) {
        return located<TagRef>(line, column, "cdecl.unknown_tag", "an enum needs a tag or a body");
      }
      const auto known = enum_tags_.find(tag);
      if (known == enum_tags_.end()) {
        return located<TagRef>(line, column, "cdecl.unknown_tag", "no enum named '" + tag + "'");
      }
      return TagRef{known->second, false};
    }

    const bool is_union = keyword == "union";
    auto& tags = is_union ? union_tags_ : struct_tags_;
    if (defines) {
      if (nesting_ >= kMaxCDeclarationNesting) {
        return located<TagRef>(line, column, "cdecl.nesting",
                               "the declaration nests deeper than 64 levels");
      }
      TypeId id{};
      if (!tag.empty()) {
        const auto known = tags.find(tag);
        if (known != tags.end()) {
          if (incomplete_.count(known->second) == 0) {
            return located<TagRef>(line, column, "cdecl.redefinition",
                                   "'" + tag + "' is already defined");
          }
          id = known->second;  // completes an earlier forward declaration
        }
      }
      if (!id.valid()) {
        TypeDefinition shell;
        shell.kind = is_union ? TypeKind::Union : TypeKind::Struct;
        shell.name = tag;
        id = add(std::move(shell));
        if (!tag.empty()) {
          tags.emplace(tag, id);
        }
      }
      incomplete_.insert(id);
      ++nesting_;
      auto body = parse_struct_body(id, is_union, tag);
      --nesting_;
      if (!body) {
        return propagate<TagRef>(body);
      }
      incomplete_.erase(id);
      return TagRef{id, tag.empty()};
    }

    if (tag.empty()) {
      return located<TagRef>(line, column, "cdecl.unknown_tag",
                             "a " + keyword + " needs a tag or a body");
    }
    if (const auto known = tags.find(tag); known != tags.end()) {
      return TagRef{known->second, false};
    }
    // A reference to a tag not yet defined is a forward declaration, completed later.
    TypeDefinition shell;
    shell.kind = is_union ? TypeKind::Union : TypeKind::Struct;
    shell.name = tag;
    const TypeId id = add(std::move(shell));
    tags.emplace(tag, id);
    incomplete_.insert(id);
    return TagRef{id, false};
  }

  Result<TypeId> parse_struct_body(TypeId id, bool is_union, const std::string& tag) {
    if (auto open = expect("{"); !open) {
      return propagate<TypeId>(open);
    }
    std::vector<TypeField> fields;
    std::uint64_t end = 0;
    std::uint64_t alignment = 1;
    while (!at_symbol("}")) {
      if (at_end()) {
        return unexpected<TypeId>("'}'");
      }
      auto spec = parse_decl_specifiers();
      if (!spec) {
        return propagate<TypeId>(spec);
      }
      if (spec.value().is_typedef) {
        return located<TypeId>(peek().line, peek().column, "cdecl.typedef_in_struct",
                               "a typedef cannot be a member");
      }
      if (at_symbol(";")) {
        return located<TypeId>(peek().line, peek().column, "cdecl.anonymous_member",
                               "a member without a name is not supported");
      }
      while (true) {
        auto decl = parse_declarator(spec.value().type, /*abstract_allowed=*/false, /*depth=*/0,
                                     /*parameter=*/false);
        if (!decl) {
          return propagate<TypeId>(decl);
        }
        const Declarator member = decl.value();
        if (member.is_function) {
          return located<TypeId>(member.line, member.column, "cdecl.function_member",
                                 "a member cannot be a function");
        }
        if (at_symbol(":")) {
          return located<TypeId>(peek().line, peek().column, "cdecl.bitfield_unsupported",
                                 "bit-fields are not supported");
        }
        const auto layout = measure(member.type);
        if (!layout) {
          return located<TypeId>(member.line, member.column, "cdecl.incomplete_type",
                                 "member '" + member.name + "' has a type whose size is not known");
        }
        std::uint64_t offset = 0;
        if (is_union) {
          end = std::max(end, layout->size);
        } else {
          const auto aligned = round_up_checked(end, layout->alignment);
          if (!aligned || *aligned > std::numeric_limits<std::uint64_t>::max() - layout->size) {
            return located<TypeId>(member.line, member.column, "cdecl.too_large",
                                   "the struct is larger than 64 bits can count");
          }
          offset = *aligned;
          end = offset + layout->size;
        }
        alignment = std::max(alignment, layout->alignment);
        TypeField field;
        field.name = member.name;
        field.offset = offset;
        field.type = member.type;
        fields.push_back(std::move(field));
        if (at_symbol(",")) {
          advance();
          continue;
        }
        break;
      }
      if (auto semicolon = expect(";"); !semicolon) {
        return propagate<TypeId>(semicolon);
      }
    }
    advance();  // the closing '}'

    const auto size = round_up_checked(end, alignment);
    if (!size) {
      return located<TypeId>(peek().line, peek().column, "cdecl.too_large",
                             "the " + std::string(is_union ? "union" : "struct") +
                                 " is larger than 64 bits can count");
    }
    TypeDefinition definition;
    if (const TypeDefinition* current = working_.find(id)) {
      definition = *current;
    }
    definition.id = id;
    definition.kind = is_union ? TypeKind::Union : TypeKind::Struct;
    definition.name = tag;
    definition.size = *size;
    definition.fields = std::move(fields);
    replace(definition);
    return id;
  }

  Result<TypeId> parse_enum_body(const std::string& tag, std::uint32_t line, std::uint32_t column) {
    if (!tag.empty() && enum_tags_.count(tag) != 0) {
      return located<TypeId>(line, column, "cdecl.redefinition",
                             "'" + tag + "' is already defined");
    }
    advance();  // '{'
    constexpr std::int64_t kInt32Min = std::numeric_limits<std::int32_t>::min();
    constexpr std::int64_t kInt32Max = std::numeric_limits<std::int32_t>::max();
    TypeDefinition definition;
    definition.kind = TypeKind::Enum;
    definition.name = tag;
    definition.size = 4;
    std::int64_t next_value = 0;
    while (!at_symbol("}")) {
      if (peek().kind != Token::Kind::Identifier || is_keyword(peek().text)) {
        return unexpected<TypeId>("an enumerator name");
      }
      TypeEnumerator enumerator;
      enumerator.name = peek().text;
      const std::uint32_t name_line = peek().line;
      const std::uint32_t name_column = peek().column;
      advance();
      if (at_symbol("=")) {
        advance();
        bool negative = false;
        if (at_symbol("-")) {
          negative = true;
          advance();
        } else if (at_symbol("+")) {
          advance();
        }
        if (peek().kind != Token::Kind::Number) {
          return unexpected<TypeId>("an integer constant");
        }
        const std::uint64_t magnitude = peek().number;
        const auto limit = static_cast<std::uint64_t>(negative ? -kInt32Min : kInt32Max);
        if (magnitude > limit) {
          return located<TypeId>(peek().line, peek().column, "cdecl.enum_value_range",
                                 "an enumerator value must fit in 32 bits");
        }
        next_value =
            negative ? -static_cast<std::int64_t>(magnitude) : static_cast<std::int64_t>(magnitude);
        advance();
      }
      if (next_value < kInt32Min || next_value > kInt32Max) {
        return located<TypeId>(name_line, name_column, "cdecl.enum_value_range",
                               "an enumerator value must fit in 32 bits");
      }
      enumerator.value = next_value;
      definition.enumerators.push_back(enumerator);
      ++next_value;
      if (at_symbol(",")) {
        advance();
        continue;
      }
      break;
    }
    if (definition.enumerators.empty()) {
      return unexpected<TypeId>("an enumerator name");
    }
    if (auto close = expect("}"); !close) {
      return propagate<TypeId>(close);
    }
    const TypeId id = add(std::move(definition));
    if (!tag.empty()) {
      enum_tags_.emplace(tag, id);
    }
    return id;
  }

  // ---- declarators ----------------------------------------------------------------

  Result<Declarator> parse_declarator(TypeId base, bool abstract_allowed, int depth,
                                      bool parameter) {
    Declarator declarator;
    declarator.type = base;
    while (at_symbol("*")) {
      if (++depth > kMaxCDeclarationNesting) {
        return nesting_error<Declarator>(peek());
      }
      advance();
      while (at_word("const") || at_word("volatile") || at_word("restrict")) {
        advance();
      }
      declarator.type = make_pointer(declarator.type);
    }
    if (at_symbol("(")) {
      return located<Declarator>(peek().line, peek().column, "cdecl.parenthesized_declarator",
                                 "a parenthesised declarator, as in a function pointer, is not "
                                 "supported");
    }
    declarator.line = peek().line;
    declarator.column = peek().column;
    if (peek().kind == Token::Kind::Identifier && !is_keyword(peek().text)) {
      declarator.name = peek().text;
      advance();
    } else if (!abstract_allowed) {
      return unexpected<Declarator>("a name");
    }

    // Suffixes are listed from the outermost to the innermost: in `a[2][3]` the first
    // dimension is 2. They apply to the base type from the innermost outwards.
    std::vector<Suffix> suffixes;
    while (at_symbol("[") || at_symbol("(")) {
      if (++depth > kMaxCDeclarationNesting) {
        return nesting_error<Declarator>(peek());
      }
      Suffix suffix;
      suffix.line = peek().line;
      suffix.column = peek().column;
      if (at_symbol("[")) {
        advance();
        if (at_symbol("]")) {
          suffix.unknown_count = true;
        } else {
          if (peek().kind != Token::Kind::Number) {
            return unexpected<Declarator>("an array size");
          }
          suffix.count = peek().number;
          advance();
        }
        if (auto close = expect("]"); !close) {
          return propagate<Declarator>(close);
        }
      } else {
        suffix.is_function = true;
        if (auto params = parse_parameters(suffix.parameters, suffix.variadic, depth); !params) {
          return propagate<Declarator>(params);
        }
      }
      suffixes.push_back(std::move(suffix));
    }

    for (const Suffix& suffix : suffixes) {
      if (suffix.is_function && suffixes.size() > 1) {
        return located<Declarator>(suffix.line, suffix.column, "cdecl.bad_declarator",
                                   "a function cannot return an array or a function");
      }
    }
    for (std::size_t index = suffixes.size(); index-- > 0;) {
      const Suffix& suffix = suffixes[index];
      if (suffix.is_function) {
        const TypeDefinition* returned = working_.find(declarator.type);
        if (returned != nullptr &&
            (returned->kind == TypeKind::Array || returned->kind == TypeKind::Function)) {
          return located<Declarator>(suffix.line, suffix.column, "cdecl.bad_declarator",
                                     "a function cannot return an array or a function");
        }
        TypeDefinition function;
        function.kind = TypeKind::Function;
        function.target = declarator.type;
        function.fields = suffix.parameters;
        function.variadic = suffix.variadic;
        declarator.type = add(std::move(function));
        declarator.is_function = true;
        continue;
      }
      if (suffix.unknown_count) {
        // Only the outermost dimension of a parameter may leave its size out; it is a
        // pointer to the element.
        if (!parameter || index != 0) {
          return located<Declarator>(suffix.line, suffix.column, "cdecl.array_size_required",
                                     "an array needs a size, except the outermost dimension "
                                     "of a parameter");
        }
        if (!is_complete(declarator.type)) {
          return located<Declarator>(suffix.line, suffix.column, "cdecl.incomplete_type",
                                     "an array needs an element type with a known size");
        }
        declarator.type = make_pointer(declarator.type);
        continue;
      }
      if (suffix.count == 0) {
        return located<Declarator>(suffix.line, suffix.column, "cdecl.array_size_required",
                                   "an array needs a size greater than zero");
      }
      auto array = make_array(declarator.type, suffix.count, suffix.line, suffix.column);
      if (!array) {
        return propagate<Declarator>(array);
      }
      declarator.type = array.value();
    }
    return declarator;
  }

  Result<void> parse_parameters(std::vector<TypeField>& parameters, bool& variadic, int depth) {
    if (depth > kMaxCDeclarationNesting) {
      return nesting_error<void>(peek());
    }
    if (auto open = expect("("); !open) {
      return propagate<void>(open);
    }
    if (at_symbol(")")) {
      advance();
      return Result<void>();
    }
    if (at_word("void") && at_symbol(")", 1)) {
      advance();
      advance();
      return Result<void>();
    }
    while (true) {
      if (at_symbol("...")) {
        if (parameters.empty()) {
          return located<void>(peek().line, peek().column, "cdecl.variadic_position",
                               "'...' needs a named parameter before it");
        }
        advance();
        variadic = true;
        if (!at_symbol(")")) {
          return located<void>(peek().line, peek().column, "cdecl.variadic_position",
                               "'...' must be the last parameter");
        }
        advance();
        return Result<void>();
      }
      auto spec = parse_decl_specifiers();
      if (!spec) {
        return propagate<void>(spec);
      }
      if (spec.value().is_typedef) {
        return located<void>(peek().line, peek().column, "cdecl.bad_specifiers",
                             "a parameter cannot be a typedef");
      }
      auto decl = parse_declarator(spec.value().type, /*abstract_allowed=*/true, depth,
                                   /*parameter=*/true);
      if (!decl) {
        return propagate<void>(decl);
      }
      const Declarator declared = decl.value();
      if (!declared.type.valid()) {
        return located<void>(declared.line, declared.column, "cdecl.bad_parameter",
                             "a parameter cannot be void");
      }
      const TypeId parameter_type = decay(declared.type);
      if (!is_complete(parameter_type)) {
        return located<void>(declared.line, declared.column, "cdecl.incomplete_type",
                             "a parameter needs a complete type");
      }
      TypeField field;
      field.name = declared.name;
      field.type = parameter_type;
      parameters.push_back(std::move(field));
      if (at_symbol(",")) {
        advance();
        continue;
      }
      break;
    }
    return expect(")");
  }

  // ---- top level ------------------------------------------------------------------

  Result<void> parse_external_declaration() {
    if (at_symbol(";")) {
      advance();
      return Result<void>();
    }
    auto spec = parse_decl_specifiers();
    if (!spec) {
      return propagate<void>(spec);
    }
    if (at_symbol(";")) {
      advance();  // a tag or enum declared with nothing else
      return Result<void>();
    }
    while (true) {
      auto decl = parse_declarator(spec.value().type, /*abstract_allowed=*/false, /*depth=*/0,
                                   /*parameter=*/false);
      if (!decl) {
        return propagate<void>(decl);
      }
      const Declarator declared = decl.value();
      if (spec.value().is_typedef) {
        if (typedef_names_.count(declared.name) != 0) {
          return located<void>(declared.line, declared.column, "cdecl.redefinition",
                               "'" + declared.name + "' is already a typedef");
        }
        if (spec.value().anonymous.valid() && declared.type == spec.value().anonymous) {
          // `typedef struct { ... } name;`: the untagged type takes the typedef's name.
          TypeDefinition named;
          if (const TypeDefinition* anonymous = working_.find(declared.type)) {
            named = *anonymous;
          }
          named.name = declared.name;
          replace(named);
          typedef_names_.emplace(declared.name, declared.type);
        } else {
          TypeDefinition typedef_definition;
          typedef_definition.kind = TypeKind::Typedef;
          typedef_definition.name = declared.name;
          typedef_definition.target = declared.type;
          const TypeId id = add(std::move(typedef_definition));
          typedef_names_.emplace(declared.name, id);
        }
      } else if (declared.is_function) {
        // A prototype: the function type takes the function's name.
        TypeDefinition named;
        if (const TypeDefinition* function = working_.find(declared.type)) {
          named = *function;
        }
        named.name = declared.name;
        replace(named);
      } else {
        return located<void>(declared.line, declared.column, "cdecl.variable",
                             "'" + declared.name +
                                 "' declares a variable; only types and function prototypes "
                                 "are in this subset");
      }
      if (at_symbol(",")) {
        advance();
        continue;
      }
      break;
    }
    return expect(";");
  }

  std::vector<Token> tokens_;
  std::size_t pos_ = 0;
  CDeclarationOptions options_;
  TypeTable working_;
  TypeId next_{};
  std::vector<TypeDefinition> out_;
  std::map<std::string, TypeId> struct_tags_;
  std::map<std::string, TypeId> union_tags_;
  std::map<std::string, TypeId> enum_tags_;
  std::map<std::string, TypeId> typedef_names_;
  std::map<std::string, TypeId> scalars_;
  std::set<TypeId> incomplete_;
  int nesting_ = 0;  ///< struct and union bodies being parsed
};

}  // namespace

Result<std::vector<TypeDefinition>> parse_c_declarations(std::string_view text,
                                                         const TypeTable& known,
                                                         const CDeclarationOptions& options) {
  if (text.size() > kMaxCDeclarationBytes) {
    return make_error<std::vector<TypeDefinition>>(Status::ResourceLimit, "cdecl.too_large",
                                                   "the declarations are larger than 1 MiB");
  }
  if (options.pointer_size != 4 && options.pointer_size != 8) {
    return make_error<std::vector<TypeDefinition>>(Status::InvalidInput, "cdecl.bad_options",
                                                   "the pointer size must be 4 or 8 bytes");
  }
  if (options.long_size != 4 && options.long_size != 8) {
    return make_error<std::vector<TypeDefinition>>(Status::InvalidInput, "cdecl.bad_options",
                                                   "the long size must be 4 or 8 bytes");
  }
  auto tokens = tokenize(text);
  if (!tokens) {
    return propagate<std::vector<TypeDefinition>>(tokens);
  }
  Parser parser(std::move(tokens.value()), known, options);
  auto declared = parser.run();
  if (!declared) {
    return declared;
  }
  // The parser checks each type as it goes, but an array can still be too large for
  // 64 bits. The type store finds that, so the result is checked as a whole.
  TypeTable check = known;
  for (const TypeDefinition& definition : declared.value()) {
    check.put(definition);
  }
  if (auto valid = check.validate(); !valid) {
    return make_error<std::vector<TypeDefinition>>(Status::InvalidInput, "cdecl.invalid_type",
                                                   valid.diagnostic().message);
  }
  return declared;
}

}  // namespace donkey
