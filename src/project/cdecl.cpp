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
    } else if (const std::string_view pair =
                   i + 1 < text.size() ? text.substr(i, 2) : std::string_view();
               pair == "<<" || pair == ">>" || pair == "<=" || pair == ">=" || pair == "==" ||
               pair == "!=" || pair == "&&" || pair == "||" || pair == "++" || pair == "--" ||
               pair == "->") {
      token.kind = Token::Kind::Symbol;
      token.text = std::string(pair);
      i += 2;
    } else if (std::string_view("{}()[];,*=:-+!~/%&|^?<>").find(c) != std::string_view::npos) {
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

// ---- integer constants ----------------------------------------------------------------

/// The value and C type of an integer constant expression: 1, 2, 4 or 8 bytes. Only a cast gives
/// a type narrower than int, and every operator applies the integer promotions first.
struct Constant {
  std::uint64_t bits = 0;  ///< the value, truncated to `size` bytes
  std::uint64_t size = 4;
  bool is_signed = true;
};

std::uint64_t mask_of(std::uint64_t size) {
  return size >= 8 ? ~std::uint64_t{0} : (std::uint64_t{1} << (size * 8)) - 1;
}

std::int64_t max_signed(std::uint64_t size) {
  return size >= 8 ? std::numeric_limits<std::int64_t>::max()
                   : static_cast<std::int64_t>(mask_of(size) >> 1U);
}

std::int64_t min_signed(std::uint64_t size) {
  return -max_signed(size) - 1;
}

std::int64_t signed_value(const Constant& value) {
  if (value.size >= 8) {
    return static_cast<std::int64_t>(value.bits);
  }
  const std::uint64_t sign = std::uint64_t{1} << (value.size * 8 - 1);
  return static_cast<std::int64_t>((value.bits ^ sign) - sign);
}

bool is_negative(const Constant& value) {
  return value.is_signed && signed_value(value) < 0;
}

bool nonzero(const Constant& value) {
  return value.bits != 0;
}

/// The value converted to the integer type of `size` bytes and the signedness, as C converts it.
Constant convert(const Constant& value, std::uint64_t size, bool is_signed) {
  const std::uint64_t wide =
      value.is_signed ? static_cast<std::uint64_t>(signed_value(value)) : value.bits;
  return Constant{wide & mask_of(size), size, is_signed};
}

/// The integer promotions: a type narrower than int becomes int, which holds all its values.
Constant promote(const Constant& value) {
  return value.size < 4 ? convert(value, 4, true) : value;
}

Constant int_constant(bool truth) {
  return Constant{truth ? 1U : 0U, 4, true};
}

/// The common type of the usual arithmetic conversions, for two promoted operands.
Constant common_type(const Constant& a, const Constant& b) {
  if (a.is_signed == b.is_signed) {
    return Constant{0, std::max(a.size, b.size), a.is_signed};
  }
  const Constant& unsigned_operand = a.is_signed ? b : a;
  const Constant& signed_operand = a.is_signed ? a : b;
  if (unsigned_operand.size >= signed_operand.size) {
    return Constant{0, unsigned_operand.size, false};
  }
  return Constant{0, signed_operand.size, true};
}

/// The type of an integer literal (C11 6.4.4.1): the first of the candidate types for its base
/// and suffix that can hold the value.
Result<Constant> literal_constant(const Token& token, const CDeclarationOptions& options) {
  const std::string& text = token.text;
  const bool hex = text.size() > 1 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X');
  std::size_t digits_end = hex ? 2 : 0;
  while (digits_end < text.size() &&
         (hex ? is_hex_digit(text[digits_end]) : is_digit(text[digits_end]))) {
    ++digits_end;
  }
  const std::string suffix = text.substr(digits_end);
  int unsigned_marks = 0;
  int long_level = 0;
  for (std::size_t i = 0; i < suffix.size();) {
    if (suffix[i] == 'u' || suffix[i] == 'U') {
      ++unsigned_marks;
      ++i;
    } else if (long_level == 0 && i + 1 < suffix.size() &&
               (suffix.compare(i, 2, "ll") == 0 || suffix.compare(i, 2, "LL") == 0)) {
      long_level = 2;
      i += 2;
    } else if (long_level == 0) {
      long_level = 1;
      ++i;
    } else {
      long_level = 3;  // a second long suffix
      ++i;
    }
  }
  if (unsigned_marks > 1 || long_level > 2) {
    return located<Constant>(token.line, token.column, "cdecl.bad_number",
                             "'" + text + "' has an integer suffix C does not have");
  }
  struct Candidate {
    std::uint64_t size;
    bool is_signed;
    int long_level;
  };
  const Candidate all[] = {
      {4, true, 0}, {4, false, 0}, {options.long_size, true, 1}, {options.long_size, false, 1},
      {8, true, 2}, {8, false, 2}};
  for (const Candidate& candidate : all) {
    if (candidate.long_level < long_level) {
      continue;
    }
    if (unsigned_marks == 1 && candidate.is_signed) {
      continue;
    }
    // Without a `u` suffix a decimal literal takes only signed types.
    if (unsigned_marks == 0 && !hex && !candidate.is_signed) {
      continue;
    }
    const std::uint64_t limit = candidate.is_signed
                                    ? static_cast<std::uint64_t>(max_signed(candidate.size))
                                    : mask_of(candidate.size);
    if (token.number <= limit) {
      return Constant{token.number, candidate.size, candidate.is_signed};
    }
  }
  return located<Constant>(token.line, token.column, "cdecl.constant_too_large",
                           "'" + text + "' is too large for any integer type");
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
      if (definition.local) {
        continue;  // declared in a prototype: neither its tag nor its constants are in scope
      }
      if (definition.kind == TypeKind::Enum) {
        for (const TypeEnumerator& enumerator : definition.enumerators) {
          enum_constants_.emplace(enumerator.name, EnumConstant{enumerator.value, 0});
        }
      }
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

  /// Lists the names the text declares in `names` (see `CDeclaredName`).
  void record_names(std::vector<CDeclaredName>* names) { names_ = names; }

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

  void note(const std::string& name, CNameSpace space, TypeKind kind, bool completes = false) {
    // A tag or enumeration constant declared inside a prototype is not visible after it.
    if (names_ != nullptr && prototype_scope_ == 0) {
      names_->push_back(CDeclaredName{name, space, kind, completes});
    }
  }

  /// Binds a tag in the current scope. Inside a prototype the binding is logged, so that the
  /// prototype's closing parenthesis restores what was bound before.
  void bind_tag(std::map<std::string, TypeId>& tags, const std::string& name, TypeId id) {
    if (prototype_scope_ > 0) {
      const auto existing = tags.find(name);
      tag_undo_.push_back(TagBinding{
          &tags, name,
          existing == tags.end() ? std::nullopt : std::optional<TypeId>(existing->second),
          prototype_scope_});
    }
    tags[name] = id;
  }

  /// Whether the current prototype bound this tag (false at file scope).
  [[nodiscard]] bool bound_in_this_prototype(const std::map<std::string, TypeId>& tags,
                                             const std::string& name) const {
    return std::any_of(tag_undo_.begin(), tag_undo_.end(), [&](const TagBinding& binding) {
      return binding.scope == prototype_scope_ && binding.tags == &tags && binding.name == name;
    });
  }

  void bind_constant(const std::string& name, std::int64_t value) {
    if (prototype_scope_ > 0) {
      const auto existing = enum_constants_.find(name);
      constant_undo_.push_back(ConstantBinding{name,
                                               existing == enum_constants_.end()
                                                   ? std::nullopt
                                                   : std::optional<EnumConstant>(existing->second),
                                               prototype_scope_});
    }
    enum_constants_[name] = EnumConstant{value, prototype_scope_};
  }

  /// The prototype depth of the innermost parameter with this name, or -1.
  [[nodiscard]] int parameter_scope(const std::string& name) const {
    for (auto it = parameter_names_.rbegin(); it != parameter_names_.rend(); ++it) {
      if (it->first == name) {
        return it->second;
      }
    }
    return -1;
  }

  /// Whether `name` is a typedef name here: a typedef that no parameter or enumeration constant
  /// hides. Typedefs are declared only at file scope, so any such binding is an inner one.
  [[nodiscard]] bool typedef_visible(const std::string& name) const {
    return typedef_names_.count(name) != 0 && enum_constants_.count(name) == 0 &&
           parameter_scope(name) < 0;
  }

  /// Leaves a prototype: its tags, enumeration constants and parameter names go out of scope.
  void leave_prototype() {
    while (!parameter_names_.empty() && parameter_names_.back().second == prototype_scope_) {
      parameter_names_.pop_back();
    }
    while (!tag_undo_.empty() && tag_undo_.back().scope == prototype_scope_) {
      const TagBinding& binding = tag_undo_.back();
      if (binding.previous) {
        (*binding.tags)[binding.name] = *binding.previous;
      } else {
        binding.tags->erase(binding.name);
      }
      tag_undo_.pop_back();
    }
    while (!constant_undo_.empty() && constant_undo_.back().scope == prototype_scope_) {
      const ConstantBinding& binding = constant_undo_.back();
      if (binding.previous) {
        enum_constants_[binding.name] = *binding.previous;
      } else {
        enum_constants_.erase(binding.name);
      }
      constant_undo_.pop_back();
    }
    --prototype_scope_;
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
          typedef_name != typedef_names_.end() && typedef_visible(word)) {
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
        if (known != tags.end() && prototype_scope_ > 0 && !bound_in_this_prototype(tags, tag)) {
          // C gives a definition inside a parameter list its own type, hiding the outer tag
          // only there; the subset does not model that hiding.
          return located<TagRef>(line, column, "cdecl.prototype_tag",
                                 "'" + tag +
                                     "' is defined inside a parameter list while an outer "
                                     "declaration of it is visible; this is not supported");
        }
        if (known != tags.end()) {
          if (incomplete_.count(known->second) == 0) {
            return located<TagRef>(line, column, "cdecl.redefinition",
                                   "'" + tag + "' is already defined");
          }
          id = known->second;  // completes an earlier forward declaration
          if (forward_tags_.erase(id) != 0) {
            note(tag, CNameSpace::Tag, is_union ? TypeKind::Union : TypeKind::Struct, true);
          }
        }
      }
      if (!id.valid()) {
        TypeDefinition shell;
        shell.kind = is_union ? TypeKind::Union : TypeKind::Struct;
        shell.name = tag;
        shell.local = prototype_scope_ > 0;
        id = add(std::move(shell));
        if (!tag.empty()) {
          bind_tag(tags, tag, id);
          note(tag, CNameSpace::Tag, is_union ? TypeKind::Union : TypeKind::Struct);
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
    // A reference to a tag not yet defined is a forward declaration, completed later. Inside a
    // prototype it declares a tag of the prototype's scope (C11 6.2.1): a later definition outside
    // is a different type, and this one stays incomplete.
    TypeDefinition shell;
    shell.kind = is_union ? TypeKind::Union : TypeKind::Struct;
    shell.name = tag;
    shell.local = prototype_scope_ > 0;
    const TypeId id = add(std::move(shell));
    bind_tag(tags, tag, id);
    note(tag, CNameSpace::Tag, is_union ? TypeKind::Union : TypeKind::Struct);
    incomplete_.insert(id);
    forward_tags_.insert(id);
    return TagRef{id, false};
  }

  /// A struct or union body. Members are laid out as the System V ABI lays them out (x86-64 and
  /// AArch64 agree here): each member at its natural alignment, the size padded to the largest
  /// alignment. A bit-field sits at the next free bit unless it would cross a boundary of a unit
  /// of its declared type's size, when it starts the next unit. A named bit-field aligns the
  /// whole like a member of its declared type; an unnamed one only pads, and an unnamed one of
  /// width zero moves the next member to its type's alignment.
  Result<TypeId> parse_struct_body(TypeId id, bool is_union, const std::string& tag) {
    if (auto open = expect("{"); !open) {
      return propagate<TypeId>(open);
    }
    const std::string what = is_union ? "union" : "struct";
    // Offsets are counted in bits; 2^61 bytes is far beyond any object.
    constexpr std::uint64_t kMaxBits = std::numeric_limits<std::uint64_t>::max() / 8;
    const auto too_large = [&](std::uint32_t line, std::uint32_t column) {
      return located<TypeId>(line, column, "cdecl.too_large",
                             "the " + what + " is larger than 2^61 bytes");
    };
    std::vector<TypeField> fields;
    std::uint64_t end_bits = 0;
    std::uint64_t alignment = 1;  // the members' alignment
    // The record's alignment where the ABI aligns it more than its members: AAPCS64 aligns a
    // record to the type of each unnamed bit-field too.
    std::uint64_t record_alignment = 1;
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
        Declarator member;
        if (at_symbol(":")) {
          // An unnamed bit-field.
          member.type = spec.value().type;
          member.line = peek().line;
          member.column = peek().column;
        } else {
          auto decl = parse_declarator(spec.value().type, /*abstract_allowed=*/false,
                                       /*depth=*/0, /*parameter=*/false);
          if (!decl) {
            return propagate<TypeId>(decl);
          }
          member = decl.value();
        }
        if (member.is_function) {
          return located<TypeId>(member.line, member.column, "cdecl.function_member",
                                 "a member cannot be a function");
        }
        const auto layout = measure(member.type);
        const std::string described =
            member.name.empty() ? "an unnamed bit-field" : "member '" + member.name + "'";
        if (!layout) {
          return located<TypeId>(member.line, member.column, "cdecl.incomplete_type",
                                 described + " has a type whose size is not known");
        }

        if (at_symbol(":")) {
          if (options_.bit_fields == CBitFieldLayout::Unmodelled) {
            return located<TypeId>(peek().line, peek().column, "cdecl.bitfield_abi",
                                   "bit-field layout is not modelled for this ABI");
          }
          advance();
          const Token width_at = peek();
          auto width_value = constant_expression(/*evaluate=*/true, /*depth=*/0);
          if (!width_value) {
            return propagate<TypeId>(width_value);
          }
          const auto declared = integer_type(member.type);
          if (!declared) {
            return located<TypeId>(member.line, member.column, "cdecl.bitfield_type",
                                   described + " needs an integer or enum type");
          }
          const std::uint64_t unit_bits = layout->size * 8;
          if (is_negative(width_value.value()) || width_value.value().bits > unit_bits) {
            return located<TypeId>(
                width_at.line, width_at.column, "cdecl.bitfield_width",
                "the width of " + described + " is negative or wider than its type");
          }
          const std::uint64_t width = width_value.value().bits;
          if (width > 1 && is_bool(member.type)) {
            return located<TypeId>(width_at.line, width_at.column, "cdecl.bitfield_width",
                                   "the width of " + described + " is wider than _Bool's one bit");
          }
          if (member.name.empty() && options_.bit_fields == CBitFieldLayout::Aapcs64) {
            record_alignment = std::max(record_alignment, layout->alignment);
          }
          if (width == 0) {
            if (!member.name.empty()) {
              return located<TypeId>(width_at.line, width_at.column, "cdecl.bitfield_width",
                                     "a named bit-field cannot have width zero");
            }
            if (!is_union) {
              const auto aligned = round_up_checked(end_bits, layout->alignment * 8);
              if (!aligned || *aligned > kMaxBits) {
                return too_large(member.line, member.column);
              }
              end_bits = *aligned;
            }
            // Kept as layout: the next member, or the record's end, starts at this offset.
            TypeField marker;
            marker.offset = is_union ? 0 : end_bits / 8;
            marker.type = member.type;
            marker.padding = true;
            fields.push_back(std::move(marker));
          } else {
            std::uint64_t start = 0;
            if (!is_union) {
              start = end_bits;
              if (start % unit_bits + width > unit_bits) {
                const auto next_unit = round_up_checked(start, unit_bits);
                if (!next_unit) {
                  return too_large(member.line, member.column);
                }
                start = *next_unit;
              }
            }
            if (start > kMaxBits - width) {
              return too_large(member.line, member.column);
            }
            end_bits = is_union ? std::max(end_bits, width) : start + width;
            if (!member.name.empty()) {
              alignment = std::max(alignment, layout->alignment);
            }
            // An unnamed bit-field is kept as padding: it takes its bits but is not a member.
            TypeField field;
            field.name = member.name;
            field.offset = start / 8;
            field.type = member.type;
            field.bit_offset = static_cast<std::uint8_t>(start % 8);
            field.bit_size = static_cast<std::uint8_t>(width);
            field.padding = member.name.empty();
            fields.push_back(std::move(field));
          }
        } else {
          if (member.name.empty()) {
            return unexpected<TypeId>("a name");
          }
          std::uint64_t offset = 0;
          if (layout->size > kMaxBits / 8) {
            return too_large(member.line, member.column);
          }
          if (is_union) {
            end_bits = std::max(end_bits, layout->size * 8);
          } else {
            const auto aligned = round_up_checked((end_bits + 7) / 8, layout->alignment);
            if (!aligned || *aligned > kMaxBits / 8 - layout->size) {
              return too_large(member.line, member.column);
            }
            offset = *aligned;
            end_bits = (offset + layout->size) * 8;
          }
          alignment = std::max(alignment, layout->alignment);
          TypeField field;
          field.name = member.name;
          field.offset = offset;
          field.type = member.type;
          fields.push_back(std::move(field));
        }
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

    const std::uint64_t record = std::max(alignment, record_alignment);
    const auto size = round_up_checked((end_bits + 7) / 8, record);
    if (!size) {
      return located<TypeId>(peek().line, peek().column, "cdecl.too_large",
                             "the " + what + " is larger than 64 bits can count");
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
    definition.alignment = record > alignment ? record : 0;
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
    definition.local = prototype_scope_ > 0;
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
        const Token value_at = peek();
        auto value = constant_expression(/*evaluate=*/true, /*depth=*/0);
        if (!value) {
          return propagate<TypeId>(value);
        }
        const Constant& constant = value.value();
        const bool fits =
            constant.is_signed
                ? signed_value(constant) >= kInt32Min && signed_value(constant) <= kInt32Max
                : constant.bits <= static_cast<std::uint64_t>(kInt32Max);
        if (!fits) {
          return located<TypeId>(value_at.line, value_at.column, "cdecl.enum_value_range",
                                 "an enumerator value must fit in 32 bits");
        }
        next_value =
            constant.is_signed ? signed_value(constant) : static_cast<std::int64_t>(constant.bits);
      }
      if (next_value < kInt32Min || next_value > kInt32Max) {
        return located<TypeId>(name_line, name_column, "cdecl.enum_value_range",
                               "an enumerator value must fit in 32 bits");
      }
      enumerator.value = next_value;
      if (const auto existing = enum_constants_.find(enumerator.name);
          (existing != enum_constants_.end() && existing->second.scope == prototype_scope_) ||
          (prototype_scope_ == 0 && typedef_names_.count(enumerator.name) != 0) ||
          (prototype_scope_ > 0 && parameter_scope(enumerator.name) == prototype_scope_)) {
        return located<TypeId>(name_line, name_column, "cdecl.redefinition",
                               "'" + enumerator.name + "' is already declared");
      }
      // The constant is in scope from the end of its own enumerator.
      bind_constant(enumerator.name, next_value);
      note(enumerator.name, CNameSpace::Ordinary, TypeKind::Enum);
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
      bind_tag(enum_tags_, tag, id);
      note(tag, CNameSpace::Tag, TypeKind::Enum);
    }
    return id;
  }

  // ---- integer constant expressions ----------------------------------------------
  //
  // Array sizes, enumerator values and bit-field widths are integer constant expressions
  // (C11 6.6): integer literals, enumeration constants, `sizeof`, casts to integer types and
  // the unary, binary and conditional operators, with C's promotions and usual arithmetic
  // conversions. An operand that is not evaluated (the untaken side of `&&`, `||` and `?:`, the
  // operand of `sizeof`) is parsed for its type only. Division by zero, a shift by a negative
  // count or by the width or more, and signed overflow are errors, as they are undefined in C.

  /// Whether the token `ahead` begins a type name, as in a cast or `sizeof(type)`.
  [[nodiscard]] bool starts_type_name(std::size_t ahead) const {
    const Token& token = peek(ahead);
    if (token.kind != Token::Kind::Identifier) {
      return false;
    }
    static const std::set<std::string, std::less<>> kTypeWords = {
        "void",     "_Bool",  "char",  "short", "int",   "long",     "float",    "double", "signed",
        "unsigned", "struct", "union", "enum",  "const", "volatile", "restrict", "_Atomic"};
    return kTypeWords.count(token.text) != 0 || typedef_visible(token.text) ||
           fixed_width_integer(token.text, options_).has_value();
  }

  /// A type name: specifiers and an abstract declarator.
  Result<TypeId> parse_type_name(int depth) {
    const std::uint32_t line = peek().line;
    const std::uint32_t column = peek().column;
    auto spec = parse_decl_specifiers();
    if (!spec) {
      return propagate<TypeId>(spec);
    }
    if (spec.value().is_typedef) {
      return located<TypeId>(line, column, "cdecl.bad_specifiers",
                             "a type name cannot be a typedef");
    }
    auto decl = parse_declarator(spec.value().type, /*abstract_allowed=*/true, depth,
                                 /*parameter=*/false);
    if (!decl) {
      return propagate<TypeId>(decl);
    }
    if (!decl.value().name.empty()) {
      return located<TypeId>(decl.value().line, decl.value().column, "cdecl.unexpected_token",
                             "a type name cannot declare '" + decl.value().name + "'");
    }
    return decl.value().type;
  }

  /// The integer type an id names, through typedefs. An enum is `int`.
  [[nodiscard]] std::optional<Constant> integer_type(TypeId id) const {
    for (int depth = 0; depth <= kMaxCDeclarationNesting && id.valid(); ++depth) {
      const TypeDefinition* definition = working_.find(id);
      if (definition == nullptr) {
        return std::nullopt;
      }
      if (definition->kind == TypeKind::Typedef) {
        id = definition->target;
        continue;
      }
      if (definition->kind == TypeKind::Enum) {
        return Constant{0, 4, true};
      }
      if (definition->kind == TypeKind::Integer &&
          (definition->size == 1 || definition->size == 2 || definition->size == 4 ||
           definition->size == 8)) {
        return Constant{0, definition->size, definition->is_signed};
      }
      return std::nullopt;
    }
    return std::nullopt;
  }

  /// Whether the type is `_Bool`, through typedefs: a conversion to it tests for zero.
  [[nodiscard]] bool is_bool(TypeId id) const {
    for (int depth = 0; depth <= kMaxCDeclarationNesting && id.valid(); ++depth) {
      const TypeDefinition* definition = working_.find(id);
      if (definition == nullptr) {
        return false;
      }
      if (definition->kind != TypeKind::Typedef) {
        return definition->kind == TypeKind::Integer && definition->name == "_Bool";
      }
      id = definition->target;
    }
    return false;
  }

  /// Counts the open expression levels of the whole parse, so that expressions nested in a
  /// struct inside `sizeof` share one bound with the expression around them.
  class ExpressionLevel {
   public:
    explicit ExpressionLevel(int& open) : open_(open) { ++open_; }
    ~ExpressionLevel() { --open_; }
    ExpressionLevel(const ExpressionLevel&) = delete;
    ExpressionLevel& operator=(const ExpressionLevel&) = delete;
    [[nodiscard]] bool too_deep() const { return open_ > kMaxCDeclarationNesting; }

   private:
    int& open_;
  };

  Result<Constant> constant_expression(bool evaluate, int depth) {
    const ExpressionLevel level(expression_levels_);
    if (level.too_deep() || ++depth > kMaxCDeclarationNesting) {
      return nesting_error<Constant>(peek());
    }
    auto condition = binary_expression(1, evaluate, depth);
    if (!condition || !at_symbol("?")) {
      return condition;
    }
    advance();
    const bool first_taken = nonzero(condition.value());
    auto first = constant_expression(evaluate && first_taken, depth);
    if (!first) {
      return first;
    }
    if (auto colon = expect(":"); !colon) {
      return propagate<Constant>(colon);
    }
    auto second = constant_expression(evaluate && !first_taken, depth);
    if (!second) {
      return second;
    }
    const Constant first_value = promote(first.value());
    const Constant second_value = promote(second.value());
    const Constant type = common_type(first_value, second_value);
    return convert(first_taken ? first_value : second_value, type.size, type.is_signed);
  }

  [[nodiscard]] int binary_precedence() const {
    const Token& token = peek();
    if (token.kind != Token::Kind::Symbol) {
      return 0;
    }
    const std::string& op = token.text;
    if (op == "||") return 1;
    if (op == "&&") return 2;
    if (op == "|") return 3;
    if (op == "^") return 4;
    if (op == "&") return 5;
    if (op == "==" || op == "!=") return 6;
    if (op == "<" || op == ">" || op == "<=" || op == ">=") return 7;
    if (op == "<<" || op == ">>") return 8;
    if (op == "+" || op == "-") return 9;
    if (op == "*" || op == "/" || op == "%") return 10;
    return 0;
  }

  Result<Constant> binary_expression(int minimum, bool evaluate, int depth) {
    auto left = unary_expression(evaluate, depth);
    if (!left) {
      return left;
    }
    while (true) {
      const int precedence = binary_precedence();
      if (precedence == 0 || precedence < minimum) {
        return left;
      }
      const Token op = peek();
      advance();
      bool right_evaluated = evaluate;
      if (op.text == "&&") {
        right_evaluated = evaluate && nonzero(left.value());
      } else if (op.text == "||") {
        right_evaluated = evaluate && !nonzero(left.value());
      }
      auto right = binary_expression(precedence + 1, right_evaluated, depth);
      if (!right) {
        return right;
      }
      left = apply_binary(op, promote(left.value()), promote(right.value()), evaluate);
      if (!left) {
        return left;
      }
    }
  }

  Result<Constant> apply_binary(const Token& op, const Constant& a, const Constant& b,
                                bool evaluate) const {
    const std::string& name = op.text;
    if (name == "&&") {
      return int_constant(nonzero(a) && nonzero(b));
    }
    if (name == "||") {
      return int_constant(nonzero(a) || nonzero(b));
    }
    if (name == "<<" || name == ">>") {
      // The result has the promoted type of the left operand.
      if (!evaluate) {
        return Constant{0, a.size, a.is_signed};
      }
      const std::uint64_t width = a.size * 8;
      if (is_negative(b) || b.bits >= width) {
        return located<Constant>(op.line, op.column, "cdecl.bad_shift",
                                 "the shift count is negative or not less than the width of the "
                                 "type");
      }
      const auto count = static_cast<unsigned>(b.bits);
      if (name == ">>") {
        if (a.is_signed) {
          const std::int64_t shifted = signed_value(a) >> count;
          return Constant{static_cast<std::uint64_t>(shifted) & mask_of(a.size), a.size, true};
        }
        return Constant{a.bits >> count, a.size, false};
      }
      if (a.is_signed) {
        const std::int64_t value = signed_value(a);
        if (value < 0 || value > (max_signed(a.size) >> count)) {
          return located<Constant>(op.line, op.column, "cdecl.constant_overflow",
                                   "the shift overflows its signed type");
        }
        return Constant{static_cast<std::uint64_t>(value) << count, a.size, true};
      }
      return Constant{(a.bits << count) & mask_of(a.size), a.size, false};
    }

    const Constant type = common_type(a, b);
    const Constant x = convert(a, type.size, type.is_signed);
    const Constant y = convert(b, type.size, type.is_signed);
    if (name == "==" || name == "!=" || name == "<" || name == ">" || name == "<=" ||
        name == ">=") {
      int order = 0;
      if (type.is_signed) {
        const std::int64_t left = signed_value(x);
        const std::int64_t right = signed_value(y);
        order = left < right ? -1 : (left > right ? 1 : 0);
      } else {
        order = x.bits < y.bits ? -1 : (x.bits > y.bits ? 1 : 0);
      }
      if (name == "==") return int_constant(order == 0);
      if (name == "!=") return int_constant(order != 0);
      if (name == "<") return int_constant(order < 0);
      if (name == ">") return int_constant(order > 0);
      if (name == "<=") return int_constant(order <= 0);
      return int_constant(order >= 0);
    }
    if (name == "&") return Constant{x.bits & y.bits, type.size, type.is_signed};
    if (name == "^") return Constant{x.bits ^ y.bits, type.size, type.is_signed};
    if (name == "|") return Constant{x.bits | y.bits, type.size, type.is_signed};
    if (!evaluate) {
      return Constant{0, type.size, type.is_signed};
    }

    if ((name == "/" || name == "%") && y.bits == 0) {
      return located<Constant>(op.line, op.column, "cdecl.division_by_zero",
                               "the constant expression divides by zero");
    }
    if (!type.is_signed) {
      std::uint64_t result = 0;
      if (name == "+") result = x.bits + y.bits;
      if (name == "-") result = x.bits - y.bits;
      if (name == "*") result = x.bits * y.bits;
      if (name == "/") result = x.bits / y.bits;
      if (name == "%") result = x.bits % y.bits;
      return Constant{result & mask_of(type.size), type.size, false};
    }
    const std::int64_t left = signed_value(x);
    const std::int64_t right = signed_value(y);
    std::int64_t result = 0;
    bool overflow = false;
    if (name == "+") {
      overflow = __builtin_add_overflow(left, right, &result);
    } else if (name == "-") {
      overflow = __builtin_sub_overflow(left, right, &result);
    } else if (name == "*") {
      overflow = __builtin_mul_overflow(left, right, &result);
    } else if (left == min_signed(type.size) && right == -1) {
      overflow = true;  // the quotient does not fit
    } else {
      result = name == "/" ? left / right : left % right;
    }
    if (overflow || result < min_signed(type.size) || result > max_signed(type.size)) {
      return located<Constant>(op.line, op.column, "cdecl.constant_overflow",
                               "the constant expression overflows its signed type");
    }
    return Constant{static_cast<std::uint64_t>(result) & mask_of(type.size), type.size, true};
  }

  Result<Constant> unary_expression(bool evaluate, int depth) {
    const ExpressionLevel level(expression_levels_);
    if (level.too_deep() || ++depth > kMaxCDeclarationNesting) {
      return nesting_error<Constant>(peek());
    }
    const Token op = peek();
    if (at_symbol("+") || at_symbol("-") || at_symbol("~") || at_symbol("!")) {
      advance();
      auto operand = unary_expression(evaluate, depth);
      if (!operand) {
        return operand;
      }
      const Constant value = promote(operand.value());
      if (op.text == "+") {
        return value;
      }
      if (op.text == "!") {
        return int_constant(!nonzero(value));
      }
      if (op.text == "~") {
        return Constant{~value.bits & mask_of(value.size), value.size, value.is_signed};
      }
      if (value.is_signed && evaluate && signed_value(value) == min_signed(value.size)) {
        return located<Constant>(op.line, op.column, "cdecl.constant_overflow",
                                 "the negation overflows its signed type");
      }
      return Constant{(std::uint64_t{0} - value.bits) & mask_of(value.size), value.size,
                      value.is_signed};
    }
    if (at_word("sizeof")) {
      advance();
      std::uint64_t size = 0;
      if (at_symbol("(") && starts_type_name(1)) {
        advance();
        const Token type_at = peek();
        auto type = parse_type_name(depth);
        if (!type) {
          return propagate<Constant>(type);
        }
        if (auto close = expect(")"); !close) {
          return propagate<Constant>(close);
        }
        const auto layout = measure(type.value());
        if (!layout) {
          return located<Constant>(type_at.line, type_at.column, "cdecl.incomplete_type",
                                   "sizeof needs a type whose size is known");
        }
        size = layout->size;
      } else {
        // The operand is not evaluated: only its type counts.
        auto operand = unary_expression(/*evaluate=*/false, depth);
        if (!operand) {
          return operand;
        }
        size = operand.value().size;
      }
      if (size > mask_of(options_.pointer_size)) {
        return located<Constant>(op.line, op.column, "cdecl.constant_overflow",
                                 "the size does not fit in size_t");
      }
      return Constant{size, options_.pointer_size, false};
    }
    if (at_symbol("(") && starts_type_name(1)) {
      advance();
      const Token type_at = peek();
      auto type = parse_type_name(depth);
      if (!type) {
        return propagate<Constant>(type);
      }
      if (auto close = expect(")"); !close) {
        return propagate<Constant>(close);
      }
      auto operand = unary_expression(evaluate, depth);
      if (!operand) {
        return operand;
      }
      const auto target = integer_type(type.value());
      if (!target) {
        return located<Constant>(type_at.line, type_at.column, "cdecl.not_integer",
                                 "a constant expression can be cast only to an integer type");
      }
      Constant converted;
      if (is_bool(type.value())) {
        converted = Constant{nonzero(operand.value()) ? 1U : 0U, 1, false};
      } else {
        converted = convert(operand.value(), target->size, target->is_signed);
      }
      // The cast keeps its type (`sizeof((char)1)` is 1); an operator promotes it when used.
      return converted;
    }
    return primary_expression(evaluate, depth);
  }

  Result<Constant> primary_expression(bool evaluate, int depth) {
    const Token token = peek();
    if (token.kind == Token::Kind::Number) {
      advance();
      return literal_constant(token, options_);
    }
    if (at_symbol("(")) {
      advance();
      auto value = constant_expression(evaluate, depth);
      if (!value) {
        return value;
      }
      // A comma operator may appear only where nothing is evaluated (C11 6.6p3), as in the operand
      // of `sizeof`; its value and type are those of its right operand.
      while (at_symbol(",")) {
        if (evaluate) {
          return located<Constant>(peek().line, peek().column, "cdecl.not_constant",
                                   "a comma operator is a constant expression only where it is "
                                   "not evaluated");
        }
        advance();
        value = constant_expression(/*evaluate=*/false, depth);
        if (!value) {
          return value;
        }
      }
      if (auto close = expect(")"); !close) {
        return propagate<Constant>(close);
      }
      return value;
    }
    if (token.kind == Token::Kind::Identifier && !is_keyword(token.text)) {
      const auto constant = enum_constants_.find(token.text);
      const int parameter = parameter_scope(token.text);
      if (parameter >= 0 &&
          (constant == enum_constants_.end() || parameter >= constant->second.scope)) {
        return located<Constant>(
            token.line, token.column, "cdecl.not_constant",
            "'" + token.text + "' is a parameter here, not an integer constant");
      }
      if (constant == enum_constants_.end()) {
        return located<Constant>(token.line, token.column, "cdecl.not_constant",
                                 "'" + token.text + "' is not an integer constant");
      }
      advance();
      return Constant{static_cast<std::uint64_t>(constant->second.value) & mask_of(4), 4, true};
    }
    return unexpected<Constant>("an integer constant expression");
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
          const Token size_at = peek();
          auto count = constant_expression(/*evaluate=*/true, depth);
          if (!count) {
            return propagate<Declarator>(count);
          }
          if (is_negative(count.value())) {
            return located<Declarator>(size_at.line, size_at.column, "cdecl.array_size_required",
                                       "an array size cannot be negative");
          }
          suffix.count = count.value().bits;
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

  /// A parameter list. It is a scope: tags and enumeration constants it declares are not visible
  /// after its closing parenthesis.
  Result<void> parse_parameters(std::vector<TypeField>& parameters, bool& variadic, int depth) {
    if (depth > kMaxCDeclarationNesting) {
      return nesting_error<void>(peek());
    }
    ++prototype_scope_;
    auto parsed = parse_parameter_list(parameters, variadic, depth);
    leave_prototype();
    return parsed;
  }

  Result<void> parse_parameter_list(std::vector<TypeField>& parameters, bool& variadic, int depth) {
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
      if (!declared.name.empty()) {
        // In scope for the declarators that follow it in this list.
        if (parameter_scope(declared.name) == prototype_scope_ ||
            (enum_constants_.count(declared.name) != 0 &&
             enum_constants_.at(declared.name).scope == prototype_scope_)) {
          return located<void>(
              declared.line, declared.column, "cdecl.redefinition",
              "'" + declared.name + "' is already declared in this parameter list");
        }
        parameter_names_.emplace_back(declared.name, prototype_scope_);
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
        if (enum_constants_.count(declared.name) != 0) {
          return located<void>(declared.line, declared.column, "cdecl.redefinition",
                               "'" + declared.name + "' is already an enumeration constant");
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
          note(declared.name, CNameSpace::Ordinary, TypeKind::Typedef);
        } else {
          TypeDefinition typedef_definition;
          typedef_definition.kind = TypeKind::Typedef;
          typedef_definition.name = declared.name;
          typedef_definition.target = declared.type;
          const TypeId id = add(std::move(typedef_definition));
          typedef_names_.emplace(declared.name, id);
          note(declared.name, CNameSpace::Ordinary, TypeKind::Typedef);
        }
      } else if (declared.is_function) {
        if (enum_constants_.count(declared.name) != 0 || typedef_names_.count(declared.name) != 0) {
          return located<void>(
              declared.line, declared.column, "cdecl.redefinition",
              "'" + declared.name + "' is already a typedef or an enumeration constant");
        }
        // A prototype: the function type takes the function's name.
        TypeDefinition named;
        if (const TypeDefinition* function = working_.find(declared.type)) {
          named = *function;
        }
        named.name = declared.name;
        replace(named);
        note(declared.name, CNameSpace::Ordinary, TypeKind::Function);
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
  /// Where the declared names go (`parse_c_declarations`'s `names`), or null.
  std::vector<CDeclaredName>* names_ = nullptr;
  std::vector<TypeDefinition> out_;
  std::map<std::string, TypeId> struct_tags_;
  std::map<std::string, TypeId> union_tags_;
  std::map<std::string, TypeId> enum_tags_;
  std::map<std::string, TypeId> typedef_names_;
  std::map<std::string, TypeId> scalars_;
  /// Enumeration constants in scope, from the known table and this text, with the scope that
  /// declared each: 0 for file scope, otherwise the depth of the prototype.
  struct EnumConstant {
    std::int64_t value = 0;
    int scope = 0;
  };
  std::map<std::string, EnumConstant> enum_constants_;
  /// Prototypes being parsed, innermost last (a prototype is a scope, C11 6.2.1).
  int prototype_scope_ = 0;
  /// A binding made inside a prototype, undone at its closing parenthesis.
  struct TagBinding {
    std::map<std::string, TypeId>* tags = nullptr;
    std::string name;
    std::optional<TypeId> previous;
    int scope = 0;
  };
  struct ConstantBinding {
    std::string name;
    std::optional<EnumConstant> previous;
    int scope = 0;
  };
  std::vector<TagBinding> tag_undo_;
  std::vector<ConstantBinding> constant_undo_;
  /// The parameter names of the prototypes being parsed, with the depth of their prototype. A
  /// parameter is an ordinary identifier: it hides a typedef or an enumeration constant of an outer
  /// scope in the declarators after it.
  std::vector<std::pair<std::string, int>> parameter_names_;
  std::set<TypeId> incomplete_;
  /// Tags this text named by a forward reference and has not defined yet.
  std::set<TypeId> forward_tags_;
  int nesting_ = 0;            ///< struct and union bodies being parsed
  int expression_levels_ = 0;  ///< constant expression levels open (see `ExpressionLevel`)
};

}  // namespace

Result<std::vector<TypeDefinition>> parse_c_declarations(std::string_view text,
                                                         const TypeTable& known,
                                                         const CDeclarationOptions& options,
                                                         std::vector<CDeclaredName>* names) {
  if (names != nullptr) {
    names->clear();
  }
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
  parser.record_names(names);
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
