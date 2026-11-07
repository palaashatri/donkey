// An MSVC name-decoration demangler for the 64-bit forms in G10-T2. It is written from the
// public description of the decoration scheme; no demangler's source was consulted. The
// corpus (tests/fixtures/msvc) records llvm-undname's output, which is the spelling used here.
// Anything outside the supported grammar is rejected as `demangle.unsupported`.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "donkey/binary/demangle.h"

namespace donkey {
namespace {

constexpr unsigned kConst = 1;
constexpr unsigned kVolatile = 2;
constexpr std::size_t kNameTableSize = 10;

std::string cv_text(unsigned cv) {
  switch (cv) {
    case kConst:
      return "const";
    case kVolatile:
      return "volatile";
    case kConst | kVolatile:
      return "const volatile";
    default:
      return std::string();
  }
}

/// The qualifier letter after a pointer or reference marker: A none, B const, C volatile,
/// D const volatile.
std::optional<unsigned> qualifier_letter(char c) {
  switch (c) {
    case 'A':
      return 0U;
    case 'B':
      return kConst;
    case 'C':
      return kVolatile;
    case 'D':
      return kConst | kVolatile;
    default:
      return std::nullopt;
  }
}

/// A type. A pointer or reference has `pointee`; `ptr` is '*', '&' or 'r' (for `&&`). `cv`
/// qualifies this object: the base type for a base, the pointer itself for a pointer.
struct Ty {
  std::string base;
  unsigned cv = 0;
  char ptr = 0;
  std::shared_ptr<Ty> pointee;
};

std::string render(const Ty& type) {
  if (!type.pointee) {
    std::string text = type.base;
    if (type.cv != 0) {
      text += " " + cv_text(type.cv);
    }
    return text;
  }
  const std::string inner = render(*type.pointee);
  std::string text = inner;
  // `int **` has no space between the stars; `int *const *` and `int *&` do: after a
  // qualified or base type the marker is set off by a space.
  if (inner.empty() || inner.back() != '*') {
    text += " ";
  }
  text += type.ptr == '*' ? "*" : "&";
  if (type.ptr == 'r') {
    text += "&";
  }
  if (type.cv != 0) {
    text += cv_text(type.cv);
  }
  return text;
}

/// A name: `text` is the entity (`get`, `~Box`, `operator=`) and `scope` holds the enclosing
/// names innermost first. For a constructor or destructor the class is the first scope entry.
struct Name {
  std::string text;
  std::vector<std::string> scope;
};

std::string qualified(const Name& name) {
  std::string out;
  for (auto it = name.scope.rbegin(); it != name.scope.rend(); ++it) {
    out += *it;
    out += "::";
  }
  return out + name.text;
}

enum class Kind : std::uint8_t { Operator, Constructor, Destructor };

struct OperatorCode {
  std::string_view code;
  std::string_view text;
  Kind kind;
};

constexpr OperatorCode kOperators[] = {
    {"0", "", Kind::Constructor},
    {"1", "", Kind::Destructor},
    {"2", "operator new", Kind::Operator},
    {"3", "operator delete", Kind::Operator},
    {"4", "operator=", Kind::Operator},
    {"5", "operator>>", Kind::Operator},
    {"6", "operator<<", Kind::Operator},
    {"7", "operator!", Kind::Operator},
    {"8", "operator==", Kind::Operator},
    {"9", "operator!=", Kind::Operator},
    {"A", "operator[]", Kind::Operator},
    {"C", "operator->", Kind::Operator},
    {"D", "operator*", Kind::Operator},
    {"E", "operator++", Kind::Operator},
    {"F", "operator--", Kind::Operator},
    {"G", "operator-", Kind::Operator},
    {"H", "operator+", Kind::Operator},
    {"I", "operator&", Kind::Operator},
    {"J", "operator->*", Kind::Operator},
    {"K", "operator/", Kind::Operator},
    {"L", "operator%", Kind::Operator},
    {"M", "operator<", Kind::Operator},
    {"N", "operator<=", Kind::Operator},
    {"O", "operator>", Kind::Operator},
    {"P", "operator>=", Kind::Operator},
    {"Q", "operator,", Kind::Operator},
    {"R", "operator()", Kind::Operator},
    {"S", "operator~", Kind::Operator},
    {"T", "operator^", Kind::Operator},
    {"U", "operator|", Kind::Operator},
    {"V", "operator&&", Kind::Operator},
    {"W", "operator||", Kind::Operator},
    {"X", "operator*=", Kind::Operator},
    {"Y", "operator+=", Kind::Operator},
    {"Z", "operator-=", Kind::Operator},
    {"_0", "operator/=", Kind::Operator},
    {"_1", "operator%=", Kind::Operator},
    {"_2", "operator>>=", Kind::Operator},
    {"_3", "operator<<=", Kind::Operator},
    {"_4", "operator&=", Kind::Operator},
    {"_5", "operator|=", Kind::Operator},
    {"_6", "operator^=", Kind::Operator},
    {"_U", "operator new[]", Kind::Operator},
    {"_V", "operator delete[]", Kind::Operator},
};

enum class Access : std::uint8_t { None, Public, Protected, Private };

std::string access_prefix(Access access) {
  switch (access) {
    case Access::Public:
      return "public: ";
    case Access::Protected:
      return "protected: ";
    case Access::Private:
      return "private: ";
    case Access::None:
      break;
  }
  return std::string();
}

bool valid_identifier(std::string_view text) {
  if (text.empty()) {
    return false;
  }
  for (const char c : text) {
    const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    const bool digit = c >= '0' && c <= '9';
    if (!letter && !digit && c != '_' && c != '$') {
      return false;
    }
  }
  return true;
}

class MsvcParser {
 public:
  MsvcParser(std::string_view input, const DemangleOptions& options)
      : in_(input), options_(options) {}

  Result<std::string> run() {
    if (in_.size() > options_.max_input_bytes) {
      return make_error<std::string>(Status::InvalidInput, "demangle.too_long",
                                     "the name is longer than the limit");
    }
    if (!is_msvc_name(in_)) {
      return make_error<std::string>(Status::InvalidInput, "demangle.not_mangled",
                                     "the name does not start with ?");
    }
    pos_ = 1;
    std::string text;
    Name name;
    bool ok = parse_name(name, /*allow_special=*/true);
    if (ok && at_end()) {
      ok = syntax("the name ends before its encoding");
    }
    if (ok) {
      ok = (peek() >= '0' && peek() <= '3') ? parse_variable(name, text)
                                            : parse_function(name, text);
    }
    if (ok && pos_ != in_.size()) {
      ok = syntax("the name has text after its encoding");
    }
    if (!ok) {
      return error_result();
    }
    if (text.size() > options_.max_output_bytes) {
      return make_error<std::string>(Status::InvalidInput, "demangle.too_large",
                                     "the demangled name is longer than the limit");
    }
    return text;
  }

 private:
  struct Failure {
    std::string code;
    std::string message;
    std::size_t offset = 0;
  };

  bool at_end() const { return pos_ >= in_.size(); }
  char peek(std::size_t ahead = 0) const {
    return pos_ + ahead < in_.size() ? in_[pos_ + ahead] : '\0';
  }
  bool at(char c) const { return !at_end() && in_[pos_] == c; }

  bool fail(std::string code, std::string message) {
    if (!failure_) {
      failure_ = Failure{std::move(code), std::move(message), pos_};
    }
    return false;
  }
  bool syntax(std::string message) { return fail("demangle.syntax", std::move(message)); }
  bool unsupported(std::string message) { return fail("demangle.unsupported", std::move(message)); }

  Result<std::string> error_result() const {
    const Failure& failure = failure_.value_or(Failure{"demangle.syntax", "malformed", 0});
    return make_error<std::string>(Status::InvalidInput, failure.code, failure.message,
                                   static_cast<std::uint64_t>(failure.offset));
  }

  /// A name: an optional special code, then components up to the terminating `@`.
  /// Identifiers join the name table as they are read; digits 0-9 repeat table entries.
  bool parse_name(Name& name, bool allow_special) {
    std::vector<std::string> parts;
    bool is_operator = false;
    bool class_member = false;
    std::string_view operator_text;
    Kind kind = Kind::Operator;
    if (at('?')) {
      if (!allow_special) {
        return syntax("a nested name cannot be a special name");
      }
      ++pos_;
      const std::size_t length = (peek() == '_') ? 2 : 1;
      const std::string_view code = in_.substr(pos_, length);
      const OperatorCode* found = nullptr;
      for (const OperatorCode& entry : kOperators) {
        if (entry.code == code) {
          found = &entry;
          break;
        }
      }
      if (found == nullptr) {
        return unsupported("this special name is not supported");
      }
      pos_ += length;
      is_operator = true;
      operator_text = found->text;
      kind = found->kind;
      class_member = kind != Kind::Operator;
    }
    while (true) {
      if (at_end()) {
        return syntax("a name is not terminated");
      }
      const char c = peek();
      if (c == '@') {
        ++pos_;
        break;
      }
      if (c >= '0' && c <= '9') {
        const std::size_t index = static_cast<std::size_t>(c - '0');
        if (index >= names_.size()) {
          return syntax("a back reference points past the name table");
        }
        parts.push_back(names_[index]);
        ++pos_;
        continue;
      }
      if (c == '?') {
        return unsupported("templates and nested special names are not supported");
      }
      const std::size_t end = in_.find('@', pos_);
      if (end == std::string_view::npos) {
        return syntax("an identifier is not terminated");
      }
      const std::string_view identifier = in_.substr(pos_, end - pos_);
      if (!valid_identifier(identifier)) {
        return syntax("an identifier has a character that is not allowed");
      }
      if (names_.size() < kNameTableSize) {
        names_.emplace_back(identifier);
      }
      parts.emplace_back(identifier);
      pos_ = end + 1;
    }
    if (is_operator) {
      if (class_member) {
        if (parts.empty()) {
          return syntax("a constructor or destructor has no class");
        }
        name.text = kind == Kind::Destructor ? "~" + parts.front() : parts.front();
      } else {
        name.text = std::string(operator_text);
      }
      name.scope = std::move(parts);
      return true;
    }
    if (parts.empty()) {
      return syntax("a name has no components");
    }
    name.text = parts.front();
    name.scope.assign(parts.begin() + 1, parts.end());
    return true;
  }

  /// A type, nested up to `options_.max_depth` levels.
  bool parse_type(Ty& out, int depth) {
    if (depth > options_.max_depth) {
      return fail("demangle.too_deep", "the type nests too deeply");
    }
    if (at_end()) {
      return syntax("a type is missing");
    }
    const char c = peek();
    if (c == 'P' || c == 'Q' || c == 'R' || c == 'S') {
      ++pos_;
      if (at('E')) {
        ++pos_;  // the 64-bit pointer marker
      }
      const std::optional<unsigned> letter = qualifier_letter(peek());
      if (!letter) {
        // `6` is a function type and `Q` or `R` a pointer to a member: neither is in the grammar.
        if (peek() == '6' || peek() == 'Q' || peek() == 'R') {
          return unsupported("pointers to functions and members are not supported");
        }
        return syntax("a pointer has no qualifier letter");
      }
      ++pos_;
      out.ptr = '*';
      out.cv = c == 'Q' ? kConst : c == 'R' ? kVolatile : c == 'S' ? (kConst | kVolatile) : 0U;
      return parse_pointee(out, depth, *letter);
    }
    if (c == 'A' || (c == '$' && peek(1) == '$' && peek(2) == 'Q')) {
      const bool rvalue = c == '$';
      pos_ += rvalue ? 3 : 1;
      if (at('E')) {
        ++pos_;
      }
      const std::optional<unsigned> letter = qualifier_letter(peek());
      if (!letter) {
        return syntax("a reference has no qualifier letter");
      }
      ++pos_;
      out.ptr = rvalue ? 'r' : '&';
      return parse_pointee(out, depth, *letter);
    }
    if (c == 'U' || c == 'V' || c == 'T') {
      ++pos_;
      Name name;
      if (!parse_name(name, /*allow_special=*/false)) {
        return false;
      }
      out.base = (c == 'U' ? "struct " : c == 'V' ? "class " : "union ") + qualified(name);
      return true;
    }
    if (c == 'W') {
      if (peek(1) != '4') {
        return unsupported("this enumeration form is not supported");
      }
      pos_ += 2;
      Name name;
      if (!parse_name(name, /*allow_special=*/false)) {
        return false;
      }
      out.base = "enum " + qualified(name);
      return true;
    }
    if (c == '_') {
      static const std::pair<std::string_view, std::string_view> kTwoLetter[] = {
          {"_N", "bool"},    {"_J", "__int64"},  {"_K", "unsigned __int64"},
          {"_W", "wchar_t"}, {"_S", "char16_t"}, {"_U", "char32_t"},
      };
      const std::string_view code = in_.substr(pos_, 2);
      for (const auto& [key, spelling] : kTwoLetter) {
        if (code == key) {
          pos_ += 2;
          out.base = std::string(spelling);
          return true;
        }
      }
      return unsupported("this builtin type is not supported");
    }
    static const std::pair<char, std::string_view> kOneLetter[] = {
        {'X', "void"},        {'C', "signed char"},    {'D', "char"},  {'E', "unsigned char"},
        {'F', "short"},       {'G', "unsigned short"}, {'H', "int"},   {'I', "unsigned int"},
        {'J', "long"},        {'K', "unsigned long"},  {'M', "float"}, {'N', "double"},
        {'O', "long double"},
    };
    for (const auto& [key, spelling] : kOneLetter) {
      if (c == key) {
        ++pos_;
        out.base = std::string(spelling);
        return true;
      }
    }
    return unsupported("this type code is not supported");
  }

  /// The pointee of a pointer or reference. The qualifier letter describes the pointee.
  bool parse_pointee(Ty& out, int depth, unsigned pointee_cv) {
    out.pointee = std::make_shared<Ty>();
    if (!parse_type(*out.pointee, depth + 1)) {
      return false;
    }
    out.pointee->cv |= pointee_cv;
    return true;
  }

  /// A global (`3`) or static member (`0`-`2`). The storage letter follows the type.
  bool parse_variable(const Name& name, std::string& out) {
    const char storage = peek();
    ++pos_;
    Ty type;
    if (!parse_type(type, 0)) {
      return false;
    }
    if (type.ptr != 0 && at('E')) {
      ++pos_;
    }
    const std::optional<unsigned> letter = qualifier_letter(peek());
    if (!letter) {
      return syntax("a variable has no storage qualifier");
    }
    ++pos_;
    if (type.ptr == 0) {
      type.cv |= *letter;
    }
    out.clear();
    if (storage != '3') {
      out += storage == '2' ? "public: " : storage == '1' ? "protected: " : "private: ";
      out += "static ";
    }
    const std::string spelled = render(type);
    out += spelled;
    if (spelled.empty() || (spelled.back() != '*' && spelled.back() != '&')) {
      out += " ";
    }
    out += qualified(name);
    return true;
  }

  /// A function. The class letter gives access, `static` and `virtual`; member functions
  /// carry the 64-bit `E` marker and a `this` qualifier. Only `__cdecl` is accepted.
  bool parse_function(const Name& name, std::string& out) {
    const char code = peek();
    ++pos_;
    Access access = Access::None;
    bool is_static = false;
    bool is_virtual = false;
    bool has_this = false;
    switch (code) {
      case 'Y':
        break;
      case 'A':
        access = Access::Private;
        has_this = true;
        break;
      case 'C':
        access = Access::Private;
        is_static = true;
        break;
      case 'E':
        access = Access::Private;
        is_virtual = true;
        has_this = true;
        break;
      case 'I':
        access = Access::Protected;
        has_this = true;
        break;
      case 'K':
        access = Access::Protected;
        is_static = true;
        break;
      case 'M':
        access = Access::Protected;
        is_virtual = true;
        has_this = true;
        break;
      case 'Q':
        access = Access::Public;
        has_this = true;
        break;
      case 'S':
        access = Access::Public;
        is_static = true;
        break;
      case 'U':
        access = Access::Public;
        is_virtual = true;
        has_this = true;
        break;
      default:
        return unsupported("this function class is not supported");
    }
    std::optional<unsigned> this_cv;
    if (has_this) {
      if (!at('E')) {
        return unsupported("a 32-bit member function is not supported");
      }
      ++pos_;
      const std::optional<unsigned> letter = qualifier_letter(peek());
      if (!letter) {
        return syntax("a member function has no this qualifier");
      }
      ++pos_;
      this_cv = *letter;
    }
    if (!at('A')) {
      return unsupported("only the __cdecl calling convention is supported");
    }
    ++pos_;

    bool has_return = true;
    std::string return_text;
    if (at('?') && peek(1) == 'A') {
      pos_ += 2;  // the result is returned through a hidden pointer
    } else if (at('@')) {
      ++pos_;  // constructors and destructors have no result type
      has_return = false;
    }
    if (has_return) {
      Ty result;
      if (!parse_type(result, 0)) {
        return false;
      }
      return_text = render(result);
    }

    std::vector<std::string> params;
    bool varargs = false;
    if (at('X') && peek(1) == 'Z') {
      ++pos_;
      params.emplace_back("void");
    } else {
      while (true) {
        if (at_end()) {
          return syntax("the parameter list is not terminated");
        }
        if (at('@')) {
          ++pos_;
          break;
        }
        if (at('Z')) {
          ++pos_;
          varargs = true;
          break;
        }
        Ty param;
        if (!parse_type(param, 0)) {
          return false;
        }
        params.push_back(render(param));
      }
    }
    if (varargs) {
      params.emplace_back("...");
    }
    if (!at('Z')) {
      return syntax("the parameter list is not followed by Z");
    }
    ++pos_;

    out = access_prefix(access);
    if (is_static) {
      out += "static ";
    }
    if (is_virtual) {
      out += "virtual ";
    }
    if (has_return) {
      out += return_text + " ";
    }
    out += "__cdecl " + qualified(name) + "(";
    for (std::size_t i = 0; i < params.size(); ++i) {
      if (i != 0) {
        out += ", ";
      }
      out += params[i];
    }
    out += ")";
    if (this_cv && *this_cv != 0) {
      out += " " + cv_text(*this_cv);
    }
    return true;
  }

  std::string_view in_;
  DemangleOptions options_;
  std::size_t pos_ = 0;
  std::vector<std::string> names_;
  std::optional<Failure> failure_;
};

}  // namespace

bool is_msvc_name(std::string_view name) noexcept {
  return !name.empty() && name[0] == '?';
}

Result<std::string> demangle_msvc(std::string_view name, const DemangleOptions& options) {
  MsvcParser parser(name, options);
  return parser.run();
}

}  // namespace donkey
