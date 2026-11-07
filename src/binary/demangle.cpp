#include "donkey/binary/demangle.h"

#include <algorithm>
#include <cstdint>
#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace donkey {
namespace {

// The tree the parser builds. Children and text depend on the kind; see each kind.
struct Node {
  enum class Kind : std::uint8_t {
    Text,             // a name or builtin type spelling in `text`
    Scope,            // children: prefix, component (printed with "::")
    Template,         // children: template name, then the arguments
    Qualified,        // cv in `cv`; children: the qualified type
    Pointer,          // children: pointee
    Reference,        // children: referenced type
    RvalueReference,  // children: referenced type
    Function,         // children: name, [return type if has_return], parameters...
    Array,            // text: the dimension; children: element type
    MemberPointer,    // children: class, member type
    Pack,             // children: elements, printed separated by ", "
    Literal,          // text: the printed value
    Special,          // text: a prefix such as "vtable for "; children: the operand
  };
  Kind kind = Kind::Text;
  std::string text;
  std::vector<Node*> children;
  unsigned cv = 0;          // Qualified: 1 const, 2 volatile, 4 restrict; Function: member cv
  unsigned ref = 0;         // Function: 1 for `&`, 2 for `&&`
  bool has_return = false;  // Function: children[1] is the return type
};

constexpr unsigned kConst = 1;
constexpr unsigned kVolatile = 2;
constexpr unsigned kRestrict = 4;

/// What a name parse learns beyond the name itself.
struct NameInfo {
  unsigned cv = 0;
  unsigned ref = 0;
  bool is_template = false;  // the final component has template arguments
  bool is_ctor_dtor_or_conv = false;
  std::string base;              // the final component's name without template arguments
  std::vector<Node*> last_args;  // the template arguments of the last template component
};

std::string cv_text(unsigned cv) {
  std::string text;
  if ((cv & kConst) != 0) {
    text += "const";
  }
  if ((cv & kVolatile) != 0) {
    text += text.empty() ? "volatile" : " volatile";
  }
  if ((cv & kRestrict) != 0) {
    text += text.empty() ? "restrict" : " restrict";
  }
  return text;
}

/// `base` with the declarator `inner` attached the way C spells it: `int*`, `int (*)(int)`,
/// `int [4]`, `char const*`.
std::string compose(const std::string& base, const std::string& inner) {
  if (inner.empty()) {
    return base;
  }
  if (inner.front() == '*' || inner.front() == '&') {
    return base + inner;
  }
  return base + " " + inner;
}

bool is_declarator_wrapper(const Node* node) {
  return node->kind == Node::Kind::Function || node->kind == Node::Kind::Array;
}

class Printer {
 public:
  std::string show(const Node* node) const {
    switch (node->kind) {
      case Node::Kind::Text:
      case Node::Kind::Literal:
        return node->text;
      case Node::Kind::Scope: {
        // A local name prints its enclosing function without the return type:
        // `f<char const*>(char const*)::Guard::Guard()`.
        const Node* left = node->children[0];
        const std::string prefix =
            left->kind == Node::Kind::Function ? function_text(left, false) : show(left);
        return prefix + "::" + show(node->children[1]);
      }
      case Node::Kind::Template: {
        std::string text = show(node->children[0]);
        // `operator<` followed by template arguments is spelled `operator< <...>`.
        text += (!text.empty() && text.back() == '<') ? " <" : "<";
        text += arguments(node);
        if (!text.empty() && text.back() == '>') {
          text += ' ';
        }
        return text + ">";
      }
      case Node::Kind::Special: {
        // A thunk's operand is a named encoding (`non-virtual thunk to Foo::bar()`), so it
        // prints as a function with its name, not as a bare function type.
        const Node* operand = node->children[0];
        return node->text +
               (operand->kind == Node::Kind::Function ? function_text(operand) : type(operand, ""));
      }
      case Node::Kind::Function:
        return function_text(node);
      case Node::Kind::Pack: {
        std::string text;
        for (std::size_t i = 0; i < node->children.size(); ++i) {
          text += (i == 0 ? "" : ", ") + type(node->children[i], "");
        }
        return text;
      }
      default:
        return type(node, "");
    }
  }

  /// The spelling of a type with the declarator `inner` (empty for an abstract type).
  std::string type(const Node* node, const std::string& inner) const {
    switch (node->kind) {
      case Node::Kind::Text:
        return compose(node->text, inner);
      case Node::Kind::Qualified: {
        const Node* target = node->children[0];
        const std::string qualifiers = cv_text(node->cv);
        if (target->kind == Node::Kind::Pointer || target->kind == Node::Kind::Reference) {
          // A qualified pointer: `char* const`, the qualifier follows the star.
          // A declarator that starts with a star or ampersand attaches directly.
          std::string declarator = " " + qualifiers;
          if (!inner.empty()) {
            declarator += (inner.front() == '*' || inner.front() == '&') ? inner : " " + inner;
          }
          return type(target, declarator);
        }
        return compose(type(target, "") + " " + qualifiers, inner);
      }
      case Node::Kind::Pointer:
        return type_with_declarator(node->children[0], "*" + inner);
      case Node::Kind::Reference:
      case Node::Kind::RvalueReference:
        return reference_text(node, inner);
      case Node::Kind::Array: {
        // c++filt puts a space before the bound of an array declarator that follows a
        // parenthesised declarator (`char const (&) [2]`), but not between dimensions
        // (`int [2][3]`).
        const bool parenthesised = !inner.empty() && inner.front() == '(';
        return type(node->children[0], inner + (parenthesised ? " " : "") + "[" + node->text + "]");
      }
      case Node::Kind::MemberPointer:
        return type(node->children[1], show(node->children[0]) + "::*" + inner);
      case Node::Kind::Function: {
        // A function type: its return type, then the parameters in parentheses.
        const std::size_t first_param = node->has_return ? 2 : 1;
        std::string params = parameter_list(node, first_param);
        std::string decl = inner + "(" + params + ")";
        if ((node->cv & kConst) != 0) {
          decl += " const";
        }
        if (node->ref == 1) {
          decl += " &";
        } else if (node->ref == 2) {
          decl += " &&";
        }
        if (!node->has_return) {
          return decl;
        }
        return compose(type(node->children[1], ""), decl);
      }
      case Node::Kind::Template:
      case Node::Kind::Scope:
      case Node::Kind::Special:
      case Node::Kind::Literal:
      case Node::Kind::Pack:
        return compose(show(node), inner);
    }
    return inner;
  }

 private:
  // A reference to a reference collapses: `&` applied to anything is `&`, and `&&` is
  // `&&` only when every reference in the chain is an rvalue reference.
  std::string reference_text(const Node* node, const std::string& inner) const {
    bool rvalue = node->kind == Node::Kind::RvalueReference;
    const Node* target = node->children[0];
    while (target->kind == Node::Kind::Reference || target->kind == Node::Kind::RvalueReference) {
      rvalue = rvalue && target->kind == Node::Kind::RvalueReference;
      target = target->children[0];
    }
    return type_with_declarator(target, (rvalue ? "&&" : "&") + inner);
  }

  std::string type_with_declarator(const Node* target, const std::string& inner) const {
    if (is_declarator_wrapper(target)) {
      // A pointer to a function or array needs parentheses: `void (*)(int)`.
      return type(target, "(" + inner + ")");
    }
    return type(target, inner);
  }

  std::string arguments(const Node* template_node) const {
    std::string text;
    for (std::size_t i = 1; i < template_node->children.size(); ++i) {
      text += (i == 1 ? "" : ", ") + type(template_node->children[i], "");
    }
    return text;
  }

  std::string parameter_list(const Node* function, std::size_t first) const {
    if (function->children.size() <= first) {
      return "";
    }
    std::string text;
    for (std::size_t i = first; i < function->children.size(); ++i) {
      text += (i == first ? "" : ", ") + type(function->children[i], "");
    }
    return text;
  }

  std::string function_text(const Node* node, bool with_return = true) const {
    std::string text = show(node->children[0]);
    text += "(" + parameter_list(node, node->has_return ? 2 : 1) + ")";
    if ((node->cv & kConst) != 0) {
      text += " const";
    }
    if (node->ref == 1) {
      text += " &";
    } else if (node->ref == 2) {
      text += " &&";
    }
    if (!node->has_return || !with_return) {
      return text;
    }
    if (returns_array(node->children[1])) {
      // c++filt puts the name inside the return type's declarator:
      // `char const (&f()) [2]`, not `char const (&)[2] f()`.
      return type(node->children[1], text);
    }
    return type(node->children[1], "") + " " + text;
  }

  // True when a return type is an array, or a pointer or reference to one.
  static bool returns_array(const Node* node) {
    while (node->kind == Node::Kind::Pointer || node->kind == Node::Kind::Reference ||
           node->kind == Node::Kind::RvalueReference) {
      node = node->children[0];
    }
    return node->kind == Node::Kind::Array;
  }
};

class Parser {
 public:
  Parser(std::string_view input, const DemangleOptions& options)
      : input_(input), options_(options) {}

  Result<std::string> run() {
    if (input_.size() > options_.max_input_bytes) {
      return make_error<std::string>(Status::InvalidInput, "demangle.too_long",
                                     "the name is longer than the limit");
    }
    if (!is_itanium_name(input_)) {
      return make_error<std::string>(Status::InvalidInput, "demangle.not_mangled",
                                     "the name does not start with _Z");
    }
    pos_ = 2;
    Node* encoding = parse_encoding();
    if (encoding == nullptr) {
      return fail();
    }
    if (pos_ != input_.size()) {
      // Clone suffixes such as `.cold` and `.isra.0` follow the encoding.
      if (input_[pos_] == '.') {
        clone_suffix_ = std::string(input_.substr(pos_));
      } else {
        error_ = "unexpected text after the name";
        return fail();
      }
    }
    std::string text = printer_.show(encoding);
    if (!clone_suffix_.empty()) {
      text += " [clone " + clone_suffix_ + "]";
    }
    if (text.size() > options_.max_output_bytes) {
      return make_error<std::string>(Status::InvalidInput, "demangle.too_large",
                                     "the demangled name is larger than the limit");
    }
    return text;
  }

 private:
  Result<std::string> fail() const {
    return make_error<std::string>(
        Status::InvalidInput, error_code_.empty() ? "demangle.syntax" : error_code_,
        error_.empty() ? "the name is not valid Itanium C++ ABI" : error_);
  }

  Node* make(Node::Kind kind, std::string text = {}, std::vector<Node*> children = {}) {
    arena_.emplace_back();
    Node* node = &arena_.back();
    node->kind = kind;
    node->text = std::move(text);
    node->children = std::move(children);
    return node;
  }

  Node* text_node(std::string text) { return make(Node::Kind::Text, std::move(text)); }

  Node* fail_node(const char* code, const char* message) {
    if (error_.empty()) {
      error_code_ = code;
      error_ = message;
    }
    return nullptr;
  }

  static bool is_letter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

  bool at_end() const { return pos_ >= input_.size(); }
  char peek(std::size_t ahead = 0) const {
    return pos_ + ahead < input_.size() ? input_[pos_ + ahead] : '\0';
  }
  bool eat(char c) {
    if (peek() == c) {
      ++pos_;
      return true;
    }
    return false;
  }

  struct DepthGuard {
    Parser& parser;
    explicit DepthGuard(Parser& p) : parser(p) { ++parser.depth_; }
    ~DepthGuard() { --parser.depth_; }
    bool too_deep() const { return parser.depth_ > parser.options_.max_depth; }
  };

  void add_candidate(Node* node) {
    if (node != nullptr) {
      candidates_.push_back(node);
    }
  }

  // <encoding>: a name with, for a function, its parameter types.
  Node* parse_encoding() {
    DepthGuard guard(*this);
    if (guard.too_deep()) {
      return fail_node("demangle.too_deep", "the name nests too deeply");
    }
    if (peek() == 'T' || peek() == 'G') {
      return parse_special();
    }
    NameInfo info;
    Node* name = parse_name(info);
    if (name == nullptr) {
      return nullptr;
    }
    if (info.last_args.size() > 0 || info.is_template) {
      template_args_ = info.last_args;
    }
    if (at_end() || peek() == 'E' || peek() == '.') {
      return name;  // a data object, or the end of a local name's entity
    }
    Node* ret = nullptr;
    if (info.is_template && !info.is_ctor_dtor_or_conv) {
      ret = parse_type();
      if (ret == nullptr) {
        return nullptr;
      }
    }
    std::vector<Node*> params;
    while (!at_end() && peek() != 'E' && peek() != '.') {
      Node* param = parse_type();
      if (param == nullptr) {
        return nullptr;
      }
      params.push_back(param);
    }
    // A lone `void` parameter means no parameters.
    if (params.size() == 1 && params[0]->kind == Node::Kind::Text && params[0]->text == "void") {
      params.clear();
    }
    Node* function = make(Node::Kind::Function, "", {name});
    function->has_return = ret != nullptr;
    if (ret != nullptr) {
      function->children.push_back(ret);
    }
    function->children.insert(function->children.end(), params.begin(), params.end());
    function->cv = info.cv;
    function->ref = info.ref;
    return function;
  }

  // The special names: vtables, typeinfo, guard variables and thunks.
  Node* parse_special() {
    if (peek() == 'T' && peek(1) == 'V') {
      pos_ += 2;
      Node* operand = parse_type();
      return operand == nullptr ? nullptr : make(Node::Kind::Special, "vtable for ", {operand});
    }
    if (peek() == 'T' && peek(1) == 'I') {
      pos_ += 2;
      Node* operand = parse_type();
      return operand == nullptr ? nullptr : make(Node::Kind::Special, "typeinfo for ", {operand});
    }
    if (peek() == 'T' && peek(1) == 'S') {
      pos_ += 2;
      Node* operand = parse_type();
      return operand == nullptr ? nullptr
                                : make(Node::Kind::Special, "typeinfo name for ", {operand});
    }
    if (peek() == 'G' && peek(1) == 'V') {
      pos_ += 2;
      NameInfo info;
      Node* name = parse_name(info);
      return name == nullptr ? nullptr : make(Node::Kind::Special, "guard variable for ", {name});
    }
    if (peek() == 'T' && (peek(1) == 'h' || peek(1) == 'v')) {
      const bool virtual_thunk = peek(1) == 'v';
      pos_ += 2;
      // Skip the offsets: `n<number>_` or, for virtual thunks, `<number>_<number>_`.
      while (!at_end() && peek() != '_') {
        ++pos_;
      }
      if (!eat('_')) {
        return fail_node("demangle.syntax", "a thunk has no offset terminator");
      }
      if (virtual_thunk) {
        while (!at_end() && peek() != '_') {
          ++pos_;
        }
        if (!eat('_')) {
          return fail_node("demangle.syntax", "a virtual thunk has no offset terminator");
        }
      }
      Node* target = parse_encoding();
      if (target == nullptr) {
        return nullptr;
      }
      return make(Node::Kind::Special,
                  virtual_thunk ? "virtual thunk to " : "non-virtual thunk to ", {target});
    }
    return fail_node("demangle.unsupported", "this special name is not supported");
  }

  // <name>: nested, local, substitution-prefixed or unscoped.
  Node* parse_name(NameInfo& info) {
    DepthGuard guard(*this);
    if (guard.too_deep()) {
      return fail_node("demangle.too_deep", "the name nests too deeply");
    }
    if (peek() == 'N') {
      return parse_nested(info);
    }
    if (peek() == 'Z') {
      return parse_local(info);
    }
    Node* prefix = nullptr;
    if (peek() == 'S' && peek(1) == 't') {
      pos_ += 2;
      prefix = text_node("std");
    }
    Node* component = nullptr;
    if (prefix == nullptr && peek() == 'S') {
      component = parse_substitution();
      if (component == nullptr) {
        return nullptr;
      }
      // A substitution can name a template that is followed by arguments.
      if (peek() == 'I') {
        return finish_template(component, info, is_candidate(component));
      }
      info.base = component->kind == Node::Kind::Text ? component->text : std::string();
      return component;
    }
    component = parse_unqualified(info.base);
    if (component == nullptr) {
      return nullptr;
    }
    if (prefix != nullptr) {
      component = make(Node::Kind::Scope, "", {prefix, component});
    }
    info.base = base_name(component);
    info.is_ctor_dtor_or_conv = last_was_special_;
    if (peek() == 'I') {
      // `St` (std::) is not a substitution candidate. The template name `std::name` is, and
      // finish_template adds it.
      return finish_template(component, info);
    }
    info.is_template = false;
    info.last_args.clear();
    return component;
  }

  bool is_candidate(const Node* node) const {
    return std::find(candidates_.begin(), candidates_.end(), node) != candidates_.end();
  }

  // A template name is a candidate, unless it is one of the abbreviations (`Sa`, `Sb`,
  // `Si`, `So`, `Sd`), which are not substitutable on their own.
  Node* finish_template(Node* component, NameInfo& info, bool name_is_candidate = true) {
    if (name_is_candidate) {
      add_candidate(component);
    }
    std::vector<Node*> args = parse_template_args();
    if (args.empty() && !error_.empty()) {
      return nullptr;
    }
    info.is_template = true;
    info.last_args = args;
    std::vector<Node*> children{component};
    children.insert(children.end(), args.begin(), args.end());
    return make(Node::Kind::Template, "", std::move(children));
  }

  // The name of the last component without its template arguments, used for constructors.
  std::string base_name(const Node* node) const {
    if (node->kind == Node::Kind::Scope) {
      return base_name(node->children[1]);
    }
    if (node->kind == Node::Kind::Template) {
      return base_name(node->children[0]);
    }
    return node->text;
  }

  Node* parse_nested(NameInfo& info) {
    eat('N');
    info.cv = 0;
    while (peek() == 'r' || peek() == 'V' || peek() == 'K') {
      info.cv |= peek() == 'r' ? kRestrict : peek() == 'V' ? kVolatile : kConst;
      ++pos_;
    }
    info.ref = 0;
    if (peek() == 'R') {
      info.ref = 1;
      ++pos_;
    } else if (peek() == 'O') {
      info.ref = 2;
      ++pos_;
    }
    Node* current = nullptr;
    std::string class_name;
    info.is_template = false;
    info.last_args.clear();
    while (!at_end() && peek() != 'E') {
      if (peek() == 'I') {
        if (current == nullptr) {
          return fail_node("demangle.syntax", "template arguments with no name");
        }
        std::vector<Node*> args = parse_template_args();
        if (args.empty() && !error_.empty()) {
          return nullptr;
        }
        info.is_template = true;
        info.last_args = args;
        std::vector<Node*> children{current};
        children.insert(children.end(), args.begin(), args.end());
        current = make(Node::Kind::Template, "", std::move(children));
        if (peek() != 'E') {
          add_candidate(current);
        }
        continue;
      }
      Node* component = nullptr;
      if (peek() == 'S' && peek(1) == 't') {
        // `St` is the std:: namespace, which is not a candidate.
        if (current != nullptr) {
          return fail_node("demangle.syntax", "std:: inside a nested name");
        }
        pos_ += 2;
        current = text_node("std");
        continue;
      }
      if (peek() == 'S') {
        if (current != nullptr) {
          return fail_node("demangle.syntax", "a substitution inside a nested name");
        }
        component = parse_substitution();
        if (component == nullptr) {
          return nullptr;
        }
        info.is_template = false;
        info.last_args.clear();
      } else if (peek() == 'T') {
        if (current != nullptr) {
          return fail_node("demangle.syntax", "a template parameter inside a nested name");
        }
        component = parse_template_param();
        if (component == nullptr) {
          return nullptr;
        }
        info.is_template = false;
        info.last_args.clear();
      } else {
        component = parse_unqualified(class_name);
        if (component == nullptr) {
          return nullptr;
        }
        info.is_template = false;
        info.last_args.clear();
        info.is_ctor_dtor_or_conv = last_was_special_;
        if (current != nullptr) {
          component = make(Node::Kind::Scope, "", {current, component});
        }
        class_name = base_name(component);
        if (peek() != 'E') {
          // Every prefix that is followed by more is a candidate, including a template
          // name before its arguments.
          add_candidate(component);
        }
        current = component;
        continue;
      }
      current = current == nullptr ? component : make(Node::Kind::Scope, "", {current, component});
    }
    if (!eat('E')) {
      return fail_node("demangle.syntax", "a nested name is not closed");
    }
    if (current == nullptr) {
      return fail_node("demangle.syntax", "an empty nested name");
    }
    info.base = base_name(current);
    return current;
  }

  Node* parse_local(NameInfo& info) {
    eat('Z');
    Node* encoding = parse_encoding();
    if (encoding == nullptr) {
      return nullptr;
    }
    if (!eat('E')) {
      return fail_node("demangle.syntax", "a local name is not closed");
    }
    Node* entity = nullptr;
    if (peek() == 's') {
      ++pos_;
      entity = text_node("string literal");
    } else {
      NameInfo inner;
      entity = parse_name(inner);
      if (entity == nullptr) {
        return nullptr;
      }
      info.base = inner.base;
      info.is_template = inner.is_template;
      info.last_args = inner.last_args;
      // The entity's qualifiers (`NK...E` for a const operator()) qualify the function.
      info.cv = inner.cv;
      info.ref = inner.ref;
    }
    // A discriminator (`_0`, `__12_`) distinguishes entities with the same name.
    if (peek() == '_') {
      ++pos_;
      if (peek() == '_') {
        ++pos_;
        while (!at_end() && peek() != '_') {
          ++pos_;
        }
        if (!eat('_')) {
          return fail_node("demangle.syntax", "a discriminator is not closed");
        }
      } else {
        while (!at_end() && peek() >= '0' && peek() <= '9') {
          ++pos_;
        }
      }
    }
    return make(Node::Kind::Scope, "", {encoding, entity});
  }

  // <unqualified-name>: a source name, an operator, a constructor or destructor, a lambda
  // or an unnamed type. `class_name` is the enclosing class, for constructors.
  Node* parse_unqualified(const std::string& class_name) {
    last_was_special_ = false;
    if (peek() >= '0' && peek() <= '9') {
      std::string name;
      if (!parse_source_name(name)) {
        return nullptr;
      }
      // ABI tags (`B5cxx11`) print as `[abi:cxx11]` after the name they belong to.
      while (peek() == 'B') {
        ++pos_;
        std::string tag;
        if (!parse_source_name(tag)) {
          return nullptr;
        }
        name += "[abi:" + tag + "]";
      }
      return text_node(name);
    }
    if (peek() == 'C' && peek(1) == 'I' && peek(2) >= '1' && peek(2) <= '5') {
      // An inheriting constructor names the base class's constructor.
      pos_ += 3;
      Node* base = parse_type();
      if (base == nullptr) {
        return nullptr;
      }
      last_was_special_ = true;
      return text_node(base_name(base));
    }
    if (peek() == 'C' && peek(1) >= '1' && peek(1) <= '5') {
      if (class_name.empty()) {
        return fail_node("demangle.syntax", "a constructor with no class");
      }
      pos_ += 2;
      last_was_special_ = true;
      return text_node(class_name);
    }
    if (peek() == 'D' && peek(1) >= '0' && peek(1) <= '5') {
      if (class_name.empty()) {
        return fail_node("demangle.syntax", "a destructor with no class");
      }
      pos_ += 2;
      last_was_special_ = true;
      return text_node("~" + class_name);
    }
    if (peek() == 'L') {
      ++pos_;  // internal linkage: the name follows unchanged
      return parse_unqualified(class_name);
    }
    if (peek() == 'U' && peek(1) == 'l') {
      pos_ += 2;
      return parse_lambda();
    }
    if (peek() == 'U' && peek(1) == 't') {
      pos_ += 2;
      std::size_t number = unnamed_number();
      return text_node("{unnamed type#" + std::to_string(number) + "}");
    }
    if (peek() == 'c' && peek(1) == 'v') {
      pos_ += 2;
      Node* type = parse_type();
      if (type == nullptr) {
        return nullptr;
      }
      last_was_special_ = true;
      return make(Node::Kind::Special, "operator ", {type});
    }
    if (peek() == 'l' && peek(1) == 'i') {
      pos_ += 2;
      std::string name;
      if (!parse_source_name(name)) {
        return nullptr;
      }
      return text_node("operator\"\" " + name);
    }
    static const struct {
      const char* code;
      const char* text;
    } kOperators[] = {
        {"nw", "operator new"},      {"na", "operator new[]"}, {"dl", "operator delete"},
        {"da", "operator delete[]"}, {"ps", "operator+"},      {"ng", "operator-"},
        {"ad", "operator&"},         {"de", "operator*"},      {"co", "operator~"},
        {"pl", "operator+"},         {"mi", "operator-"},      {"ml", "operator*"},
        {"dv", "operator/"},         {"rm", "operator%"},      {"an", "operator&"},
        {"or", "operator|"},         {"eo", "operator^"},      {"aS", "operator="},
        {"pL", "operator+="},        {"mI", "operator-="},     {"mL", "operator*="},
        {"dV", "operator/="},        {"rM", "operator%="},     {"aN", "operator&="},
        {"oR", "operator|="},        {"eO", "operator^="},     {"ls", "operator<<"},
        {"rs", "operator>>"},        {"lS", "operator<<="},    {"rS", "operator>>="},
        {"eq", "operator=="},        {"ne", "operator!="},     {"lt", "operator<"},
        {"gt", "operator>"},         {"le", "operator<="},     {"ge", "operator>="},
        {"ss", "operator<=>"},       {"nt", "operator!"},      {"aa", "operator&&"},
        {"oo", "operator||"},        {"pp", "operator++"},     {"mm", "operator--"},
        {"cm", "operator,"},         {"pm", "operator->*"},    {"pt", "operator->"},
        {"cl", "operator()"},        {"ix", "operator[]"},     {"qu", "operator?"},
    };
    if (is_letter(peek()) && is_letter(peek(1))) {
      for (const auto& op : kOperators) {
        if (peek() == op.code[0] && peek(1) == op.code[1]) {
          pos_ += 2;
          return text_node(op.text);
        }
      }
    }
    return fail_node("demangle.syntax", "an unqualified name is not valid");
  }

  bool parse_source_name(std::string& out) {
    std::size_t length = 0;
    if (!(peek() >= '0' && peek() <= '9')) {
      fail_node("demangle.syntax", "a source name has no length");
      return false;
    }
    while (peek() >= '0' && peek() <= '9') {
      length = length * 10 + static_cast<std::size_t>(peek() - '0');
      if (length > input_.size()) {
        fail_node("demangle.syntax", "a source name is longer than the name");
        return false;
      }
      ++pos_;
    }
    if (length == 0 || pos_ + length > input_.size()) {
      fail_node("demangle.syntax", "a source name runs past the end of the name");
      return false;
    }
    std::string_view identifier = input_.substr(pos_, length);
    pos_ += length;
    if (identifier.substr(0, 9) == "_GLOBAL__" && identifier.size() >= 11 && identifier[9] == 'N') {
      out = "(anonymous namespace)";
    } else {
      out = std::string(identifier);
    }
    return true;
  }

  // An unnamed lambda: `Ul <parameter types> E [number] _`. Its printed name numbers it
  // from one, and the number in the name is one less than the printed number minus one.
  Node* parse_lambda() {
    // A `T_` inside the parameters of a generic lambda names the lambda's own template
    // parameter, not one of the enclosing function's. That is not modelled, so it is refused.
    struct Restore {
      bool& flag;
      bool saved;
      ~Restore() { flag = saved; }
    } restore{in_lambda_parameters_, in_lambda_parameters_};
    in_lambda_parameters_ = true;
    std::vector<Node*> params;
    while (!at_end() && peek() != 'E') {
      Node* param = parse_type();
      if (param == nullptr) {
        return nullptr;
      }
      params.push_back(param);
    }
    if (!eat('E')) {
      return fail_node("demangle.syntax", "a lambda's parameters are not closed");
    }
    const std::size_t number = unnamed_number();
    std::string text = "{lambda(";
    for (std::size_t i = 0; i < params.size(); ++i) {
      text += (i == 0 ? "" : ", ") + printer_.type(params[i], "");
    }
    if (params.size() == 1 && params[0]->kind == Node::Kind::Text && params[0]->text == "void") {
      text = "{lambda(";  // a lambda with no parameters prints as `()`
    }
    text += ")#" + std::to_string(number) + "}";
    return text_node(text);
  }

  // The discriminator of an unnamed entity: none is 1, `n_` is n + 2.
  std::size_t unnamed_number() {
    std::size_t number = 1;
    if (peek() != '_') {
      std::size_t value = 0;
      while (peek() >= '0' && peek() <= '9') {
        value = value * 10 + static_cast<std::size_t>(peek() - '0');
        ++pos_;
      }
      number = value + 2;
    }
    eat('_');
    return number;
  }

  // <type>.
  Node* parse_type() {
    DepthGuard guard(*this);
    if (guard.too_deep()) {
      return fail_node("demangle.too_deep", "the name nests too deeply");
    }
    const char c = peek();
    if (const char* builtin = builtin_type(c)) {
      ++pos_;
      return text_node(builtin);
    }
    switch (c) {
      case 'u': {
        ++pos_;
        std::string name;
        if (!parse_source_name(name)) {
          return nullptr;
        }
        return text_node(name);
      }
      case 'D': {
        const char d = peek(1);
        pos_ += 2;
        switch (d) {
          case 'n':
            return text_node("decltype(nullptr)");
          case 'a':
            return text_node("auto");
          case 'c':
            return text_node("decltype(auto)");
          case 'd':
            return text_node("decimal64");
          case 'e':
            return text_node("decimal128");
          case 'f':
            return text_node("decimal32");
          case 'h':
            return text_node("half");
          case 'i':
            return text_node("char32_t");
          case 's':
            return text_node("char16_t");
          case 'u':
            return text_node("char8_t");
          case 'p':
            return parse_pack_expansion();
          default:
            return fail_node("demangle.unsupported", "this extended type is not supported");
        }
      }
      case 'r':
      case 'V':
      case 'K': {
        unsigned cv = 0;
        while (peek() == 'r' || peek() == 'V' || peek() == 'K') {
          cv |= peek() == 'r' ? kRestrict : peek() == 'V' ? kVolatile : kConst;
          ++pos_;
        }
        Node* target = parse_type();
        if (target == nullptr) {
          return nullptr;
        }
        Node* qualified = make(Node::Kind::Qualified, "", {target});
        qualified->cv = cv;
        add_candidate(qualified);
        return qualified;
      }
      case 'P':
      case 'R':
      case 'O': {
        ++pos_;
        Node* target = parse_type();
        if (target == nullptr) {
          return nullptr;
        }
        Node* wrapper = make(c == 'P'   ? Node::Kind::Pointer
                             : c == 'R' ? Node::Kind::Reference
                                        : Node::Kind::RvalueReference,
                             "", {target});
        add_candidate(wrapper);
        return wrapper;
      }
      case 'F': {
        ++pos_;
        eat('Y');
        Node* ret = parse_type();
        if (ret == nullptr) {
          return nullptr;
        }
        Node* function = make(Node::Kind::Function, "", {nullptr});
        function->has_return = true;
        function->children.push_back(ret);
        // The name slot of a function type is unused; print it as nothing.
        function->children[0] = text_node("");
        unsigned ref = 0;
        while (!at_end() && peek() != 'E') {
          if (peek() == 'R' && peek(1) == 'E') {
            ref = 1;
            ++pos_;
            break;
          }
          if (peek() == 'O' && peek(1) == 'E') {
            ref = 2;
            ++pos_;
            break;
          }
          Node* param = parse_type();
          if (param == nullptr) {
            return nullptr;
          }
          function->children.push_back(param);
        }
        if (function->children.size() == 3 && function->children[2]->kind == Node::Kind::Text &&
            function->children[2]->text == "void") {
          function->children.pop_back();
        }
        function->ref = ref;
        if (!eat('E')) {
          return fail_node("demangle.syntax", "a function type is not closed");
        }
        add_candidate(function);
        return function;
      }
      case 'A': {
        ++pos_;
        std::string dimension;
        while (peek() >= '0' && peek() <= '9') {
          dimension += peek();
          ++pos_;
        }
        if (!eat('_')) {
          return fail_node("demangle.syntax", "an array has no element separator");
        }
        Node* element = parse_type();
        if (element == nullptr) {
          return nullptr;
        }
        Node* array = make(Node::Kind::Array, dimension, {element});
        add_candidate(array);
        return array;
      }
      case 'M': {
        ++pos_;
        Node* klass = parse_type();
        Node* member = klass == nullptr ? nullptr : parse_type();
        if (member == nullptr) {
          return nullptr;
        }
        Node* pointer = make(Node::Kind::MemberPointer, "", {klass, member});
        add_candidate(pointer);
        return pointer;
      }
      case 'T': {
        Node* param = parse_template_param();
        if (param == nullptr) {
          return nullptr;
        }
        if (peek() == 'I') {
          return fail_node("demangle.unsupported", "a template template parameter");
        }
        return param;
      }
      case 'S': {
        Node* sub = nullptr;
        if (peek(1) == 't') {
          pos_ += 2;
          NameInfo info;
          Node* name = parse_unqualified(std::string());
          if (name == nullptr) {
            return nullptr;
          }
          sub = make(Node::Kind::Scope, "", {text_node("std"), name});
          info.base = base_name(sub);
          if (peek() == 'I') {
            Node* templated = finish_template(sub, info);
            if (templated == nullptr) {
              return nullptr;
            }
            add_candidate(templated);
            return templated;
          }
          add_candidate(sub);
          return sub;
        }
        sub = parse_substitution();
        if (sub == nullptr) {
          return nullptr;
        }
        if (peek() == 'I') {
          NameInfo info;
          Node* templated = finish_template(sub, info, is_candidate(sub));
          if (templated == nullptr) {
            return nullptr;
          }
          add_candidate(templated);
          return templated;
        }
        return sub;
      }
      case 'N':
      case 'Z':
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9': {
        NameInfo info;
        Node* name = parse_name(info);
        if (name == nullptr) {
          return nullptr;
        }
        add_candidate(name);
        return name;
      }
      default:
        return fail_node("demangle.syntax", "a type is not valid");
    }
  }

  static const char* builtin_type(char c) {
    switch (c) {
      case 'v':
        return "void";
      case 'w':
        return "wchar_t";
      case 'b':
        return "bool";
      case 'c':
        return "char";
      case 'a':
        return "signed char";
      case 'h':
        return "unsigned char";
      case 's':
        return "short";
      case 't':
        return "unsigned short";
      case 'i':
        return "int";
      case 'j':
        return "unsigned int";
      case 'l':
        return "long";
      case 'm':
        return "unsigned long";
      case 'x':
        return "long long";
      case 'y':
        return "unsigned long long";
      case 'n':
        return "__int128";
      case 'o':
        return "unsigned __int128";
      case 'f':
        return "float";
      case 'd':
        return "double";
      case 'e':
        return "long double";
      case 'g':
        return "__float128";
      case 'z':
        return "...";
      default:
        return nullptr;
    }
  }

  // S_, S<n>_ and the abbreviations St, Sa, Sb, Ss, Si, So and Sd.
  Node* parse_substitution() {
    if (!eat('S')) {
      return fail_node("demangle.syntax", "a substitution does not start with S");
    }
    const char c = peek();
    switch (c) {
      case 'a':
        ++pos_;
        return text_node("std::allocator");
      case 'b':
        ++pos_;
        return text_node("std::basic_string");
      case 's':
        ++pos_;
        return text_node("std::string");
      case 'i':
        ++pos_;
        return text_node("std::istream");
      case 'o':
        ++pos_;
        return text_node("std::ostream");
      case 'd':
        ++pos_;
        return text_node("std::iostream");
      default:
        break;
    }
    std::size_t index = 0;
    if (c != '_') {
      // A base-36 number, digits then capital letters, plus one.
      while (!at_end() && peek() != '_') {
        const char d = peek();
        int value = 0;
        if (d >= '0' && d <= '9') {
          value = d - '0';
        } else if (d >= 'A' && d <= 'Z') {
          value = d - 'A' + 10;
        } else {
          return fail_node("demangle.syntax", "a substitution index is not valid");
        }
        index = index * 36 + static_cast<std::size_t>(value);
        ++pos_;
      }
      index += 1;
    }
    if (!eat('_')) {
      return fail_node("demangle.syntax", "a substitution is not closed");
    }
    if (index >= candidates_.size()) {
      return fail_node("demangle.syntax", "a substitution refers to nothing");
    }
    return candidates_[index];
  }

  Node* parse_template_param() {
    if (!eat('T')) {
      return fail_node("demangle.syntax", "a template parameter does not start with T");
    }
    std::size_t index = 0;
    if (peek() != '_') {
      while (peek() >= '0' && peek() <= '9') {
        index = index * 10 + static_cast<std::size_t>(peek() - '0');
        ++pos_;
      }
      index += 1;
    }
    if (!eat('_')) {
      return fail_node("demangle.syntax", "a template parameter is not closed");
    }
    if (in_lambda_parameters_) {
      return fail_node("demangle.unsupported",
                       "a generic lambda's template parameter is not supported");
    }
    if (index >= template_args_.size()) {
      return fail_node("demangle.syntax", "a template parameter has no argument");
    }
    Node* argument = template_args_[index];
    if (argument == override_pack_) {
      // While a pack expansion is being printed for one element, that element stands in.
      return override_element_;
    }
    if (argument->kind == Node::Kind::Pack) {
      last_pack_ = argument;
    }
    add_candidate(argument);
    return argument;
  }

  // <template-args>: I <arg>... E.
  std::vector<Node*> parse_template_args() {
    std::vector<Node*> args;
    if (!eat('I')) {
      fail_node("demangle.syntax", "template arguments do not start with I");
      return args;
    }
    while (!at_end() && peek() != 'E') {
      Node* arg = nullptr;
      if (peek() == 'L') {
        arg = parse_literal();
      } else if (peek() == 'J') {
        ++pos_;
        std::vector<Node*> pack;
        while (!at_end() && peek() != 'E') {
          Node* element = parse_type();
          if (element == nullptr) {
            return args;
          }
          pack.push_back(element);
        }
        if (!eat('E')) {
          fail_node("demangle.syntax", "an argument pack is not closed");
          return args;
        }
        arg = make(Node::Kind::Pack, "", pack);
      } else if (peek() == 'X') {
        fail_node("demangle.unsupported", "an expression as a template argument");
        return args;
      } else {
        arg = parse_type();
      }
      if (arg == nullptr) {
        return args;
      }
      args.push_back(arg);
    }
    if (!eat('E')) {
      fail_node("demangle.syntax", "template arguments are not closed");
      return args;
    }
    return args;
  }

  // L <type> <value> E: an integer, bool or character literal.
  // L <class or enum type> <value> E: an enumerator, printed as `(Type)value`.
  Node* parse_class_literal() {
    Node* klass = parse_type();
    if (klass == nullptr) {
      return nullptr;
    }
    const bool negative = eat('n');
    std::string digits;
    while (peek() >= '0' && peek() <= '9') {
      digits += peek();
      ++pos_;
    }
    if (digits.empty() || !eat('E')) {
      return fail_node("demangle.syntax", "an enumerator literal has no value");
    }
    return make(Node::Kind::Literal,
                "(" + printer_.type(klass, "") + ")" + (negative ? "-" : "") + digits);
  }

  Node* parse_literal() {
    eat('L');
    const char type = peek();
    if (type == 'b') {
      ++pos_;
      const char value = peek();
      ++pos_;
      if (!eat('E')) {
        return fail_node("demangle.syntax", "a literal is not closed");
      }
      return text_node(value == '0' ? "false" : "true");
    }
    const char* builtin = builtin_type(type);
    if (builtin == nullptr) {
      return parse_class_literal();
    }
    if (type == 'n' || type == 'o' || type == 'f' || type == 'd' || type == 'e' || type == 'g' ||
        type == 'w' || type == 'z') {
      return fail_node("demangle.unsupported", "this literal type is not supported");
    }
    ++pos_;
    bool negative = false;
    if (eat('n')) {
      negative = true;
    }
    std::string digits;
    while (peek() >= '0' && peek() <= '9') {
      digits += peek();
      ++pos_;
    }
    if (digits.empty() || !eat('E')) {
      return fail_node("demangle.syntax", "a literal has no value");
    }
    std::string text = (negative ? "-" : "") + digits;
    switch (type) {
      case 'j':
        text += "u";
        break;
      case 'l':
        text += "l";
        break;
      case 'm':
        text += "ul";
        break;
      case 'x':
        text += "ll";
        break;
      case 'y':
        text += "ull";
        break;
      case 'c':
        text = "(char)" + text;
        break;
      case 's':
        text = "(short)" + text;
        break;
      case 'a':
        text = "(signed char)" + text;
        break;
      case 'h':
        text = "(unsigned char)" + text;
        break;
      case 't':
        text = "(unsigned short)" + text;
        break;
      default:
        break;
    }
    return make(Node::Kind::Literal, text);
  }

  std::string_view input_;
  DemangleOptions options_;
  std::size_t pos_ = 0;
  int depth_ = 0;
  std::deque<Node> arena_;
  std::vector<Node*> candidates_;  // substitution candidates, in the order they are added
  std::vector<Node*> template_args_;
  bool last_was_special_ = false;
  bool in_lambda_parameters_ = false;
  std::string error_;
  std::string error_code_;
  std::string clone_suffix_;
  // Pack expansions: the pattern is read once to find the pack it expands, then read again
  // for each element of that pack.
  Node* last_pack_ = nullptr;
  Node* override_pack_ = nullptr;
  Node* override_element_ = nullptr;

  // `Dp <pattern>`: the pattern repeated for each element of the pack it names. The
  // expansions are returned as one pack, printed as a comma-separated list.
  Node* parse_pack_expansion() {
    const std::size_t start = pos_;
    const std::vector<Node*> before = candidates_;
    Node* saved_pack = last_pack_;
    last_pack_ = nullptr;
    Node* first = parse_type();
    Node* pack = last_pack_;
    last_pack_ = saved_pack;
    if (first == nullptr) {
      return nullptr;
    }
    if (pack == nullptr) {
      return first;  // no pack is named: the pattern is the expansion
    }
    const std::size_t end = pos_;
    const std::vector<Node*> after_first = candidates_;
    std::vector<Node*> expansions;
    for (Node* element : pack->children) {
      pos_ = start;
      candidates_ = before;
      override_pack_ = pack;
      override_element_ = element;
      Node* item = parse_type();
      override_pack_ = nullptr;
      override_element_ = nullptr;
      if (item == nullptr) {
        return nullptr;
      }
      expansions.push_back(item);
    }
    pos_ = end;
    candidates_ = after_first;
    return make(Node::Kind::Pack, "", std::move(expansions));
  }
  Printer printer_;
};

}  // namespace

bool is_itanium_name(std::string_view name) noexcept {
  return name.size() >= 2 && name[0] == '_' && name[1] == 'Z';
}

Result<std::string> demangle_itanium(std::string_view name, const DemangleOptions& options) {
  Parser parser(name, options);
  return parser.run();
}

}  // namespace donkey
