// Mangling fixture (G10-T1): standard library types, lambdas, static locals, guards and
// special symbols (vtables, typeinfo). Written for this repository.
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

std::string make_string(const char* s) {
  return std::string(s);
}
std::vector<int> make_vector(int n) {
  return std::vector<int>(n, 1);
}
std::map<std::string, int> make_map() {
  return {{"a", 1}};
}
std::unique_ptr<int> make_unique(int v) {
  return std::make_unique<int>(v);
}
std::shared_ptr<double> make_shared(double v) {
  return std::make_shared<double>(v);
}
std::function<int(int)> make_function(int k) {
  return [k](int x) { return x + k; };
}
std::vector<std::string> strings(const std::vector<std::string>& in) {
  return in;
}
void throws(int v) {
  if (v < 0) throw std::runtime_error("negative");
}
int lambdas(int x) {
  auto f = [x](int y) { return x + y; };
  auto g = [&](auto z) { return z + x; };
  return f(1) + g(2);
}
int static_locals() {
  static int counter = 0;
  static std::string label = "x";
  return ++counter + (int)label.size();
}
struct Shape {
  virtual ~Shape() {}
  virtual double area() const = 0;
};
struct Circle : Shape {
  double r;
  explicit Circle(double radius) : r(radius) {}
  double area() const override { return 3.0 * r * r; }
};
struct Square final : Shape {
  double s;
  explicit Square(double side) : s(side) {}
  double area() const override { return s * s; }
};
double total(const std::vector<std::unique_ptr<Shape>>& shapes) {
  double sum = 0;
  for (const auto& s : shapes) sum += s->area();
  return sum;
}
namespace {
struct Local {
  int v;
};
}  // namespace
int local_struct_user() {
  Local l{4};
  return l.v;
}
