// Itanium RTTI and vtable fixture (G10-T3). It has a polymorphic root with a pure virtual
// slot, a single-inheritance chain (__si_class_type_info), a class with two bases
// (__vmi_class_type_info) and a polymorphic class with no bases (__class_type_info).
// Written for this repository. Built as a PIE and as a non-PIE executable (see CMakeLists).

struct Shape {
  virtual ~Shape();
  virtual double area() const = 0;
  virtual const char* label() const;
  int id = 0;
};

struct Named {
  virtual const char* name() const;
  virtual int rank() const;
};

struct Square : Shape {
  double side = 1.0;
  double area() const override;
  const char* label() const override;
};

struct Cube : Square {
  double area() const override;
};

struct Tagged : Shape, Named {
  double area() const override;
  const char* name() const override;
};

struct Lone {
  virtual void ping();
  virtual int pong(int x);
};

Shape::~Shape() {}
const char* Shape::label() const {
  return "shape";
}
const char* Named::name() const {
  return "named";
}
int Named::rank() const {
  return 0;
}
double Square::area() const {
  return side * side;
}
const char* Square::label() const {
  return "square";
}
double Cube::area() const {
  return side * side * side;
}
double Tagged::area() const {
  return 2.0;
}
const char* Tagged::name() const {
  return "tagged";
}
void Lone::ping() {}
int Lone::pong(int x) {
  return x;
}

int use_hierarchy(int n) {
  Square square;
  Cube cube;
  Tagged tagged;
  Lone lone;
  Shape* shape = n > 0 ? static_cast<Shape*>(&square) : static_cast<Shape*>(&cube);
  Named* named = &tagged;
  lone.ping();
  return (int)shape->area() + named->rank() + lone.pong(n) + shape->id;
}

int main(int argc, char**) {
  return use_hierarchy(argc);
}
