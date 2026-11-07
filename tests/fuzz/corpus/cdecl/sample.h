typedef unsigned char u8;
struct point {
  int32_t x;
  int32_t y;
};
struct record {
  uint8_t tag;
  struct point at;
  double weight;
  char name[5];
};
union value {
  uint32_t word;
  float real;
};
enum mode { MODE_A, MODE_B = 4, MODE_C };
typedef struct {
  uint16_t lo, hi;
} pair;
struct list {
  struct list* next;
  int count;
};
int64_t sum(const struct point* points, size_t count, ...);
void reset(void);
