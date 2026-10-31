/* Demo program for the documentation screenshots: a tiny parts inventory
 * with a struct, a dense switch (jump table), a loop and some strings.
 * Built by the test suite; nothing here is ever run by Donkey. */
#include <stdio.h>
#include <string.h>

struct part {
  const char* name;
  int quantity;
  int price_cents;
  unsigned char category;
};

static struct part inventory[] = {
    {"hex bolt", 120, 15, 0},  {"washer", 400, 2, 0},     {"bearing", 16, 450, 1},
    {"drive belt", 8, 1299, 2}, {"pulley", 12, 899, 2},   {"sensor", 5, 2499, 3},
    {"cable tie", 900, 1, 4},  {"gear 32T", 20, 650, 1},
};

__attribute__((noinline)) const char* category_name(unsigned category) {
  switch (category) {
    case 0: return "fasteners";
    case 1: return "drivetrain";
    case 2: return "transmission";
    case 3: return "electronics";
    case 4: return "consumables";
    case 5: return "tools";
    case 6: return "spares";
    default: return "unknown";
  }
}

__attribute__((noinline)) long stock_value(const struct part* parts, int count) {
  long total = 0;
  for (int i = 0; i < count; ++i) {
    total += (long)parts[i].quantity * parts[i].price_cents;
  }
  return total;
}

__attribute__((noinline)) int low_stock(const struct part* parts, int count, int threshold) {
  int low = 0;
  for (int i = 0; i < count; ++i) {
    if (parts[i].quantity < threshold) {
      ++low;
    }
  }
  return low;
}

int main(int argc, char** argv) {
  const int count = (int)(sizeof(inventory) / sizeof(inventory[0]));
  const int threshold = argc > 1 ? (int)strlen(argv[1]) * 5 : 10;
  for (int i = 0; i < count; ++i) {
    printf("%-12s %5d  %s\n", inventory[i].name, inventory[i].quantity,
           category_name(inventory[i].category));
  }
  printf("stock value: %ld cents, %d parts below %d\n", stock_value(inventory, count),
         low_stock(inventory, count, threshold), threshold);
  return 0;
}
