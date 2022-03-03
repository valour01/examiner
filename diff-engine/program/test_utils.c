#include <stdint.h>
#include <stdio.h>

#include "utils.h"

int main() {
  // printf("%d\n", ipow(2, 3));
  // printf("%d\n", ipow(2, 4));
  // printf("%d\n", ipow(2, 5));

  uint8_t bytes[4];

  bin2bytes(bytes, "11100010101100100001000000000010", 32); // 0210b2e2
  for (int i = 0; i < 4; i++) {
    printf("%02x", bytes[i]);
  }
  printf("\n");

  bin2bytes(bytes, "11100010101100100001000000000010", 16); // b2e20210
  for (int i = 0; i < 4; i++) {
    printf("%02x", bytes[i]);
  }
  printf("\n");

  return 0;
}
