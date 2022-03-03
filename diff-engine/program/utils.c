#include <assert.h>
#include <stdint.h>
#include "utils.h"

int ipow(int base, int exp) {
  int result = 1;
  for (;;) {
    if (exp & 1) result *= base;
    exp >>= 1;
    if (!exp) break;
    base *= base;
  }

  return result;
}

void bin2bytes(uint8_t* dst, const char* src, int base) {
    assert(base == 32 || base == 16);
    for (int i = 0; i < 4; i++) {
        uint8_t v = 0;
        for (int j = 0; j < 8; j++) {
            v += (src[i*8+j] - '0') * (uint8_t)ipow(2, 7-j);
        }
        dst[i] = v;
    }
    if (base == 32) {
        // 0 1 2 3
        // a b c d
        // d c b a
        int tmp3 = dst[0];
        int tmp2 = dst[1];
        dst[0] = dst[3];
        dst[1] = dst[2];
        dst[2] = tmp2;
        dst[3] = tmp3;
    } else {
        // 0 1 2 3
        // a b c d
        // b a d c
        int tmp = dst[0];
        dst[0] = dst[1];
        dst[1] = tmp;
        tmp = dst[2];
        dst[2] = dst[3];
        dst[3] = tmp;
    }
}
