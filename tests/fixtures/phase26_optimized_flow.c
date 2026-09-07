#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_input(char *buffer) {
    static const uint8_t target[8] = {0x23, 0x2a, 0x22, 0x31, 0x20, 0x26, 0x36, 0x00};
    for (unsigned i = 0; i < 7; ++i) {
        buffer[i] ^= 0x42;
    }
    return memcmp(buffer, target, sizeof(target)) == 0;
}

int main(void) {
    char input[32] = {0};
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 2;
    }
    return check_input(input) ? 0 : 1;
}
