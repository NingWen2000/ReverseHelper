/* Self-authored P0 acceptance fixture. Compile with -DMODE=1, 2 or 3.
 * No real challenge/flag is embedded. These fixtures are not a CTF benchmark.
 */
#include <stdio.h>
#include <string.h>

#ifndef MODE
#define MODE 1
#endif

int main(void) {
    char input[64] = {0};
    static const char target[] = "RHdemo";
    puts("Enter password:");
    if (!fgets(input, sizeof(input), stdin)) {
        puts("Input error");
        return 2;
    }
    input[strcspn(input, "\r\n")] = 0;
#if MODE == 1
    if (strcmp(input, target) != 0) {
        puts("Wrong flag!");
        return 1;
    }
#elif MODE == 2
    if (strlen(input) != 6 || memcmp(input, target, 6) != 0) {
        puts("Wrong flag!");
        return 1;
    }
#else
    if (strlen(input) != 6) {
        puts("Invalid length");
        return 1;
    }
    for (unsigned int i = 0; i < 6; ++i) {
        if ((unsigned char)input[i] != (unsigned char)target[i]) {
            puts("Wrong flag!");
            return 1;
        }
    }
#endif
    puts("Correct flag! Congratulations!");
    return 0;
}
