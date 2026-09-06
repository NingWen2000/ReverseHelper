/* Negative acceptance fixture: ordinary data comparison, no input or flag UI. */
#include <string.h>

static const unsigned char a[] = {4, 3, 2, 1};
static const unsigned char b[] = {4, 2, 3, 1};
int main(void) {
    return memcmp(a, b, sizeof(a)) == 0 ? 0 : 1;
}
