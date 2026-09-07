#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#define EXPORT __declspec(dllexport)
#else
#define NOINLINE __attribute__((noinline))
#define EXPORT __attribute__((dllexport))
#endif

static const unsigned char expected_text[] = "phase27";

NOINLINE int static_linked_strcmp(const unsigned char *a, const unsigned char *b) {
    while (*a == *b) {
        if (*a == 0) return 0;
        ++a;
        ++b;
    }
    return (int)*a - (int)*b;
}

NOINLINE int static_linked_memcmp(const unsigned char *a, const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return 1;
    }
    return 0;
}

NOINLINE unsigned comparator_false_loop(unsigned n) {
    unsigned total = 0;
    for (unsigned i = 0; i < n; ++i) total += i;
    return total;
}

NOINLINE int comparator_thunk(const unsigned char *a, const unsigned char *b) {
    return static_linked_strcmp(a, b);
}

EXPORT int export_buffer_argument(unsigned char *buffer, size_t length) {
    if (length < sizeof(expected_text)) return 0;
    buffer[0] ^= 0x21;
    return static_linked_memcmp(buffer, expected_text, sizeof(expected_text)) == 0;
}

EXPORT int export_non_input_argument(uintptr_t handle, unsigned flags) {
    return handle != 0 && (flags & 1u) != 0;
}

NOINLINE int entry_stub_to_body(const unsigned char *value) {
    return comparator_thunk(value, expected_text);
}

NOINLINE int body_boundary_false_positive(int value) {
    return (int)comparator_false_loop((unsigned)value) + 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const unsigned char *argv_x64 = (const unsigned char *)argv[1];
    const unsigned char *argv_x86 = (const unsigned char *)argv[1];
    const unsigned char *argv_unknown_index = (const unsigned char *)argv[(unsigned)argc - 1u];
    int crt_to_main_argv = entry_stub_to_body(argv_x64);
    return crt_to_main_argv + static_linked_memcmp(argv_x86, argv_unknown_index, 1)
           + body_boundary_false_positive(argc);
}
