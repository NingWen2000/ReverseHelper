#include <stdint.h>
#include <stddef.h>

volatile uint32_t side_effect;
static const uint32_t key_words[4] = {1, 2, 3, 4};
static const uint8_t target_bytes[4] = {9, 8, 7, 6};

void rename_input_transform(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] ^= (uint8_t)i; }
int rename_validation(const uint8_t *p) { return p[0] == target_bytes[0]; }
int rename_false_positive(int x) { return x + 1; }
void type_byte_buffer(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i]++; }
uint32_t type_u32_array(const uint32_t *p, size_t i) { return p[i]; }
uint32_t type_key4(size_t i) { return key_words[i & 3]; }
int type_false_pointer(uintptr_t x) { return (int)(x + 4); }
uint8_t array_index_x86(const uint8_t *p, size_t i) { return p[i] ^ p[i + 1]; }
uint32_t array_index_x64(const uint32_t *p, size_t i) { return p[i] + p[i + 1]; }

struct observed_only { uint32_t a, b; void *p; uint32_t d; };
uintptr_t fixed_offset_struct_like(struct observed_only *p) { return p->a + p->b + (uintptr_t)p->p + p->d; }

uint32_t temporary_shift_xor_add(uint32_t x) { return ((x << 4) ^ (x >> 5)) + x; }
uint32_t temporary_multiuse_negative(uint32_t x) { uint32_t a = x << 4; side_effect = a; return a ^ x; }
uint32_t temporary_side_effect_negative(uint32_t x) { side_effect++; return (x << 4) ^ (x >> 5); }

volatile uint32_t dispatch_state;
int state_variable_semantic(int x) { while (dispatch_state < 3) dispatch_state++; return x + dispatch_state; }
uint8_t target_bytes_semantic(size_t i) { return target_bytes[i & 3]; }
uint32_t key_role_false_positive(size_t i) { static const uint32_t ordinary[] = {10, 20, 30, 40}; return ordinary[i & 3]; }

int main(int argc, char **argv) {
    uint8_t b[8] = {0}; uint32_t w[4] = {0};
    rename_input_transform(b, sizeof(b));
    return rename_validation(b) + type_u32_array(w, 0) + type_key4(argc) +
           temporary_shift_xor_add((uint32_t)argc) + state_variable_semantic(argv != 0);
}
