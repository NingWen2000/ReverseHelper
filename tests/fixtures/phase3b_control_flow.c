#include <stdint.h>

volatile int sink;
typedef int (*handler_t)(int);

int add1(int x) { return x + 1; }
int sub1(int x) { return x - 1; }
int xor1(int x) { return x ^ 0x55; }

int simple_switch(int x) {
    switch (x) { case 0: return 11; case 1: return 23; case 2: return 37;
    case 3: return 41; case 4: return 53; default: return -1; }
}

int jump_table_x86(int x) { return simple_switch(x); }
int jump_table_x64(int x) { return simple_switch(x + 1); }
int switch_false_table(int x) { static const int values[] = {1, 2, 3, 4}; return values[x & 3]; }

int simple_state_machine(int x) {
    int state = 0;
    while (state != 3) {
        switch (state) { case 0: x += 3; state = 1; break;
        case 1: x ^= 9; state = 2; break; default: state = 3; break; }
    }
    return x;
}

int dispatcher_loop(int x) { return simple_state_machine(x); }
volatile int state_global;
int state_global_machine(int x) {
    state_global = 0;
    while (state_global < 3) state_global = (state_global + x + 1) % 4;
    return state_global;
}
int state_stack(int x) { volatile int state = x & 3; while (state) state--; return state; }

int indirect_jump_table(int x) { return simple_switch(x); }
int function_table_call(int x) { static handler_t table[] = {add1, sub1, xor1}; return table[x % 3](x); }
int indirect_false_positive(handler_t callback, int x) { return callback(x); }

int flattening_like(int x) {
    volatile int state = 0;
    for (;;) {
        switch (state) {
        case 0: x += 7; state = 2; break;
        case 1: x ^= 0x33; state = 3; break;
        case 2: x -= 2; state = 1; break;
        case 3: state = 4; break;
        default: return x;
        }
    }
}

int flattening_false_high_complexity(int x) {
    if (x < 0) x = -x;
    if (x & 1) x += 3;
    if (x & 2) x ^= 7;
    if (x > 100) x -= 90;
    return x;
}

int opaque_like_candidate(int x) {
    if ((x * x + x) & 1) sink++;
    if ((x * x + x) & 1) sink++;
    if ((x * x + x) & 1) sink++;
    return x;
}
int opaque_false_positive(int x) { return x == 42 ? 1 : 0; }

int main(int argc, char **argv) {
    int x = argc + (argv != 0);
    return simple_switch(x) + simple_state_machine(x) + state_global_machine(x) +
           state_stack(x) + function_table_call(x) + flattening_like(x) +
           flattening_false_high_complexity(x) + opaque_like_candidate(x) + opaque_false_positive(x);
}
