/* v2 of target.c: IDENTICAL except stack_copy() gains a bounds clamp (the simulated
 * "fix"). symdiff should report exactly stack_copy as CHANGED, nothing else. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void *alloc_table(int count, int elem) {
    return malloc(count * elem);
}

char *heap_copy(const char *src, int n) {
    char *p = (char *)malloc(n);
    memcpy(p, src, n + 16);
    return p;
}

/* v2: clamp n to the buffer size before copying (the patch) */
int stack_copy(const char *src, unsigned int n) {
    char buf[64];
    if (n > sizeof buf) n = sizeof buf;
    memcpy(buf, src, n);
    return buf[0];
}

void log_msg(const char *user) {
    char out[128];
    sprintf(out, user);
    puts(out);
}

int double_fetch(volatile int *p, char *dst, const char *src) {
    int r = 0;
    if (*p < 64) {
        memcpy(dst, src, (size_t)*p);
        r = *p;
    }
    return r;
}

long recurse_sum(long n) {
    if (n <= 0) return 0;
    return n + recurse_sum(n - 1);
}

int big_frame(void) {
    volatile char scratch[4096];
    scratch[0] = 1;
    scratch[4095] = 2;
    return scratch[0] + scratch[4095];
}

const char *MAGIC = "MAGIC_HANDLER_STRING_v1";
int handler(void) {
    return puts(MAGIC);
}

int leaf(void) {
    return 42;
}
int never_called(void) {
    return leaf() * 2;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        char dst[64];
        volatile int probe = (int)argc;
        alloc_table(argc, 8);
        heap_copy(argv[1], (int)strlen(argv[1]));
        stack_copy(argv[1], (unsigned int)strlen(argv[1]));
        log_msg(argv[1]);
        double_fetch(&probe, dst, argv[1]);
        recurse_sum(argc);
        big_frame();
        handler();
    }
    return leaf();
}
