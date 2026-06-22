/* Test fixture for the disasm-codemode skills. Each function exercises a specific
 * skill feature or bug-class scanner. Compiled both as an executable (symbols, for the
 * BN skills) and as an ET_REL .o (for cap_scan/symdiff). See build.sh.
 *
 * Build flags deliberately keep library calls intact (no FORTIFY/builtins/stack-protector)
 * so memcpy/sprintf/malloc stay as named calls the scanners can resolve. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* intof: size = count * size  -> integer-overflow into an undersized allocation */
void *alloc_table(int count, int elem) {
    return malloc(count * elem);
}

/* heapmismatch: allocate n, copy more than n */
char *heap_copy(const char *src, int n) {
    char *p = (char *)malloc(n);
    memcpy(p, src, n + 16);
    return p;
}

/* dangcopy / cap_scan STACKCOPY: attacker length into a fixed stack buffer */
int stack_copy(const char *src, unsigned int n) {
    char buf[64];
    memcpy(buf, src, n);
    return buf[0];
}

/* callsites --sink sprintf: the format string IS attacker-controlled */
void log_msg(const char *user) {
    char out[128];
    sprintf(out, user);
    puts(out);
}

/* doublefetch: *p read twice across a check (TOCTOU); volatile defeats CSE */
int double_fetch(volatile int *p, char *dst, const char *src) {
    int r = 0;
    if (*p < 64) {
        memcpy(dst, src, (size_t)*p);
        r = *p;
    }
    return r;
}

/* frame.py: self-recursive */
long recurse_sum(long n) {
    if (n <= 0) return 0;
    return n + recurse_sum(n - 1);
}

/* frame.py --top: large stack frame */
int big_frame(void) {
    volatile char scratch[4096];
    scratch[0] = 1;
    scratch[4095] = 2;
    return scratch[0] + scratch[4095];
}

/* strxref: a distinctive string */
const char *MAGIC = "MAGIC_HANDLER_STRING_v1";
int handler(void) {
    return puts(MAGIC);
}

/* xrefs: leaf has callers (main, never_called) but no callees;
 * never_called has a callee (leaf) but no callers */
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
