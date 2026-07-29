#!/bin/bash
# Build the disasm-codemode test fixtures. Idempotent; safe to re-run.
set -e
cd "$(dirname "$0")"
# Keep library calls intact (no FORTIFY/builtins/stack-protector) so memcpy/sprintf/malloc
# stay as named calls the scanners can resolve.
CF="-fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-builtin -w"

# executable with symbols + DWARF (for the BN skills): -O0 keeps every function/call/type
gcc $CF -O0 -g  target.c    -o target
# ET_REL objects (.symtab + .rela.text) for cap_scan / symdiff: -O1 = realistic reg patterns
gcc $CF -O1 -c  target.c    -o target.o
gcc $CF -O1 -c  target_v2.c -o target_v2.o
# stripped executable (edge case: no .symtab) for graceful-failure tests
cp -f target target.stripped && strip target.stripped
# malformed inputs
printf 'this is definitely not an ELF object file\n' > notelf.txt
: > empty.bin

echo "[build] fixtures:"
for f in target target.stripped target.o target_v2.o notelf.txt empty.bin; do
    printf '  %-18s %s bytes\n' "$f" "$(stat -c%s "$f" 2>/dev/null || echo '?')"
done
