---
name: go-re
description: Reverse-engineer STRIPPED Go binaries (function inventory, cross-binary patch-diff, xrefs, addr→name) via the pclntab — instant on huge binaries where BN/Ghidra/symdiff/ghidriff struggle.
---

# go-re — reversing stripped Go binaries (the `go-*` commands)

Go release binaries are built `-s -w` (no ELF symtab) so `nm`, BinDiff, the disasm-codemode `symdiff`,
and ghidriff all see ~0 functions. But Go ALWAYS keeps the **`.gopclntab`** (function name/addr table,
needed for panic traces). `gore` parses it directly with the Go stdlib `debug/gosym` — **no BN/Ghidra**,
and **instant** even on 40MB+ binaries (e.g. it diffs two 64,882-function spherelet builds in seconds).

## Commands
- `go-list  <bin> <name-regex>`  → `addr  size  full.package.Func` for matching functions. Find your targets.
- `go-diff  <old> <new>`         → `CHANGED/ADDED/REMOVED` functions by name+byte-hash = a real Go PATCH-DIFF
  (what symdiff can't do on Go). Use for n-day hunting across builds.
- `go-xref  <bin> <hexaddr>`     → functions that CALL the target address (scans .text for e8/e9 rel32). Trace callers.
- `go-addr  <bin> <hexaddr>`     → resolve an address to its function name (e.g. a CALL target from objdump).

## The workflow (how this combines with objdump + BN/Ghidra)
1. `go-list` to find the function(s) of interest by name (the package paths are intact).
2. `go-diff` across two builds to find what changed = the targeted fixes / n-days.
3. To read a function's logic: `objdump -d --start-address=<addr> --stop-address=<addr+size>` (gore gives
   addr+size); resolve each `call <target>` with `go-addr` to recover the callee name. `go tool objdump`
   does NOT work (it needs the stripped symtab); objdump-by-address + go-addr is the reliable path.
4. For deep decompilation, BN/Ghidra DO have Go support — but they're slow on big binaries; use gore to
   pinpoint the few functions worth loading, then decompile just those.

## When to use vs BN/Ghidra
- **Use gore first** for: function inventory, cross-build diffing, xrefs, addr→name — especially on large
  Go binaries (kubelet/spherelet/containerd/CF/BOSH/Consul/etc. — the whole cloud-native stack is Go).
- **Use BN/Ghidra** for: reading decompiled logic of a *specific* function gore pointed you at.

Built from the Phase-4 CRX/spherelet container→host audit. `go build` the source in `skills/go-re/src/`.

## Tests
`skills/go-re/tests/run_tests.sh` — hermetic suite (builds its own stripped `-s -w` Go
fixtures, then checks list/diff/xref/addr + error handling; 13 checks). Needs `go` on PATH.
