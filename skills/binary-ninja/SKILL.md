---
name: binary-ninja
description: >-
  Drive Binary Ninja headlessly via its code-mode MCP to reverse-engineer compiled binaries,
  patch-diff two builds to locate silently-fixed security bugs (n-day discovery), and scan for
  memory-safety bug classes (integer overflow, heap alloc/copy mismatch, stack-buffer overflow,
  double-fetch/TOCTOU). Use when analyzing or comparing ELF/PE binaries, firmware, shared libraries,
  or kernel modules — stripped or not — especially for vulnerability research and exploit development.
---

# Binary Ninja code-mode: RE, patch-diff, and bug-class scanning

This skill drives Binary Ninja programmatically by POSTing Python to its **code-mode MCP** `/execute`
endpoint, plus a set of disassembler-independent capstone/pyelftools tools for breadth. It encodes a
working methodology for **finding memory-safety vulnerabilities** in binaries and for **patch-diffing**
(diffing two versions of a binary to find the bug a patch fixed).

## Prerequisites
- Binary Ninja (Personal edition is fine — code runs in the GUI's own Python, no headless license).
- The **code-mode MCP** BN plugin running an HTTP server on `127.0.0.1:42069`
  (e.g. `akrutsinger/binja-codemode-mcp`: `Plugins > MCP Code Mode > Start Server`).
- Python deps for the BN-independent tools: `pip install capstone pyelftools`.
- Override the endpoint with env vars `BINJA_MCP_URL` / `BINJA_MCP_KEY` (defaults baked into `scripts/binja.py`).

## Core loop — run Python inside BN
`scripts/binja.py` POSTs a Python string to `/execute` and prints captured stdout (so always `print()`):
```bash
python3 scripts/binja.py 'print(binja.get_binary_status())'          # what's open in the GUI
# load ANY file headlessly (import is allowed; use a cached .bndb for speed):
python3 scripts/binja.py 'import binaryninja; bv=binaryninja.load("/path/bin", update_analysis=False); print(len(list(bv.functions)))'
```
Each `/execute` call is **stateless** — re-`import` and re-`load` every call. To diff two builds, load both
in the *same* call. **Read `reference/mcp-codemode-guide.md` before writing non-trivial scripts** — the exec
sandbox has sharp edges (no `re.compile`/`__import__`, a globals/locals scoping trap that NameErrors your
functions, `f.hlil` can be None, BN rebases addresses) that will waste your time otherwise.

## Bug-class scanners (BN HLIL — run against a prebuilt `.bndb`)
Each is a template with a `BNDBPATH` placeholder; substitute the path and pipe to `binja.py`. Flag-generously,
then **triage every hit to a verdict** (the scanners find candidates, not bugs):
```bash
sed 's#BNDBPATH#/tmp/target.bndb#' scripts/bn_scan_intof.py | python3 scripts/binja.py "$(cat)"
```
- `bn_scan_intof.py` — **integer overflow**: alloc/copy size computed with `*`/`<<`/`+` over non-constant operands.
- `bn_scan_heapmismatch.py` — **heap mismatch**: `buf = alloc(A)` then `memcpy(buf, …, B)` with `B`'s expression ≠ `A`.
- `bn_scan_dangcopy.py` — **dangerous copy**: unbounded `strcpy`/`sprintf`, or a copy into a stack buffer with a non-constant length (stack overflow).
- `bn_scan_doublefetch.py` — **double-fetch/TOCTOU**: the same `*(argN+off)` attacker-memory deref read in both a check and a use. (Noisy — see the guide; races are usually better found by patch-diff.)

## Breadth without a bndb (BN-independent, parallel, fast)
For sweeping many modules at once — `scripts/cap_scan.py` resolves allocator/`memcpy` call sites in **ET_REL**
relocatable objects via `.rela.text` (callee names) + `.symtab` (function names), and classifies the size
operand's local register provenance (MUL/SHIFT = int-overflow, SIGNEXT = signed length, MEMLOAD = attacker
length, STACKCOPY = stack-dest copy). No BN needed; runs on every file in seconds:
```bash
python3 scripts/cap_scan.py /path/to/module.o            # high-signal classes
python3 scripts/cap_scan.py /path/to/module.o --all      # everything
```

## Patch-diffing (find the silently-fixed bug between two builds)
See `reference/patch-diff-method.md`. In short: for **non-stripped** ELFs use `scripts/symdiff.py old new`
(capstone disassembles each named function, normalizes away layout noise, hashes, diffs by symbol name —
seconds vs hours, no decompiler). For stripped/library code, diff by exported symbol or BN's function
matching, then read the changed function's HLIL in BN and look at what the new build *adds* (a bound check,
a re-validation, a lock) — that delta IS the vulnerability in the old build.

## Method discipline (what actually finds real bugs)
1. **Map the attacker-reachable surface first** — which functions parse attacker-controlled input? Point scanners there.
2. **Flag generously, triage exhaustively** — every candidate gets SAFE / NEEDS-VERIFY / CONFIRMED, with the reason.
3. **Trace to root** — a flagged `count*K` is only a bug if `count` is attacker-controlled AND unbounded AND the
   product is used undersized. Follow it (often into a shared decoder/allocator that may already guard it).
4. **Verify in HLIL, not by pattern** — the scanners are heuristics; confirm the dataflow in BN.
5. **Mind the address spaces** — BN rebases (BN addr ≠ file offset); use BN HLIL for BN addresses, objdump/capstone
   for file offsets. Don't cross the streams.

## Files
- `scripts/binja.py` — code-mode MCP client.
- `scripts/bn_scan_{intof,heapmismatch,dangcopy,doublefetch}.py` — BN HLIL bug-class scanners.
- `scripts/cap_scan.py` — BN-independent ET_REL bug-class scanner (capstone + pyelftools).
- `scripts/symdiff.py` — fast symbol-matched patch-differ for non-stripped ELFs.
- `reference/mcp-codemode-guide.md` — the code-mode sandbox + every gotcha, with the robust scan template.
- `reference/patch-diff-method.md` — the patch-diff methodology.
