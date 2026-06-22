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
endpoint, plus disassembler-independent capstone/pyelftools tools for breadth. It encodes a working
methodology for **finding memory-safety vulnerabilities** and for **patch-diffing** (diffing two builds
to find the bug a patch fixed).

## Prerequisites
- Binary Ninja (Personal edition is fine — code runs in the GUI's own Python, no headless license).
- The **code-mode MCP** BN plugin serving `127.0.0.1:42069` (e.g. `akrutsinger/binja-codemode-mcp`:
  `Plugins > MCP Code Mode > Start Server`). Verify with **`bn-status`**.
- Python deps for the BN-independent tools: `pip install capstone pyelftools`.
- Endpoint overrides: env `BINJA_MCP_URL` / `BINJA_MCP_KEY`.

## Command-line tools
Installed, these are on your PATH (from a local clone, use `bin/<cmd>` or `python3 skills/.../scripts/<file>`):
- **`bn-status`** — is the MCP up + what binary is loaded.  **`bn-open <path>`** — open a file as a GUI tab (enables `--bv-match`).
- **`bn-exec '<python>'`** — run arbitrary Python inside BN (`print()` to see output); the raw code-mode client.
- **`bn-scan`**, **`bn-cap-scan`**, **`bn-symdiff`** — the standalone scanners/differ below.
- Targeted lookups (`bn-decompile` / `bn-find` / `bn-xrefs` / `bn-strxref` / `bn-scansec`) are in the **bn-inspect**
  skill; sink/frame/disasm hunting (`bn-callsites` / `bn-frame` / `bn-disasm-range`) in **bn-hunt**; whole-binary
  dumps (`bn-bulk-decompile`) in **bulk-decompile**.

## Core loop — run Python inside BN
`bn-exec` POSTs a Python string to `/execute` and prints captured stdout (so always `print()`):
```bash
bn-exec 'print(binja.get_binary_status())'                 # what's open in the GUI
# load ANY file headlessly (a cached .bndb is faster than re-analyzing):
bn-exec 'import binaryninja; bv=binaryninja.load("/path/bin", update_analysis=True); print(len(list(bv.functions)))'
```
Each `/execute` call is **stateless** — re-`import` and re-`load` every call; to diff two builds, load both in the
*same* call. **Read `reference/mcp-codemode-guide.md` before writing non-trivial scripts** — the exec sandbox has
sharp edges (no `re.compile`/`__import__`; a globals/locals scoping trap that NameErrors nested functions/comprehensions;
`raise`/`SystemExit` discards captured stdout; `f.hlil` can be None; BN rebases addresses; output truncates ~100 KB)
that will waste your time otherwise.

## Bug-class scanners (BN HLIL)
`bn-scan <class> <binary-or-bndb>` runs a scanner and prints candidates — it finds **candidates, not bugs**, so
triage every hit to a verdict:
```bash
bn-scan intof /tmp/target            # classes: intof | heapmismatch | dangcopy | doublefetch
```
- **intof** — integer overflow: an alloc/copy size computed with `*`/`<<`/`+` over non-constant operands.
- **heapmismatch** — `buf = alloc(A)` then `memcpy(buf, …, B)` with `B`'s expression ≠ `A`.
- **dangcopy** — unbounded `strcpy`/`sprintf`, or a copy into a stack buffer with a non-constant length (stack overflow).
- **doublefetch** — the same `*(argN+off)` attacker-memory deref read in both a check and a use. (Noisy — see the guide.)

Each is a `scripts/bn_scan_<class>.py` template (a `BNDBPATH` placeholder); `bn-scan` substitutes the path and runs it
via `bn-exec`. To point one at a pre-built `.bndb`, pass the `.bndb` path.

## Breadth without a bndb (BN-independent, parallel, fast)
`bn-cap-scan` resolves allocator/`memcpy` call sites in **ET_REL** relocatable objects via `.rela.text` (callee names)
+ `.symtab` (function names) and classifies the size operand's local register provenance (MUL/SHIFT = int-overflow,
SIGNEXT = signed length, MEMLOAD = attacker length, STACKCOPY = stack-dest copy). No BN; runs on every file in seconds:
```bash
bn-cap-scan /path/to/module.o            # high-signal classes
bn-cap-scan /path/to/module.o --all      # everything
```

## Patch-diffing (find the silently-fixed bug between two builds)
See `reference/patch-diff-method.md`. For **non-stripped** ELFs use `bn-symdiff old new` (capstone disassembles each
named function, normalizes away layout noise, hashes, and diffs by symbol name — seconds vs hours, no decompiler).
For stripped/library code, diff by exported symbol or BN's function matching, then read the changed function's HLIL
and look at what the new build *adds* (a bound check, a re-validation, a lock) — that delta IS the bug in the old build.

## Method discipline (what actually finds real bugs)
1. **Map the attacker-reachable surface first** — which functions parse attacker-controlled input? Point scanners there.
2. **Flag generously, triage exhaustively** — every candidate gets SAFE / NEEDS-VERIFY / CONFIRMED, with the reason.
3. **Trace to root** — a flagged `count*K` is a bug only if `count` is attacker-controlled AND unbounded AND used undersized.
4. **Verify in HLIL, not by pattern** — the scanners are heuristics; confirm the dataflow in BN. (The `bn-triage` subagent automates this for batches.)
5. **Mind the address spaces** — BN rebases (BN addr ≠ file offset); use BN HLIL for BN addresses, objdump/capstone for file offsets.

## Files
- `scripts/binja.py` — code-mode MCP client (the `bn-exec` command).
- `scripts/bnstatus.py` / `scripts/bnopen.sh` — the `bn-status` / `bn-open` commands.
- `scripts/bn_scan_{intof,heapmismatch,dangcopy,doublefetch}.py` — BN HLIL bug-class scanner templates (run via `bn-scan`).
- `scripts/cap_scan.py` — `bn-cap-scan` (BN-independent ET_REL scanner; capstone + pyelftools).
- `scripts/symdiff.py` — `bn-symdiff` (fast symbol-matched patch-differ for non-stripped ELFs).
- `reference/mcp-codemode-guide.md` — the code-mode sandbox + every gotcha, with the robust scan template.
- `reference/patch-diff-method.md` — the patch-diff methodology.
