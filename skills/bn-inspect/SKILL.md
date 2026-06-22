---
name: bn-inspect
description: >-
  Targeted, injection-safe Binary Ninja code-mode lookups: decompile one function to HLIL (with
  optional line-grep), find functions by name/regex or resolve an address, list a function's
  xrefs, find a string's referencing functions, or scan a section. Use for quick single-target RE
  questions over the code-mode MCP — not a whole-binary dump (use bulk-decompile) or a bug-class
  sweep (use binary-ninja). CLIs: bn-decompile / bn-find / bn-xrefs / bn-strxref / bn-scansec.
---

# bn-inspect — targeted Binary Ninja lookups (code-mode)

The five operations that dominate interactive RE over the Binary Ninja code-mode MCP (derived
from the actual usage logs: decompile-one-function, find-function, xrefs, string-pivot,
section/data scan). Each is a small CLI in `scripts/` that builds a Python snippet, sends it to
`/execute`, and prints the result. They share `scripts/bncm.py` (the client + the injection
guards) and the `binary-ninja` skill's endpoint/env conventions (`BINJA_MCP_URL`,
`BINJA_MCP_KEY`, `BINJA_HTTP_TIMEOUT`).

## The templates
| script | task | example |
|--------|------|---------|
| `bn-decompile` | decompile one function to HLIL (+ optional `--grep REGEX`/`--asm`) | `bn-decompile --file /tmp/vmdird VmDirMLBind --grep sasl --context 2` |
| `bn-find`  | find functions by name substring/`--regex`, or `--addr` → what's there | `bn-find --file /tmp/vmdird --regex '^Srv_.*[Ss]rp'` |
| `bn-xrefs`     | callers + callees + call-sites of a function/`--addr` | `bn-xrefs --file /tmp/libsrp.so --addr 0x405e50` |
| `bn-strxref`   | find a string → the functions that reference it (`--decompile` to dump them) | `bn-strxref --file /tmp/vmdird 'SASL start failed' --decompile` |
| `bn-scansec`   | list sections; `--read ADDR --len N` hexdump; `--section S --strings`/`--ptrs` | `bn-scansec --file /tmp/vmdird --section .data --ptrs` |

## Target selection (every script)
- `--file PATH` — load the binary **headless** in the BN process (`binaryninja.load`). Simplest;
  best for small/medium binaries. Re-loads each call (seconds), so for a big binary used
  repeatedly prefer:
- `--bv-match SUBSTR` — use an **already-open BN GUI tab** whose name contains `SUBSTR` (no
  reload). Open it first with `bn-open /path/to/binary`.

Resolve targets by **symbol name** when you can — BN rebases, so a file offset ≠ a BN address;
pass real addresses with `--addr` (hex `0x..` or decimal).

## Injection safety (by construction)
Every user value passes two independent guards before it can reach `/execute`:
1. **Validation** (`bncm.py`): per-type validators reject control characters and the
   quote/backslash/backtick/semicolon break-out characters (`vsym`/`vaddr`/`vregex`/`vsection`/
   `vpath`/`vbvmatch`); rejected input exits non-zero (`[reject] ...`) and nothing is sent. (A
   search *needle*, which may legitimately contain quotes, is the one input that is not
   char-restricted — it relies on guard 2.)
2. **Escaped-literal embedding** (`pylit`): validated values are emitted only as `json.dumps`
   literals in a `name = <literal>` prologue. The per-template **body is a constant string** that
   references those vars; user input is never concatenated into it and never touches a shell.

So even a quote/backslash that slipped past guard 1 stays inside a Python string literal — it
cannot break out into executed code. (Quick check: `bn-find --file X "a'; import os" ` →
`[reject]`, exit 2, no call.)

## Gotchas (code-mode sandbox)
- **The sandbox AST-denies certain attribute *names* — including `compile`, `open`, `eval`,
  `exec`, `os` — even inside an untaken branch.** That is why these templates use
  `re.search(pattern, text)` (never `re.compile`) inside the BN code; regex *validation* is done
  locally in `bncm.py`. If you extend a body, avoid those names.
- **Comprehension/def bodies don't see top-of-`/execute` names.** A free variable inside a
  `[... for ...]`/`{...}`/`def` resolves against module globals only, not the names assigned at
  the top of the executed snippet. The bodies here reference prologue vars (`_name`, `_grep`,
  `_needle`, ...) only from plain `for`/`if` statements. (The *outermost iterable* of a
  comprehension is fine — `{c.name for c in fn.callers}` works because `fn` is evaluated in the
  enclosing scope.) Keep this rule if you edit a body.
- **The executor discards captured stdout if the executed code raises** (including
  `raise SystemExit`). `bncm.run()` wraps the body in `try/except SystemExit`, so a body can
  `print("[no function ...]"); raise SystemExit` to bail early *and still have the message reach the
  agent*. Raising `SystemExit` to stop after printing is fine; an uncaught real exception instead
  surfaces as `[BN ERROR]` (correct for genuine errors).
- **`/execute` stdout is truncated ~100 KB** and a giant single-call iteration can crash the host
  — these templates cap output (`--maxlen`, `--limit`, `--cap`) and operate on one target. For a
  whole-binary dump use `bulk-decompile`.
- **Headless `binaryninja.load` re-analyzes every call** (tens of seconds on large binaries) — use
  `--bv-match` against an open tab for repeated queries on big binaries.
- **Timeouts:** the server `/execute` cap is ~600 s; the client default is 900 s
  (`BINJA_HTTP_TIMEOUT`). A big headless load that times out → raise it or switch to `--bv-match`.

## Prerequisites
- BN GUI running the code-mode MCP on `127.0.0.1:42069` — check with `bn-status`.
- Python 3 (standard library only).
- Installed, the tools are on your PATH as the `bn-*` commands shown above. From a local clone,
  run `bin/bn-decompile …` or `python3 skills/bn-inspect/scripts/decompile.py …`.
- For `--bv-match`, open the target as a tab first: `bn-open /path/to/binary`.
