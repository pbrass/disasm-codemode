---
name: bn-hunt
description: >-
  Bug-class hunting templates for Binary Ninja code-mode: list a sink's call sites with their
  argument expressions (bn-callsites), report stack-frame size / self-recursion / params or rank
  functions by frame size for DoS candidates (bn-frame), and disassemble an instruction window
  (bn-disasm-range). Use when triaging a memory-safety, format-string, or DoS lead — inspecting a
  sink's arguments, attacker-controlled lengths, or exact instructions at a copy/patch site. Pairs
  with the binary-ninja scanners and bn-inspect. Injection-safe.
---

# bn-hunt - bug-class hunting recipes (BN code-mode)

The next tier of common code-mode tasks after `bn-inspect`, derived from the usage logs: the
ad-hoc bug-hunt moves you make when a lead needs a one-off pattern the canned `bn_scan_*`
scanners (in the `binary-ninja` skill) don't cover. Each is a small CLI in `scripts/` that builds
a Python snippet, sends it to `/execute`, and prints the result. They share `scripts/bncm.py`
(the client + injection guards; same module as `bn-inspect`) and the `binary-ninja` skill's
endpoint/env conventions (`BINJA_MCP_URL`, `BINJA_MCP_KEY`, `BINJA_HTTP_TIMEOUT`).

## The templates
| script | task | example |
|--------|------|---------|
| `bn-callsites` | every call to a SINK + its **argument expressions** (HLIL) | `bn-callsites --file /tmp/vmdird --sink memcpy --arg 2` |
| `bn-frame` | one function's **frame size / recursion / params+types/vars**, or `--top N` largest frames | `bn-frame --file /tmp/apiForwarder --top 15` |
| `bn-disasm-range` | disassemble an **instruction window** at an address | `bn-disasm-range --file /tmp/vmknvme --addr 0x429dc0 --count 24` |

The bug-hunt loop these support: **find a sink's call sites → read its argument expressions
(`callsites --arg N`) → check the length/pointer provenance → check the frame (`frame`)**, and
read exact instructions at the site (`disasm-range`) when the HLIL is ambiguous. `callsites`
resolves the sink as a function *or* an imported symbol, so PLT/import sinks (memcpy, strcpy,
sprintf) work; `--arg 2` on memcpy isolates the length expression.

## What about the other two next-tier ops?
Two ranks in the same tier are already served by existing tooling, so they are **not** duplicated
here:
- **Cross-build patch-diff** (load two builds, compare a function) -> the `binary-ninja` skill's
  **`bn-symdiff`** (fast symbol-matched ELF differ) and the project's ghidriff flow. Use
  `bn-decompile` against each build for an interactive spot-diff.
- **MLIL/LLIL/SSA value provenance** ("is this length attacker-controlled?") -> the `binary-ninja`
  skill's **`bn_scan_*`** scanners (intof / heapmismatch / dangcopy / doublefetch) encode the
  canonical dataflow patterns. (A generic `provenance.py` could be added if one-off SSA def-use
  queries become frequent.)

## Target selection, injection safety, gotchas
Identical to `bn-inspect` (shared `bncm.py`):
- **`--file PATH`** (headless `binaryninja.load`) or **`--bv-match SUBSTR`** (an already-open BN
  GUI tab, no reload - prefer for big binaries used repeatedly). Resolve by symbol name / pass
  real `--addr` (BN rebases; a file offset != a BN address).
- **Injection-safe by construction**: every input is validated (control chars + quote/backslash/
  backtick/semicolon rejected -> `[reject]`, nothing sent) and embedded only as a `json.dumps`
  literal in a prologue; the per-template body is a constant string, never f-string-interpolated,
  never shelled.
- **Sandbox gotchas** (see `bn-inspect`'s SKILL.md for detail): the sandbox AST-denies the
  attribute name `compile` (and `open`/`eval`/`exec`/`os`) even in untaken branches - bodies use
  `re.search`, not `re.compile`; and comprehension/def bodies don't see top-of-`/execute` names,
  so prologue vars are referenced only from plain `for`/`if`. Output is capped (`--limit`,
  `--count`); a whole-binary `frame --top` on a large binary iterates every function (can take a
  minute - prefer `--bv-match`).

## Prerequisites
- BN GUI running the code-mode MCP on `127.0.0.1:42069` (see the `binary-ninja` skill).
- Python 3 (standard library only).
