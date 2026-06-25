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
- The **code-mode MCP** BN plugin serving `127.0.0.1:42069` (e.g. `akrutsinger/binja-codemode-mcp`).
  The user must: open the BN GUI, load ≥1 file, then click the MCP-server button in the **bottom-left
  corner** of the main window (see "Loading a binary independently" below). Verify with **`bn-status`**.
- Python deps for the BN-independent tools: `pip install capstone pyelftools`.
- Endpoint overrides: env `BINJA_MCP_URL` / `BINJA_MCP_KEY`.

## Loading a binary independently — the #1 trip-up (read this)
"Headless" in this skill means **your Python runs in BN's GUI-process interpreter via the `/execute` MCP** —
it does **NOT** mean standalone `python3 -c "import binaryninja"`. A **Personal** license REJECTS standalone
headless (`RuntimeError: License is not valid`). Once the GUI + MCP are up, you open and select binaries
**yourself** — never ask the user to load or switch tabs. Two rules prevent ~all the friction:

1. **Always go through the MCP, never standalone.** Use `bn-exec '<py>'`, `bn-* --file`, or the
   `mcp__binja-codemode__execute` tool. NEVER run `python3 … import binaryninja …` directly (no license
   seat → fails). The MCP runs in the licensed GUI process where `binaryninja.load()` works.
2. **Always use ABSOLUTE paths.** BN's process cwd is some plugin dir (e.g. `…/seeinglogic_ariadne/web`);
   a *relative* path resolves THERE → `File not found` / `Unable to create new BinaryView`. `bn-* --file`
   now auto-absolutizes; `bn-exec` / `mcp execute` do **not** — pass `/abs/path` to `binaryninja.load()`.

Two ways to get a BinaryView (both agent-driven, both via the MCP):

| you want | how | tab? |
|---|---|---|
| a fresh object for a specific binary (one-off, or a binary not open) | `bn-* --file /abs/path` · or in bn-exec/execute: `bv = binaryninja.load("/abs/path", update_analysis=False)` | **no tab** ("just an object") |
| an already-open, fully-analyzed binary (esp. a big pre-analyzed `.bndb`) | `bn-open /abs/path` to add the tab, then `bn-* --bv-match <substr>` | tab |

- **`bn-status` first** — shows MCP up/down **and lists every open tab**. `--bv-match` must match exactly
  ONE open tab; it now ERRORS on ambiguity / no-match (with the tab list) instead of silently grabbing the
  active tab — the old "three tabs open, can't get the one I want" footgun.
- `mcp__binja-codemode__execute`'s `binja` global is only ever the **ACTIVE** tab. To work on a specific
  binary regardless of which tab is active, `binaryninja.load("/abs/path")` your own object instead.
- `update_analysis=False` = fast triage load; `=True` (or open a pre-analyzed `.bndb`) for full xrefs.
- **Getting the MCP up.** If `bn-status` says NOT reachable:
  - **Self-bootstrap (if the auto-start hook is installed + you have a display).** Install once:
    `cat skills/binary-ninja/scripts/mcp_autostart_startup.py >> ~/.binaryninja/startup.py`. Then YOU launch
    BN — `DISPLAY=:0 <BN>/binaryninja /abs/path/to/file &` — and the MCP comes up on `:42069` with **no
    clicks** (verified: GUI launches + loads the file, the hook calls `plugin_instance.start_server(bv)`).
    Wait ~15s, re-check `bn-status`. *(Enabling the MCP otherwise has no CLI flag / no auto-start setting —
    it's a GUI button — which is why the startup.py hook exists.)*
  - **Otherwise ask the user**, in order: **(1)** open the BN GUI; **(2)** load ≥1 file (any binary/`.bndb` —
    the MCP won't start with no view open); **(3)** **click the MCP-server button in the bottom-left corner**
    of the main window (binds `:42069`). Re-check `bn-status`.
  - Everything after — opening/selecting any other binaries — is yours; never ask them to load or switch tabs.

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
bn-exec 'print(binja.get_binary_status())'                 # what's open in the GUI (binja = the ACTIVE tab)
# load ANY file as its own object (runs in BN's GUI process, NOT standalone; ABSOLUTE path required;
# a cached .bndb loads faster than re-analyzing a raw binary):
bn-exec 'import binaryninja; bv=binaryninja.load("/abs/path/bin", update_analysis=True); print(len(list(bv.functions)))'
```
Each `/execute` call is **stateless** — re-`import` and re-`load` every call; to diff two builds, load both in the
*same* call. **Read `reference/mcp-codemode-guide.md` before writing non-trivial scripts** — the exec sandbox has
sharp edges (no `re.compile`/`__import__`; a globals/locals scoping trap that NameErrors nested functions/comprehensions;
`raise`/`SystemExit` discards captured stdout; `f.hlil` can be None; BN rebases addresses; output truncates ~100 KB)
that will waste your time otherwise.

## Annotate as you analyze — the RE sidecar (durable, git-tracked)
A `.bndb` is a 100s-of-MB blob: useless in a git diff, easy to lose to a re-analysis or an unsaved session.
So keep your reverse-engineering — function **renames**, **prototypes**, **struct/type decls**, **variable**
names+types, and **comments / analysis notes** — in a small JSON+C **sidecar** that you author by hand and
sync INTO the bndb. The sidecar is the source of truth; the bndb is the live artifact you re-hydrate.

- **`bn-re-apply SIDECAR.json --bv-match <tab>`** — push the sidecar into the open tab (preview). Then **Ctrl+S**
  in the GUI to persist (the GUI owns the open .bndb — a tool-side save races it). For a headless save, apply to
  a copy: `--file /abs/copy.bndb --save`.
- **`bn-re-vars --bv-match <tab> <fn>`** — list a function's variables with their stable **identifiers** (+ current
  name/type + the function's address), so the sidecar's `vars` section is easy to author.

Idempotent: types are applied first, functions are matched by **address**, variables by **identifier** — re-running
converges (never duplicates). **Comments and analyses can be arbitrarily long and multi-line** — nothing is capped or
truncated; write as much as the analysis needs. Annotate continuously *as you read each function* (a one-line purpose
comment + a real name beats a perfect write-up later). Sidecar schema + an example are in `scripts/re_sync.py`.

```jsonc
{ "types_c": "struct VmxState { uint32_t hdr_len; uint64_t flags; void *payload; };",
  "functions": { "0x140001000": {
      "name": "Vmx_HandleFoo",
      "comment": "ANALYSIS: reconciles guest hdr_len vs descriptor TSO field; caller-owed bound, not re-checked here.",
      "vars": { "576460752290840576": {"name": "ctx", "type": "struct VmxState*"} },
      "line_comments": { "0x140001020": "OOB-relevant copy site" } } } }
```

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
