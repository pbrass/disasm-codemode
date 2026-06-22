---
name: bulk-decompile
description: >-
  Dump an entire binary (or just the reachable closure from chosen entry points) to per-function
  HLIL pseudo-C and disassembly files via the Binary Ninja code-mode MCP, when the binary is too
  big to decompile in a single /execute call. Use when you need the whole decompilation on disk for
  offline reading, grepping, parallel/subagent review, or diffing — rather than one function at a
  time interactively. Companion to the binary-ninja skill.
---

# Bulk-decompile a binary to per-function files (BN code-mode)

Drives the Binary Ninja code-mode MCP (`/execute`, see the `binary-ninja` skill) to write one file
per function: `<func>.hlil.c` (decompilation) and optionally `<func>.asm` (disassembly), plus an
`INDEX.{json,txt}`. Driver: `scripts/bn-bulk-decompile`.

## Why one function per call (the constraints this works around)
- **/execute output is captured stdout, truncated at ~100 KB** — you cannot print a whole large
  binary's decompilation in one call.
- **A full-binary HLIL iteration inside one /execute can crash the BN host** (heavy iteration on
  10–36 MB binaries → the server then returns connection-refused).
- **The sandbox forbids `open`/`os`** — the `/execute` side cannot write files; the *local* driver does.
- **Headless `binaryninja.load()` is stateless per call** — a `bv` doesn't persist, so re-loading a
  big binary every function would cost tens of seconds each.

So: **keep the binary OPEN IN THE BN GUI** (its BinaryView persists across `/execute` calls), rebind
the `binja` API object to it, and dump **one function per call** (each well under 100 KB). The driver
runs locally and writes each result to disk.

## Prerequisites
- BN GUI running the code-mode MCP on `127.0.0.1:42069` (see the `binary-ninja` skill).
- **The target binary must be open as a GUI tab** so its BV persists. Open it with the
  `binary-ninja` skill's `bn-open <path>` or via `UIContext...openFilename`.
- Env overrides: `BINJA_MCP_URL`, `BINJA_MCP_KEY`.

## Usage
```bash
# whole binary, with disassembly, to an explicit dir:
bn-bulk-decompile --bv-match vmdird --out ./vmdird_hlil --all --asm

# only the pre-auth reachable closure from chosen entry points (HLIL only):
bn-bulk-decompile --bv-match vmdird --out ./vmdird_hlil \
        --entry ParseFilter,VmDirPerformBind,ParseRequestControls

# structured path <root>/<product>/<build>/<binary>/ (disambiguates builds — recommended for
# multi-build work, since source ≠ shipped binary; cf. D7/D8):
bn-bulk-decompile --bv-match vmdird --product vcenter --build 24755230 \
        --root ./decomp --all --asm
```
`--bv-match` is a substring of the open tab name; the driver rebinds `binja._bv` to it deterministically
(independent of GUI focus) and derives the binary name from its filename. Choose either `--out DIR`
or `--product`+`--build` (composed under `--root`, default `./decomp`).

## Output
```
<outdir>/<func>.hlil.c     # // callers: ...  + signature + // Variables: + HLIL body
<outdir>/<func>.asm        # disassembly (with --asm)
<outdir>/INDEX.json        # {product,build,binary,source_file,functions:[{name,hlil,asm,bytes}]}
<outdir>/INDEX.txt         # name / size / file, one per line
```
Then read/grep/diff offline, or fan out subagents over the files.

## Gotchas
- The binary **must be open in the GUI** — a headless `binaryninja.load()` won't persist across the
  per-function calls (and would re-analyze each time). If you only need a handful of functions from a
  not-open binary, the `binary-ninja` skill's headless `load()` + `fn.hlil` is fine.
- One bad/None function won't abort the run (each call is independent; failures are logged and skipped).
- For very large binaries, expect minutes; the driver prints progress every 50 functions.
- Resolve functions by **symbol name** when scripting (BN rebases — a file address ≠ a BN address).
