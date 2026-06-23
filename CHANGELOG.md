# Changelog

All notable changes to disasm-codemode. Versioning is semantic (MAJOR.MINOR.PATCH); pre-1.0,
minor versions may add features and refine interfaces.

## 0.3.0 — 2026-06-22

A second engine: the **ghidra** skill brings the bn-inspect/bn-hunt toolkit to Ghidra over
[ghidra-headless-mcp](https://github.com/mrphrazer/ghidra-headless-mcp)'s `ghidra.eval` (real PyGhidra
backend), realizing the engine-agnostic thesis — the same commands and guards over a different backend.

### New skill: ghidra
- Eleven injection-safe `gh-*` commands mirroring the BN interface: `gh-decompile`, `gh-find`
  (`--no-imports`), `gh-xrefs`, `gh-strxref` (follows the global-pointer hop), `gh-scansec`,
  `gh-callsites` (decompiled call-site argument expressions), `gh-frame` (`getStackFrame` size +
  self-recursion + `--top N`), `gh-disasm-range`, `gh-scan` (heuristic intof/alloccopy/copylen/fmt finder
  over decompiled C), `gh-exec` (raw `ghidra.eval` escape hatch), `gh-status`.
- `skills/ghidra/scripts/ghcm.py` — a stdlib-only MCP/JSON-RPC (TCP) client for ghidra-headless-mcp, with a
  server-side program **session** model (find-or-open reuse by path, `--program` attach) and the same
  `vsym`/`vaddr`/`vregex`/`vsection`/`vpath`/`pylit`/`scrub` guards as `bncm.py`.
- `reference/ghidra-codemode-guide.md` — the Ghidra/PyGhidra/JPype gotchas: the `ghidra.eval` contract, the
  in-scope namespace, `Address` objects, the BN→Ghidra API map, and the differences that bite (unrestricted
  Python, `globals is locals` scoping, signed `byte[]`, the `DefinedDataIterator.definedStrings` gap).
- `bin/` gains the eleven `gh-*` wrappers (pure `exec`-passthrough — no shell-injection surface).

### Tests / security
- `tests/run_tests.py` grows a `ghcm` injection-guard unit section plus live Ghidra integration sections
  (inspect / hunt / bin-wrappers) that **skip cleanly** when the server is unreachable — now 236 checks.
- Tainted-output `scrub()` is applied to every Ghidra output path (stdout, stderr, eval result, error JSON,
  status fields); verified by unit tests, integration tests, and **live adversarial injection probes**
  (needle/regex break-out, code-file metachars, wrapper argv).
- Fixed a real robustness bug the suite surfaced: `flat_api.toAddr(int)` overflows JPype's `int` overload
  for offsets > 2³¹ (most real 64-bit addresses) — bodies now build addresses via a string-form `_toaddr`.

## 0.2.0 — 2026-06-22

Three new skills, command wrappers, a triage subagent, a test suite, a marketplace manifest, and
hostile-binary security hardening across all tools.

### New skills
- **bn-inspect** — five injection-safe targeted templates: `decompile`, `findfunc` (`--no-imports`),
  `xrefs`, `strxref` (follows a data-ref hop for strings reached via a global pointer), `scansec`.
- **bn-hunt** — bug-class hunting templates: `callsites` (a sink's call sites + argument
  expressions), `frame` (stack-frame size / self-recursion / params+vars, or `--top N`),
  `disasm-range` (instruction window at an address).
- **bulk-decompile** — per-function HLIL/asm dump for binaries too large for one `/execute` call.

### Tooling
- `bin/` command wrappers, auto-added to PATH when installed: `bn-decompile`, `bn-find`, `bn-xrefs`,
  `bn-strxref`, `bn-scansec`, `bn-callsites`, `bn-frame`, `bn-disasm-range`, `bn-scan`, `bn-cap-scan`,
  `bn-symdiff`, `bn-bulk-decompile`, `bn-open`, `bn-status`, `bn-exec`.
- `binary-ninja` gained `bnstatus.py` (`bn-status`, MCP health check) and `bnopen.sh` (`bn-open`,
  open a binary as a GUI tab for `--bv-match`).
- `agents/bn-triage` — read-only subagent for parallel, adversarial triage of decompiled functions /
  scanner candidates.
- `.claude-plugin/marketplace.json` so the repo installs as a single-plugin marketplace; `plugin.json`
  gains `homepage`/`repository`.
- `tests/` — a 140-test suite: injection-guard unit tests, per-skill integration tests against
  compiled C fixtures, packaging/manifest checks, and a security section.

### Security / robustness
- **Tainted-output hardening (hostile-binary threat model).** All code-mode output (function/symbol
  names, string values, HLIL, disassembly) is treated as attacker-controlled and routed through
  `scrub()`, which neutralizes terminal-escape bytes (ANSI/OSC clipboard/title/cursor/hyperlink
  hijack and output-spoofing) before printing or writing.
- `bnopen.sh` and `bn-scan` validate their path argument (no shell/string break-out → no host command
  injection); `dump_decompile` sanitizes filenames (no traversal), scrubs the decompilation it writes
  to disk, and leaves the function-list JSON intact.
- Graceful handling of missing/non-ELF/stripped inputs in `cap_scan`/`symdiff`; fixed the code-mode
  `[N.Ns]` timing-prefix bug in `dump_decompile` (which could otherwise dump the wrong open binary).
- Templates validate inputs (reject control/quote/backslash/backtick/semicolon) and embed user values
  only as `json.dumps`-escaped literals.
- New code-mode gotchas in `reference/mcp-codemode-guide.md`: §F (a raised exception, incl.
  `SystemExit`, discards captured stdout; the `[N.Ns]` output prefix) and §G (output is tainted —
  terminal-escape / prompt-injection guidance for agents driving code-mode without the plugin).

## 0.1.0 — 2026-06-09

Initial release — the **binary-ninja** skill: the code-mode MCP client (`binja.py`), HLIL bug-class
scanner templates (`bn_scan_intof` / `heapmismatch` / `dangcopy` / `doublefetch`), the BN-independent
`cap_scan.py` (allocator/`memcpy` size-provenance over ET_REL objects) and `symdiff.py` (symbol-matched
ELF differ), and the reference docs (code-mode sandbox gotchas + the patch-diff methodology).
