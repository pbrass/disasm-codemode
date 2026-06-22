# Changelog

All notable changes to disasm-codemode. Versioning is semantic (MAJOR.MINOR.PATCH); pre-1.0,
minor versions may add features and refine interfaces.

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
