# Changelog

All notable changes to disasm-codemode. Versioning is semantic (MAJOR.MINOR.PATCH); pre-1.0,
minor versions may add features and refine interfaces.

## 0.6.0 — 2026-06-25

### Binary Ninja independence: load reliably, pick the right tab, self-bootstrap the MCP
Root-caused why an agent sometimes loads binaries freely and sometimes gets stuck asking the user. It was
never a license/GUI-seat split — it was two operator footguns + missing docs:
- **Fix — `bn-* --file` now absolutizes the path** (`bncm.py:vpath`). A *relative* `--file`/`load()` path
  resolved against BN's **process cwd** (a plugin dir, e.g. `…/seeinglogic_ariadne/web`) → `File not found` /
  `Unable to create new BinaryView`. (Same `realpath` fix `bnopen.sh` already had.)
- **Change — `--bv-match` no longer silently grabs the active tab.** It now ERRORS on *ambiguous* (substring
  matches >1 open tab) or *no match* (prints the open-tab list) — killing the "three tabs open, can't get the
  one I want" footgun.
- **Feature — `bn-status` lists every open tab** (not just the active binary), so `--bv-match` is pickable.
- **New — `skills/binary-ninja/scripts/mcp_autostart_startup.py`**: append to `~/.binaryninja/startup.py` and
  the agent can self-bootstrap BN with **zero clicks** — `DISPLAY=:0 binaryninja /abs/file &` launches the
  GUI, loads the file, and the hook auto-starts the MCP on `:42069` (verified end-to-end).
- **Docs — new "Loading a binary independently" section** in the binary-ninja SKILL: never run standalone
  `python3 import binaryninja` (a Personal license rejects it — go through the `/execute` MCP); always use
  absolute paths; the object (`--file`/`load()`) vs open-tab (`--bv-match`/`bn-open`) decision; and the exact
  human MCP-bootstrap steps (open GUI → load ≥1 file → click the bottom-left server button).

## 0.5.0 — 2026-06-24

### New skill: kernel-audit
Rank → contract-infer → attack → live-validate memory-safety auditor for large symbol-rich binaries
(kernel/hypervisor/driver). Ranks functions by a reachability×bug-likelihood `BugScore`, drives a parallel
per-function contract-inference review into a queryable **precondition ledger** (sqlite), then attacks the
caller-owed preconditions and live-validates candidates on a reachability/exploitability ladder. Includes the
`extract.py`/`score.py` pipeline, `prep_batch`/`review-wf` parallel harness, `ingest*` loaders, the
`esxi-vmkernel`/`generic-c` profiles, and `METHODOLOGY.md`. Validated on real ESXi engagements (tcpip4, vmci).

### kernel-audit refinements (this release)
- **Profile-driven retargeting**: `anchors` (calibration set) and `review_target`/`review_attacker`/
  `review_context` (Stage-2 review framing) are now profile fields — point the pipeline at a new module by
  editing JSON, no script edits. `score.py` prints the profile's anchors; `prep_batch.py` splices the framing.
- **v2 bug-class taxonomy in the review schema**: `suspected_bugs` now carry `bug_class`
  (oob/int-overflow/double-fetch/uaf-lifetime/uninit-disclosure/race/type-confusion) so the ledger is sliceable by class.
- **Fresh-ledger robustness**: `ingest.py` creates the `review`/`precondition` tables on a brand-new ledger
  (previously assumed a hand-initialized db).
- **Methodology (SKILL.md)**: calibrate on attacker-entry handlers when there's no prior bug; Stage 3 scopes the
  **full** caller-owed surface (spicy attacker-value bounds vs kernel-internal boilerplate vs UAF/race residue),
  and reachability is traced through the entry chain that may live *outside* the audited binary.

### bn-open
- Absolutize the target path (`realpath`) so opens are independent of Binary Ninja's process cwd — a
  plugin web-server cwd was making relative `.bndb` paths fail to open.

## 0.4.0 — 2026-06-22

### New skill: go-re
Reverse stripped Go binaries via the `pclntab` (`go-list`/`go-diff`/`go-xref`/`go-addr`) — function inventory,
cross-binary patch-diff, xrefs, and addr→name where BN/Ghidra/symdiff/ghidriff struggle on large stripped Go.

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
