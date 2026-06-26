# disasm-codemode test suite

Thorough tests for every skill in the plugin, against compiled C fixtures loaded into Binary
Ninja via the code-mode MCP (plus BN-independent/unit paths for scanners, ledgers, symbol recovery,
and sidecar helpers).

## Run
```bash
python3 tests/run_tests.py        # use a python with capstone + pyelftools
```
The runner builds the fixtures, runs the unit tests, then the integration tests. Exit code is
nonzero iff a test FAILS. Tests that can't meet a precondition SKIP (they do not fail the run):

- **No capstone/pyelftools** in the running python → the `cap_scan`/`symdiff` tests skip.
- **BN code-mode MCP not reachable** (`$BINJA_MCP_URL`, default `http://127.0.0.1:42069`) → all
  the Binary Ninja integration tests skip; the `bncm`, `binary-audit`, and `symbolicate` unit tests still run.
- **Ghidra MCP not reachable** (`$GHIDRA_MCP_HOST`/`$GHIDRA_MCP_PORT`) → Ghidra integration tests skip; the
  `ghcm` unit tests still run.
- Env: `BINJA_MCP_URL`, `BINJA_MCP_KEY`, `GHIDRA_MCP_HOST`, `GHIDRA_MCP_PORT` (same as the skills).

## Fixtures (`fixtures/`, built by `build.sh`)
`target.c` is one program whose functions each exercise a feature/bug-class:
`alloc_table` (int-overflow `malloc(a*b)`), `heap_copy` (alloc/copy mismatch), `stack_copy`
(attacker length into a stack buffer), `log_msg` (`sprintf` format-string sink), `double_fetch`
(TOCTOU), `recurse_sum` (self-recursion), `big_frame` (large stack frame), `handler`/`MAGIC`
(a string reached via a global pointer), `leaf`/`never_called` (xref edges). `target_v2.c` is
identical except `stack_copy` gains a bounds clamp (for `symdiff`). Builds: `target` (exe, symbols
+ DWARF), `target.o`/`target_v2.o` (ET_REL for cap_scan/symdiff), `target.stripped`, and malformed
inputs `notelf.txt`/`empty.bin`.

## Coverage
- **`bncm` injection guards (unit, no BN):** `pylit` round-trips & escapes nasty strings (quotes,
  backslash, newline, unicode, `"; import os…`); validators accept real symbols/addrs/regex/paths
  and reject control/quote/backslash/backtick/semicolon; `run()` embeds an un-restricted needle as
  an inert escaped literal (no statement-level injection).
- **bn-inspect / bn-hunt (integration):** every template on happy paths AND edge/failure cases —
  missing function/addr, no-match, bad section, unmapped read, unknown sink, injection rejection,
  missing/garbage `--file`, a string reached only via a global pointer, recursion & frame sizing.
- **bn_scan_\* templates:** run against the fixture (intof flags `alloc_table`) and a stripped
  binary; assert structured output and no sandbox error/traceback.
- **cap_scan / symdiff:** real candidates / a single CHANGED function on the .o fixtures, plus
  graceful handling of missing files, non-ELF/empty inputs, and stripped (no-`.symtab`) objects.
- **bulk-decompile:** graceful `NO-MATCH` (no wrong-binary dump), and a real rebind+dump of a
  single leaf function from whatever binary is open.
- **binary-audit (unit + live):** ledger-to-comment rendering, no-truncation ingest caps, exact target-name
  matching in phase-2 ingest, and live `bn-audit-sync --file --save` persistence when BN MCP is available.
- **symbolicate (unit):** deterministic log-prefix naming into sidecars, workflow generation, tiered
  split/combine validation, abstention normalization, and sidecar ingest.
- **re_sync (live):** `bn-re-apply --file --save` persists names, types, variables, line comments, and long
  multi-line function comments when BN MCP is available.

## What "graceful" means here
Every failure case asserts: a clear, specific message the agent can act on (e.g. `[reject] …`,
`[no function named …]`, `[cap_scan] … is not a usable ELF object`), the right exit code
(2 = input rejected, 1 = hard error, 0 = ran and reported), and **no uncaught traceback**.
