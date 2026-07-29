# disasm-codemode

A [Claude Code](https://claude.com/claude-code) plugin for **driving a disassembler/decompiler headlessly
via its code-mode MCP** — to reverse-engineer binaries, recover symbols in stripped targets, **patch-diff**
two builds (find silently-fixed security bugs), and **scan for memory-safety bug classes** at scale.

The idea: most disassemblers now expose a "code mode" MCP server that runs arbitrary Python inside the tool's
own process. That's far more flexible than a fixed set of MCP "tools" — you send the exact analysis you want.
This plugin packages a battle-tested methodology + tooling around that pattern, plus disassembler-independent
helpers (capstone/pyelftools) for breadth when you don't need the full engine.

**Two engines implemented: Binary Ninja and Ghidra.** The methodology — patch-diff method, bug-class
taxonomy, triage discipline, and the injection-safety + tainted-output model — is engine-agnostic; only the
"talk to the tool" layer changes. The Ghidra skill is the proof of that thesis: the same commands and the
same guards over a different backend ([ghidra-headless-mcp](https://github.com/mrphrazer/ghidra-headless-mcp) /
PyGhidra's `ghidra.eval`). IDA / radare siblings remain a natural next step.

## What's inside

A skill (`skills/binary-ninja/`) that gives the agent:
- **`binja.py`** — a tiny client for Binary Ninja's code-mode MCP `/execute` endpoint.
- **BN HLIL bug-class scanners** — integer overflow, heap alloc/copy mismatch, dangerous/stack-overflow copy,
  and double-fetch/TOCTOU candidates, as templates you point at a `.bndb`.
- **`cap_scan.py`** — a BN-*independent* scanner that resolves allocator/`memcpy` call sites in ET_REL
  relocatable objects (via `.rela.text` + `.symtab`) and classifies the size operand's provenance
  (int-overflow / signed-length / attacker-length / stack-dest). Sweeps many modules in seconds, no engine.
- **`symdiff.py`** — a fast symbol-matched patch-differ for non-stripped ELFs (seconds, not hours; no decompiler).
- **Reference docs** — the code-mode sandbox gotchas (the ones that actually waste your time) and the
  patch-diff methodology.

Companion skills build on it:
- **`skills/bulk-decompile/`** — dump a whole binary (or a reachable closure) to per-function HLIL/asm
  files on disk, one `/execute` call per function (works around the ~100 KB output cap + big-binary
  crash), for offline reading/grepping/diffing or subagent fan-out.
- **`skills/bn-inspect/`** — five **injection-safe** parameterized templates for the most common
  targeted lookups (decompile one function, find functions, list xrefs, find a string's referencing
  functions, scan a section). Inputs are validated (suspicious characters rejected) and embedded only
  as escaped literals, so they are safe to point at attacker-influenced names/strings.
- **`skills/bn-hunt/`** — the next-tier **bug-class hunting** templates (same injection-safe client):
  a sink's call sites + argument expressions (`bn-callsites`), stack-frame/recursion/signature analysis
  with a `--top N` DoS-candidate ranking (`bn-frame`), and an instruction-window disassembler
  (`bn-disasm-range`).
- **`skills/symbolicate/`** — evidence-driven mass symbol recovery for stripped or partially stripped
  binaries. It harvests per-function strings, log prefixes, call-neighborhoods, and domain tags into sqlite;
  applies deterministic high-confidence names first; prepares tiered LLM naming batches; combines/validates
  fanout results; and merges names, role comments, and optional prototypes into the same `bn-re-apply`
  sidecar used for BN database sync.
- **`skills/binary-audit/`** — rank -> contract-infer -> caller-precondition audit for large symbol-rich
  binaries, with BN-backed extraction/prep paths for cases where useful names live in a `.bndb` rather than
  the ELF symbol table. It maintains the `kreview.db` ledger, prepares review/decider/caller-loop workflows,
  validates review outputs, generates graph-locality reports, and can sync findings back into BN comments.

A parallel skill brings the same toolkit to **Ghidra**:
- **`skills/ghidra/`** — the Ghidra sibling of bn-inspect/bn-hunt, driving
  [ghidra-headless-mcp](https://github.com/mrphrazer/ghidra-headless-mcp)'s `ghidra.eval` (real PyGhidra
  backend) over MCP/TCP. Eleven injection-safe `gh-*` commands: `gh-decompile`, `gh-find`, `gh-xrefs`,
  `gh-strxref`, `gh-scansec`, `gh-callsites`, `gh-frame`, `gh-disasm-range`, `gh-scan` (heuristic bug-class
  finder), `gh-exec` (raw escape hatch), `gh-status`. Same two-guard injection model and `scrub()`
  tainted-output hardening as the BN skills, a server-side **session** model with find-or-open reuse, and a
  Ghidra/PyGhidra/JPype gotchas guide in `reference/`.

Plus:
- **`bin/`** — command wrappers auto-added to PATH when the plugin is installed. Binary Ninja:
  `bn-decompile`, `bn-find`, `bn-xrefs`, `bn-strxref`, `bn-scansec`, `bn-callsites`, `bn-frame`,
  `bn-disasm-range`, `bn-scan`, `bn-cap-scan`, `bn-symdiff`, `bn-bulk-decompile`, `bn-open`, `bn-status`,
  `bn-exec`, `bn-re-apply`, `bn-re-vars`. Symbol recovery: `bn-sym-extract`, `bn-sym-determ`,
  `bn-sym-prep`, `bn-sym-makewf`, `bn-sym-ingest`, `bn-sym-split`, `bn-sym-combine`,
  `bn-sym-prep-locality`, `bn-sym-prep-second`, `bn-sym-review-protos`, `bn-sym-slice-protos`.
  Binary audit: `bn-audit-sync`, `bn-audit-extract-bn`, `bn-audit-make-batches`,
  `bn-audit-prep-batch-bn`, `bn-audit-make-phase2`, `bn-audit-prep-phase2-bn`,
  `bn-audit-prep-deciders-bn`, `bn-audit-prep-functions-bn`, `bn-audit-graph-report`,
  `bn-audit-make-graph-batches`, `bn-audit-dump-table-bn`, `bn-audit-validate-reviews`.
  Ghidra: `gh-decompile`, `gh-find`, `gh-xrefs`, `gh-strxref`, `gh-scansec`, `gh-callsites`,
  `gh-frame`, `gh-disasm-range`, `gh-scan`, `gh-exec`, `gh-status`. Go RE: `go-list`, `go-addr`,
  `go-xref`, `go-diff`.
- **`agents/bn-triage`** — a read-only subagent for parallel, adversarial triage of decompiled
  functions / scanner candidates.
- **`tests/`** — a 200+ check suite (injection-guard unit tests for both clients + per-skill integration
  against compiled C fixtures, for **both** engines + graceful-failure + security checks + no-BN unit tests
  for `binary-audit`, `symbolicate`, and sidecar sync helpers):
  `python3 tests/run_tests.py`. Integration tests skip cleanly when an engine's MCP isn't reachable.

## Install

```bash
# the repo doubles as a single-plugin marketplace (.claude-plugin/marketplace.json):
/plugin marketplace add pbrass/disasm-codemode        # or a local clone path
/plugin install disasm-codemode@disasm-codemode
```

Then in Binary Ninja, start the code-mode MCP server (e.g. the
[`akrutsinger/binja-codemode-mcp`](https://github.com/akrutsinger/binja-codemode-mcp) plugin:
`Plugins > MCP Code Mode > Start Server`, binds `127.0.0.1:42069`) and verify with `bn-status`.
For the standalone capstone tools: `pip install capstone pyelftools`.

For the **Ghidra** skill, run a [ghidra-headless-mcp](https://github.com/mrphrazer/ghidra-headless-mcp)
TCP server against a Ghidra install (needs PyGhidra + a JDK):

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra python3 ghidra_headless_mcp.py --transport tcp --port 8765
```

Point the skill at it with `GHIDRA_MCP_HOST`/`GHIDRA_MCP_PORT` (default `127.0.0.1:8765`) and verify with
`gh-status`. ⚠️ ghidra-headless-mcp is **unauthenticated and runs arbitrary code** — keep it bound to
localhost or a container, never an untrusted network.

The agent loads a skill automatically when a task involves reverse-engineering, patch-diffing, or
bug-hunting a binary; the `bin/` commands are then on PATH. From a local clone (not installed), run
them as `bin/<cmd>`:

```bash
bin/bn-status                                    # is the BN code-mode MCP up?
bin/bn-exec 'print(binja.get_binary_status())'
bin/bn-sym-extract --bv-match my_open_bndb --db symdb.sqlite --profile skills/symbolicate/profiles/vmware.json
bin/bn-sym-determ --db symdb.sqlite --sidecar recovered.sidecar.json --profile skills/symbolicate/profiles/vmware.json
bin/bn-re-apply recovered.sidecar.json --bv-match my_open_bndb --no-protos --no-vars
bin/bn-cap-scan /path/to/module.o
bin/bn-symdiff old.elf new.elf --demangle --list
bin/gh-status                                    # is the ghidra-headless-mcp server up?
bin/gh-callsites --file /path/to/bin --sink memcpy   # call sites + arg expressions (Ghidra)
```

## Status

v0.9 — extracted from real vulnerability-research work and used in anger. **Binary Ninja and Ghidra** support
are both complete for the core inspect/hunt flows; Binary Ninja additionally has sidecar sync, mass
symbol-recovery, bulk-decompile, and binary-audit workflows. The suite includes no-engine unit coverage and
live MCP integration tests with hostile-binary output hardening. IDA / radare siblings are TODO. See
[CHANGELOG.md](CHANGELOG.md).
Issues and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).

> The scanners are **heuristics that surface candidates, not bugs** — every hit must be triaged to a verdict.
> Use only on binaries you are authorized to analyze.
