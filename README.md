# disasm-codemode

A [Claude Code](https://claude.com/claude-code) plugin for **driving a disassembler/decompiler headlessly
via its code-mode MCP** — to reverse-engineer binaries, **patch-diff** two builds (find silently-fixed
security bugs), and **scan for memory-safety bug classes** at scale.

The idea: most disassemblers now expose a "code mode" MCP server that runs arbitrary Python inside the tool's
own process. That's far more flexible than a fixed set of MCP "tools" — you send the exact analysis you want.
This plugin packages a battle-tested methodology + tooling around that pattern, plus disassembler-independent
helpers (capstone/pyelftools) for breadth when you don't need the full engine.

**First implementation: Binary Ninja.** The architecture invites sibling skills for IDA / Ghidra / radare —
the patch-diff method, bug-class taxonomy, and triage discipline are engine-agnostic; only the "talk to the
tool" layer changes.

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

Two companion skills build on it:
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

Plus:
- **`bin/`** — command wrappers auto-added to PATH when the plugin is installed: `bn-decompile`,
  `bn-find`, `bn-xrefs`, `bn-strxref`, `bn-scansec`, `bn-callsites`, `bn-frame`, `bn-disasm-range`,
  `bn-scan`, `bn-cap-scan`, `bn-symdiff`, `bn-bulk-decompile`, `bn-open`, `bn-status`, `bn-exec`.
- **`agents/bn-triage`** — a read-only subagent for parallel, adversarial triage of decompiled
  functions / scanner candidates.
- **`tests/`** — a 103-test suite (injection-guard unit tests + per-skill integration against compiled
  C fixtures + graceful-failure checks): `python3 tests/run_tests.py`.

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

The agent loads a skill automatically when a task involves reverse-engineering, patch-diffing, or
bug-hunting a binary; the `bin/` commands are then on PATH. From a local clone (not installed), run
them as `bin/<cmd>`:

```bash
bin/bn-status                                    # is the BN code-mode MCP up?
bin/bn-exec 'print(binja.get_binary_status())'
bin/bn-cap-scan /path/to/module.o
bin/bn-symdiff old.elf new.elf --demangle --list
```

## Status

v0.2 — extracted from real vulnerability-research work and used in anger. Binary Ninja support is complete
(four skills + a triage subagent + a 140-test suite, with hostile-binary output hardening); IDA / Ghidra
siblings are TODO. See [CHANGELOG.md](CHANGELOG.md). Issues and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).

> The scanners are **heuristics that surface candidates, not bugs** — every hit must be triaged to a verdict.
> Use only on binaries you are authorized to analyze.
