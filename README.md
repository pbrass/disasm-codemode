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

## Install

```bash
# from a local clone (add as a plugin marketplace, then install):
/plugin marketplace add /path/to/disasm-codemode
/plugin install disasm-codemode
# or point Claude Code at the published repo once it's on GitHub.
```

Then in Binary Ninja, start the code-mode MCP server (e.g. the
[`akrutsinger/binja-codemode-mcp`](https://github.com/akrutsinger/binja-codemode-mcp) plugin:
`Plugins > MCP Code Mode > Start Server`, binds `127.0.0.1:42069`). For the standalone capstone tools:
`pip install capstone pyelftools`.

The agent loads the skill automatically when a task involves reverse-engineering, patch-diffing, or
bug-hunting a binary. You can also use the scripts directly:

```bash
python3 skills/binary-ninja/scripts/binja.py 'print(binja.get_binary_status())'
python3 skills/binary-ninja/scripts/cap_scan.py /path/to/module.o
python3 skills/binary-ninja/scripts/symdiff.py old.elf new.elf --demangle --list
```

## Status

v0.1 — extracted from real vulnerability-research work. The BN skill is complete and used in anger; IDA /
Ghidra siblings are TODO. Issues and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).

> The scanners are **heuristics that surface candidates, not bugs** — every hit must be triaged to a verdict.
> Use only on binaries you are authorized to analyze.
