# Changelog

All notable changes to disasm-codemode. Versioning is semantic (MAJOR.MINOR.PATCH); pre-1.0,
minor versions may add features and refine interfaces.

## 0.12.0 — 2026-06-28

### Binary-audit: a find→verify **agent pair**, with the review lens relocated into an agent system prompt
The Stage-2 review calibration (disclosure lens, the 11-class taxonomy, required `impact`, the reachability
+ checkpoint=host-local rule, the honesty guardrails, the i→g re-anchor note) used to live as a ~9 KB **JS
template literal** inside `review-wf.js` — which is exactly why v0.11.1 had to escape backticks. It now lives
where prompts belong: a markdown **agent system prompt**.
- **New agent `binary-audit-reviewer`** (`agents/binary-audit-reviewer.md`, auto-discovered): the Stage-2
  hunter. Reads one function's pre-extracted HLIL+asm, infers preconditions (self/caller/unguaranteed), and
  emits the schema-shaped record (verdict + preconditions + suspected_bugs with `bug_class`/`impact`/
  `reachability`), self-capturing it to `<root>/review-out/<fn>.json`. Reusable standalone via the Agent tool
  ("review this one function"), not just in the workflow.
- **`review-wf.js` collapses** to the `SCHEMA` (kept for tool-layer enforcement) + a slim per-function task
  that fans out the agent via `agentType: 'binary-audit-reviewer'`. The prose lens exists **once**, in
  markdown → the template-literal break-out bug class is structurally gone (no escaping to get wrong).
- **`bn-triage` sharpened** (the verify/skeptic half) with the calibration this engagement earned: the **guard
  taxonomy** (copy-then-use, architecturally-masked input, state-invariant-on-every-path, zero-fill/
  exact-overwrite/0xFF-tail/clamp-to-produced), required **impact** (observable outcome, not mechanism), the
  **reachability** taxonomy + checkpoint=host-local, the **exploitability ladder** (demonstrated >
  confirmed-latent > gated > refuted), the disclosure **leak-back** filter, and a widened `CLASS` set.
- **Tests**: assert `review-wf.js` wires the agent (and still passes `node --check`), and that both agent
  definitions carry the lens / guard-taxonomy tokens. SKILL.md documents the find→verify agent pair.
- **Note**: install/update the plugin so `agentType: 'binary-audit-reviewer'` resolves inside a workflow.

## 0.11.1 — 2026-06-28

### Fix: `review-wf.js` failed to parse as JavaScript (binary-audit Workflow launch path)
The Stage-2 review prompt is a backtick-delimited JS template literal, but its prose used markdown backticks
(`` `div` ``/`` `idiv` ``/`` `%` ``, `` `*_Alloc` ``/`` `*_Get` ``, `` `*Cpt*` ``/`` `*Checkpoint*` ``/…) that
broke OUT of the string — so `Workflow({scriptPath: review-wf-bN.js})`, the skill's primary parallel-review
launch path, failed with `Unexpected token`. The bug stayed latent because the prior large engagement drove the
generated scripts through Codex/ephemeral workers (plain text), which never invoked a JS parser.
- Escaped the 20 prose backticks in the `review-wf.js` PROMPT template literal (the legitimate `f.locality`
  nested-template is preserved). No change to the rendered prompt the reviewer sees, or to the schema/lens.
- **New regression test** (`tests/run_tests.py`): `review-wf.js` must pass `node --check` under a harness-faithful
  wrap (strip `export`, stub the `phase`/`agent`/`pipeline` hooks, wrap top-level `return`/`await` in an async
  fn). Skips cleanly when `node` is absent. This guards the whole template-literal prompt against future
  break-out edits, not just these characters.

## 0.11.0 — 2026-06-28

### Binary-audit: broadened bug-class coverage + the impact filter + indirect-dispatch seeding
Tuning the review lens from a full guest→host engagement — adds the classes the prior passes under-covered and
forces the observable-impact discipline that culls static-loose-but-harmless findings.
- **New bug classes** (`review-wf.js` enum + per-class recipes in the prompt): `null-deref` (unchecked
  callee-NULL/`*Alloc`/lookup deref — demonstrated as live PSODs the v1 audit *missed*; controllable ones are
  corruption), `div-zero` (attacker-influenced divisor/modulus, no nonzero guard → #DE), `uninit-use`
  (uninitialized value used as a size/index/pointer = corruption, distinct from uninit-*disclosure*), and
  `logic` (for privileged userworld targets: command/path injection, file-op TOCTOU/symlink, privilege/credential
  checks — escape-class with zero memory corruption). `type-confusion` gained an actual detection recipe.
- **Required `impact` field** (`host-psod`/`host-rce`/`host-mem-corruption`/`guest-readable-leak`/`vmx-rce`/
  `vmx-crash`/`privesc`/`dos-other`/`none-or-guarded`/`unknown`): the reviewer must state the concrete
  attacker-OBSERVABLE outcome, not the mechanism — the single biggest calibration lever against the
  over-produced `confirmed-violable` findings that were runtime-guarded or whose over-read is discarded.
- **Checkpoint/restore reachability rule**: `*Cpt*`/`*Checkpoint*`/`*Restore*`/`*Load*`/`*SaveState*` are the
  forged-checkpoint/vMotion path = host-local/migration, NOT guest — the prompt + vmx profile now tag them so
  up front (this engagement repeatedly re-discovered it at adjudication time).
- **Indirect-dispatch seeding promoted from a footnote to an active step** (SKILL.md): recover the dispatch-table
  targets (ops-tables / `vmkFuncTable` / vmx device-ops) and feed them in as reachability roots via the profile
  `anchors` before scoring — device-op handlers reached only through `[ops+N]` are invisible to the direct call
  graph and otherwise score ~0 (exactly why the v1 pass missed the nfs41client callback PSODs).
- vmx-userworld profile `review_context` enriched with all of the above + a build note (re-anchor in the live `g`
  binary via string xrefs; symbolicated-`i` artifact addresses don't map). New precondition kind `nonzero-divisor`.
- `ingest.py` idempotently migrates the `impact` column; new regression tests cover the classes/impact/kind +
  the prompt+profile wiring (269 checks, all green).

## 0.10.0 — 2026-06-28

### Binary-audit: uninitialized-disclosure lens promoted to the first pass
Address randomization makes an info-leak the highest-leverage primitive (a single leaked kernel pointer
defeats kASLR and unblocks every write primitive), but the first-pass review only listed `uninit-disclosure`
in an enum — the actual hunting recipe lived only in the second-pass v2-lens harness. Folded it into the
canonical `scripts/review-wf.js`:
- The contract-inference step now runs **the disclosure lens** on every host write of a struct/buffer into
  attacker-readable memory (rings, descriptors, response/SgCopyTo buffers, datagrams, shared pages):
  non-zeroing alloc → partial/conditional fill → copy-back, plus the copy-length-exceeds-init-source shape.
  Adds the `init-complete` precondition kind.
- Every read/over-read/uninit must now be classified by two filters or it is not actionable:
  **leak-back** (`reaches-attacker` vs `discarded`=DoS-not-leak vs `side-channel`) and **reachability-origin**
  (`guest` / `userworld` / `rogue-peer` / `host-local` — a leak readable only by the userworld or host root is
  not a guest escape). New `suspected_bugs` fields `leak_back`, `disclosure_source`, `reachability`, plus
  `guarded_by` to record the exact defusing instruction on a refutation.
- `ingest.py` idempotently migrates the four new `bug` columns and persists them; the real guest-leak query is
  one line: `WHERE leak_back='reaches-attacker' AND reachability='guest' AND disclosure_source IN ('stack','heap')`.
- Profiles gain the copy-to-attacker disclosure sinks (`SgCopyTo`/`CopyToMachine`/`CopySGData`/`DeliverPkt`/
  `AllocKernelMem`); SKILL.md documents the lens, the two filters, and the full-init/anti-leak guard
  class with a calibration datum (ESXi guest-facing completion rings are systematically zero-filled, so the
  reachability filter — not the bug filter — culls most disclosure leads).

### Binary-audit: audit ledger append-history + phase-2 auto-bug
The audit ingest now **preserves history instead of replacing** it (`ingest_phase2.py`, `ingest_deciders.py`,
`ingest_guestentry.py`):
- New `audit.audit_pass` (per-function sequence) + `audit.audited_at` (UTC) columns and `func.n_audited`; each
  ingest appends a new audit row, so the full analysis history is queryable. Default flipped from `--append`
  to append-by-default (`--replace` to opt back into delete-then-insert).
- Phase-2 now auto-creates a class-inferred `bug` row for a `confirmed-violable` verdict on a function that had
  no phase-1 bug (a deeper pass can surface bugs the first pass missed); the existence check is schema-agnostic.
- New regression tests cover the disclosure columns/kind, the schema/profile wiring, append-history
  (`audit_pass` 1→2 + `n_audited`), and phase-2 auto-bug (254 checks, all green).

## 0.9.0 — 2026-06-26

### New: `symbolicate` — evidence-driven mass symbol recovery for stripped binaries
Adds `skills/symbolicate/`, a repeatable workflow for recovering useful function names and role comments in
large stripped or partially stripped binaries:
- `bn-sym-extract` harvests function evidence from an open Binary Ninja database into sqlite: referenced
  strings/log prefixes, call-neighborhoods, domain tags, and HLIL snippets.
- `bn-sym-determ` applies deterministic high-confidence names from VMware-style log prefixes before any LLM
  pass.
- `bn-sym-prep` / `bn-sym-makewf` prepare tiered naming workflow batches; `bn-sym-split` /
  `bn-sym-combine` support external fanout and strict result validation.
- `bn-sym-ingest` merges recovered names, comments, and optional prototypes into the git-tracked
  `bn-re-apply` sidecar.
- Added second-pass/locality/prototype helpers: `bn-sym-prep-locality`, `bn-sym-prep-second`,
  `bn-sym-review-protos`, `bn-sym-slice-protos`.

### Binary-audit: BN-backed extraction and caller-loop workflow
`binary-audit` can now operate when the useful function names live in a `.bndb` instead of the ELF symbol
table:
- New wrappers/scripts: `bn-audit-extract-bn`, `bn-audit-prep-batch-bn`, `bn-audit-prep-phase2-bn`,
  `bn-audit-prep-deciders-bn`, `bn-audit-prep-functions-bn`, `bn-audit-make-batches`,
  `bn-audit-make-phase2`, `bn-audit-make-graph-batches`, `bn-audit-graph-report`,
  `bn-audit-dump-table-bn`, and `bn-audit-validate-reviews`.
- Phase-2 batching can include open caller/unguaranteed preconditions, enabling broader caller-contract loops
  beyond already-open suspected bugs.
- `ingest_phase2.py` now resolves exact target names first and then uses the longest substring match, avoiding
  collisions like `Snapshot_Load` vs `Snapshot_LoadConfig_2`.

### Release hygiene
- README and marketplace metadata now describe symbol recovery, binary-audit BN-backed workflows, and the new
  command wrappers.
- Tests now cover symbolicate's no-BN sidecar/fanout helpers and the phase-2 exact-target ingest regression,
  in addition to existing wrapper/manifest checks and live MCP integration tests.

## 0.8.0 — 2026-06-25

### New: `bn-re-apply` / `bn-re-vars` — annotate in a git-tracked sidecar, sync into the bndb
Reverse-engineering work (function renames, prototypes, struct/type decls, variable names+types, and
**comments / long analysis notes**) now lives in a small hand-authored **sidecar** (JSON + C) that syncs INTO
a Binary Ninja database — so the analysis is reviewable, diff-able in git, and re-appliable to a fresh `.bndb`
in one command, instead of trapped in a 100s-of-MB blob.
- **`bn-re-apply SIDECAR.json (--bv-match|--file) [--save]`** (`skills/binary-ninja/scripts/re_sync.py`) —
  idempotent apply: **types first**, functions matched by **address**, variables by stable **identifier**;
  sets function + line **comments**, prototypes, var names/types, data symbols. Open-tab → persist with Ctrl+S
  (the GUI owns the db); `--file --save` saves headless. Reuses the `bn-audit-sync` save model.
- **`bn-re-vars (--bv-match|--file) <fn>`** (`re_vars.py`) — list a function's variables with their stable
  identifiers (+ name/type, + the function address) so the sidecar's `vars` section is easy to author.
- **No length caps.** Comments/analyses are passed through verbatim — verified a 6.9 KB, multi-line analysis
  round-trips into the bndb byte-for-byte (tests assert `len == authored`, tail intact, multi-line preserved).
- Docs: a new "Annotate as you analyze" section in the binary-ninja SKILL with the schema + example.
- Tests: +9 checks (packaging + a live apply/persist/idempotency/long-comment round-trip). Suite now 215/0.

## 0.7.4 — 2026-06-25

### Test coverage for `binary-audit` (the suite had none)
The whole `binary-audit` skill — including the new `bn-audit-sync` comment/tag writer and the ingest
scripts — was untested. Added 20 checks to `tests/run_tests.py`:
- **packaging** — `bn-audit-sync` in the `bin/` wrapper set; the `binary-audit` skill dir + `sync_to_bv.py` +
  ingest scripts present; no stale `kernel-audit/` dir.
- **`unit_binary_audit` (no MCP, always runs)** — `build_items()` emits one `[binaudit]…[/binaudit]`-wrapped
  comment with the **full** bug desc + guest_path (unique tail tokens asserted present, zero `…`), includes the
  caller-owed precondition and **excludes** the self-checked one, tags `confirmed-violable`→`violable`, and is
  deterministic/regenerable; plus the ingest cap (a 1500-char summary + 2000-char bug desc survive intact past
  the old 600 clip).
- **`test_binary_audit_live` (needs MCP)** — `bn-audit-sync --file --save` annotates + persists, and an
  independent reload of the saved `.bndb` confirms the comment survived in full (markers + both tails, no
  truncation) — the end-to-end regression guard for the 0.7.2 save fix and 0.7.3 full-text.

## 0.7.3 — 2026-06-25

### Ledger ingest: stop clipping the narrative fields
`bn-audit-sync` renders the ledger faithfully — but the ledger itself was clipping the audit/review prose at
ingest, so a `STAGE-3` path or decider `evidence` could read as a complete-looking sentence that was actually
cut mid-clause (e.g. a `guest_path` capped at 600 chars). Raised the caps **way** up where the analyst
narrative lives: `audit.guest_path`/`evidence` 600/1800 → **8000**, `residual` → 2000, `next` → 1000,
`review.summary` 600 → 4000, decider-frontier fields up too (`ingest.py`, `ingest_deciders.py`,
`ingest_guestentry.py`). `precondition.text` and `bug.desc` were already uncapped. Caps are now a runaway
backstop, not an editor. (Pre-existing rows stay as-stored — re-ingest to refill.)

## 0.7.2 — 2026-06-25

### `bn-audit-sync` — full text + reliable save
- **Full annotation text (no truncation).** The 0.7.1 word-boundary cap still elided the *end* of long
  preconditions/bug-descs (the actual bound being violated) with a `…`. Comments now carry the **complete**
  ledger text — only collapsed to one wrapped line per entry (BN/Ghidra wrap it). An audit annotation should
  read as a complete thought.
- **Fixed `--save`.** Two bugs: (1) an open-tab tool-side save raced the GUI that owns the `.bndb`
  (`database is locked`) and a separate `load()` couldn't even see it; (2) the `--file` save used a nested
  `def` whose body referenced top-level names — illegal in the code-mode sandbox → `NameError: _serr`. Now:
  **open tab** (`--bv-match`) sets comments live and prints "persist with Ctrl+S" (the GUI owns the db);
  **`--file --save`** loads its own BV and saves directly (no closure, no race) — verified to persist across a
  fresh independent reload.

## 0.7.1 — 2026-06-25

### `bn-audit-sync` readability
Comments were truncating fields mid-word (hard 90-char cut) so nothing read as a complete thought. Now each
bug/precondition/stage-3 entry carries the **full text** (collapsed to one wrapped line, generous cap with a
word-boundary `…`), under clear `BUG (...)` / `CALLER-OWED PRECONDITIONS` / `STAGE-3 (...)` sections with blank
lines between. Reads like a proper analyst annotation in the disassembler.

## 0.7.0 — 2026-06-25

### Rename: `kernel-audit` → `binary-audit`
The skill audits any large symbol-rich binary (userspace daemons, libraries, firmware), not just kernels —
the name now says so. Skill dir + `name:` renamed; SKILL/METHODOLOGY note "(formerly kernel-audit)". No
`bin/` wrappers or marketplace entries referenced the old name.

### New: `bn-audit-sync` — push the ledger back into the disassembler
`skills/binary-audit/scripts/sync_to_bv.py` + `bin/bn-audit-sync`. Writes the ledger's findings into the
BinaryView as **function comments + a `binaudit` tag**, optionally persisting a snapshot to the `.bndb` — so
the analysis is visible in BN and travels with the database. Each comment carries the review verdict, every
`bug` (class/status/desc), the caller-owed **preconditions** (the attack surface), and the Stage-3/4 audit
verdict + guest path; the tag mirrors the strongest signal (`violable`/`latent`/`gated`/`suspected`/`refuted`/
`review`). Comments are wrapped in `[binaudit]…[/binaudit]` markers and **regenerable** (re-run replaces, never
duplicates). Injection-safe (reuses `bncm`'s validated-literal embedding). Verified end-to-end: 80 functions
of the nfs41client ledger annotated + saved to the `.bndb` + survived a fresh reload.

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
