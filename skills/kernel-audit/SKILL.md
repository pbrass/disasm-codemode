---
name: kernel-audit
description: >
  Rank the functions of a large symbol-rich binary by memory-safety bug-likelihood
  (reachability × cyclomatic complexity × memory-arithmetic × sink/parser signature), then drive a
  function-by-function CONTRACT-INFERENCE review that records a queryable PRECONDITION LEDGER — which
  becomes the worklist for caller-side violation hunting. Use when auditing a kernel / hypervisor / driver /
  large C binary for guest→host or remote memory-corruption bugs and you need to spend review time where it
  pays off and keep a durable record of every function's safety contract. Then LIVE-VALIDATE candidates on a
  reachability/exploitability ladder — most static OOB looseness is runtime-guarded (copy-then-use,
  masked-input, state-invariant), and recent escapes are int-overflow/double-fetch/UAF/uninit, not loose
  bounds — so adversarial verification + the guard taxonomy are part of the skill, not an afterthought.
---

# kernel-audit — rank → contract-infer → attack → live-validate

*Generalized from the ESXi 8.0.3 vmkernel engagement; examples (e1000 TSO, vmxnet3 queue-count) are illustrative. Point `seed_regex` at any attack surface — see `profiles/generic-c.json`.*

## Thesis
Most memory-safety bugs are **broken contracts**: a function assumes something about its inputs (a length
bound, non-NULL, no integer overflow, a held lock, a live object, one header field consistent with another)
that *some caller* fails to guarantee. So split the work:
1. **Rank** functions by bug-likelihood (don't read 27k functions in symbol order).
2. **Contract-infer** per function: record every precondition + whether it's self-checked, caller-owed, or
   unguaranteed. (The ledger.)
3. **Attack** the caller-owed / unguaranteed preconditions: find a caller path that violates one. That path
   is the bug. (E.g. the e1000 TSO OOB read this skill was built on = a caller-owed field-consistency
   precondition — guest IHL not reconciled with the descriptor header length — that nobody checked.)

## When to use
- A big binary (hundreds–tens of thousands of functions) you can't review exhaustively.
- It is **symbol-rich** (FUNC symbols present) — this is what makes the call graph + reachability cheap.
  (Stripped? recover symbols first, or fall back to ranking by intrinsic features only.)
- You want a durable, queryable artifact (the ledger) rather than ad-hoc notes.

## Getting started (quickstart)
The scripts are path-agnostic via env vars — set them once:
- `KAUDIT_BIN`     — the **target ELF** to audit (symbol-rich). Required.
- `KAUDIT_ROOT`    — working dir for the ledger (`$KAUDIT_ROOT/kreview.db`) + extracted `hlil/`,`asm/` (default `.`).
- `KAUDIT_BVMATCH` — (optional) the open Binary Ninja BV name for `bn-decompile` HLIL (default = basename of `KAUDIT_BIN`).
```bash
export KAUDIT_BIN=./target.elf KAUDIT_ROOT=./kaudit
mkdir -p "$KAUDIT_ROOT"/hlil "$KAUDIT_ROOT"/asm
cp profiles/generic-c.json myprofile.json   # then EDIT seed_regex -> your attacker-input entry fns
python3 scripts/extract.py "$KAUDIT_BIN" "$KAUDIT_ROOT/kreview.db" myprofile.json   # metrics + call graph
python3 scripts/score.py   "$KAUDIT_ROOT/kreview.db" myprofile.json                 # reachability + BugScore, prints top-40
# *** CALIBRATE: confirm a known bug lands in the top percentile before trusting the ranking ***
python3 scripts/prep_batch.py 1                       # -> $KAUDIT_ROOT/review-wf-b1.js
#   Workflow(scriptPath:"$KAUDIT_ROOT/review-wf-b1.js")   # 1 subagent/fn -> records
python3 scripts/ingest.py <workflow-output.json>      # -> review/precondition/bug
# then Stage 3 (prep_phase2 -> Workflow -> ingest_phase2), the decider loop (prep_deciders…), and Stage 4 live-validation.
```

## Pipeline & interface
```
scripts/extract.py  <binary> <db> [profile.json]   # ~25s: capstone metrics + resolved call graph -> sqlite
scripts/score.py    <db>        [profile.json]      # reachability gate + BugScore; writes back; prints top-40 + anchors
# review (pick one):
scripts/prep_batch.py N   +   Workflow(scripts/review-wf-bN.js)   # parallel: 1 subagent/function -> structured records
scripts/ingest.py   <workflow-output.json>          # load records into the ledger (review/precondition/bug tables)
```
Outputs in `<db>`: `func` (metrics + `reach`/`dist`/`score`), `edge` (call graph), `review`, `precondition`,
`bug`. Worklist = `SELECT name,score,cc,dist FROM func ORDER BY score DESC`.

### BugScore
`BugScore(f) = Reach(f) · Σ wᵢ·percentile(featureᵢ)`. Reach is a **multiplier** (`γ^dist(seed→f)`, floor for
direct-edge-unreachable) so an unreachable megafunction scores ~0. Features (weights in the profile): cc
(CFG E−N+2), n_memidx (computed addressing = the corruption mechanism, w=1.2), sink_calls, parse_off
(distinct input-offset reads = parser signature), loops, state_calls (UAF/race), n_arith, size, fanin
(precondition-violation surface). Full rationale: `METHODOLOGY.md`.

### Designing the ranking function (the profile = your ranking function)
**The profile (`profiles/*.json`) IS the ranking function** — tuning it is the main lever, and the design
rationale (why each feature, how to weight, the reachability multiplier) is in `METHODOLOGY.md`. A profile sets:
- `seed_regex` — **the most important knob**: the functions where attacker bytes first enter (the reachability
  roots). Get this right for *your* target or everything scores ~0 or uniformly.
- `sink_regex` — the dangerous operations (copy/alloc/user-copy) that anchor `sink_calls`.
- `state_regex` — free/lock/refcount calls that anchor `state_calls` (UAF/race signal — the v2 lifetime lens).
- `weights` — per-feature multipliers in `BugScore = Reach · Σ wᵢ·percentile(featureᵢ)`; bump `n_memidx`
  (corruption mechanism), `n_arith` (the v2 int-overflow lens), `state_calls` (UAF/race) for the v2 classes.
- `gamma`, `floor` — the reachability decay and the floor for direct-edge-unreachable functions.
- `anchors` (optional) — the calibration set: function names whose rank `score.py` prints at the end. Put your
  **known bugs** (or, for a fresh target with none, the **known attacker-entry handlers**) here and confirm they
  land in the top percentile before trusting the ranking. Defaults to the ESXi device anchors if omitted.
- `review_target` / `review_attacker` / `review_context` (optional) — the per-target framing spliced into the
  Stage-2 review prompt (what binary, who the attacker is, what the guest/remote-controlled inputs are). Set
  these so the reviewers hunt the *right* classes (e.g. mbuf/TLV parsing for a net stack, queue-pair/datagram
  size math for VMCI) instead of the default device-datapath framing. Omitted → the ESXi vmkernel-datapath default.
Ship two: `esxi-vmkernel.json` (device backends + storage-target + net + VMCI/hypercall + UW-syscall + VSI)
and `generic-c.json` (parser/IO/ioctl + libc/alloc sinks). **To target a new binary: copy `generic-c.json`,
set `seed_regex` to your input handlers, set `anchors` + the `review_*` framing, optionally re-weight, run
extract+score — then CALIBRATE** (confirm an anchor lands in the top percentile). No profile arg → ESXi defaults.

### Review (Stage 2) — produces one ledger record per function
For each ranked function (call-tree order from the roots — a hot root pulls in its callees):
1. **Orient**: what it does; provenance of each param/global (attacker / kernel-internal / validated-upstream).
2. **Contract inference**: for every computed-index memory access and every variable-size sink, ask "what
   must be true for this to be safe?" Each answer = a precondition. Cover len-bound, no-overflow, signed,
   nonnull, lifetime (UAF), lock (race), **field-consistency** (one input field bounding another).
3. **Classify**: `self` / `caller` / `unguaranteed`. caller + unguaranteed = attack surface.
4. **Desk-check**: OOB r/w, int overflow/truncation, off-by-one, UAF, double-free, TOCTOU, uninit, type
   confusion, error-path cleanup, unchecked returns.
The parallel implementation (`review-wf*.js`) fans out one subagent per function (reads pre-extracted
`hlil/<fn>.hlil.c` + `asm/<fn>.asm`), returning a schema-validated record. Solo works too — same loop.

### Stage 3 — attack the contract (the phase-2 audit, tooled)
Phase-1 records what each function *assumes*; Stage 3 decides whether each caller-owed assumption is actually
**established** (safe) or **violable** (a real bug) by tracing the upstream callers. This is a distinct,
parallelizable pass — *not* re-reading the function in isolation.

**Scope Stage 3 to the FULL caller-owed surface, not just the reviewer-flagged `suspected_bugs`.** The bugs are
the sharp tips; the real worklist is every `caller`/`unguaranteed` precondition (often 5–10× as many). Triage it
first or you'll either drown or under-cover:
- **spicy** = an *attacker-controlled value* (packet/datagram/descriptor field) feeds a size/index/offset bound
  (`field-consistency`/`no-overflow`/`signed`/`len-bound`/`range`). **Trace these** — they're the memory-corruption surface.
- **boilerplate** = a *kernel-internal* contract owed by a trusted caller ("mbuf valid", "inpcb ref-held",
  "lock held", nonnull on an internal ptr). Lower yield; characterize, don't chase each one.
- **UAF/race residue** = the `unguaranteed` `lifetime`/`lock`/`state` preconds — a *separate* pass from the
  size/offset trace (different question: is the object ref/lock-held across use, and can a concurrent context
  free it). Don't let the spicy-size triage silently drop these.
Slice it with SQL (`SELECT func_name,kind,klass,attack_note FROM precondition WHERE klass IN('caller','unguaranteed')`)
and fan out one agent per consumer (the tcpip4/vmci runs used ad-hoc `verify-wf`/`trace-wf`/`uaf-wf` scripts in
the same shape as `phase2-wf`). **Reachability often hinges on a layer OUTSIDE the audited binary** — the entry
chain that delivers attacker input (e.g. whether a guest can hold the socket fd that reaches a vmkernel ioctl):
trace *who registers/invokes the entry handler* before claiming guest→host, or you'll over- or under-rate severity.
```
scripts/prep_phase2.py N         # for phase2-batches.json[N-1]: per bug fn, pull its caller-owed preconditions
                              # + its callers (lynchpins) from the edge table, extract HLIL+asm, emit phase2-wf-bN.js
Workflow(scripts/phase2-wf-bN.js)# 1 subagent/bug: read consumer + lynchpin callers -> trace the bound
scripts/ingest_phase2.py <out>   # verdicts -> `audit` table + bug.status / precondition.status
```
Each task bundles the **consumer** (the flagged fn — exactly what bound must hold) with its **lynchpin
callers** (which must establish it). Verdict taxonomy (the key discipline): **established-safe** (bound IS
enforced upstream → `refuted`), **violable-bug** (NOT enforced, guest can break it → `confirmed-violable`),
**partial** (enforced on some paths), **uncertain** (the establishing check is *above* the provided callers —
the subagent must say so and **name the next function to pull**, never assume safe). Worklists:
```sql
SELECT func_name,desc,confidence FROM bug WHERE status='open' ORDER BY ... ;            -- not-yet-adjudicated
SELECT func_name,verdict,evidence,guest_path FROM audit WHERE verdict='violable-bug';   -- the real candidates
```
Every `violable-bug` → **verify against the shipped binary before claiming it** (the verify-before-claim rule).
Iterate the audit batch-by-batch until every suspected bug is adjudicated.

**Driving `uncertain` to a fixpoint — the decider loop.** An `uncertain` names the next function *up* the
chain, so resolution is iterative-deepening: `scripts/prep_deciders.py N` bootstraps a frontier from every
`uncertain`/`partial` verdict's named decider, `Workflow(decider-wf-bN.js)` audits that frontier, and
`scripts/ingest_deciders.py` either resolves the bug or pushes the chain one function higher (depth-capped,
cycle-guarded) — loop N=1,2,… until the frontier is empty (**fixpoint**). The decider verdict is sharpened to
**six** outcomes so a stalled chain is never lumped into one "unknown" bucket — the three terminal stalls mean
very different things:
- `established-safe`→refuted · `violable-bug`→confirmed-violable · `partial`.
- **`guest-entry`** — the value reaches a guest/target-controlled origin *unclamped* (the contract is owed to
  the attacker) → `exhausted-guest-entry`, **leans violable** (a real candidate, not "unknown").
- `uncertain-continue` — a real *in-kernel* function above might still clamp it → extend the frontier; if it
  hits the depth cap → `exhausted-depthcap` (**resumable** tooling limit), or a cycle → `exhausted-cycle`.
- **`uncertain-external`** — the decider is an external / library / `*_RA` symbol not in the binary →
  `exhausted-extsym`, genuinely **undecidable here** (needs external analysis).
Final tally reports **`confirmed-violable` + `exhausted-guest-entry`** as the real guest→host candidate set,
*separately* from the `exhausted-extsym`/`exhausted-depthcap` residue — that residue is "needs more," **not**
"safe." Only `refuted`/`partial`/`exhausted-cycle` are closed.

## Calibration discipline (do this first)
Validate the *ranker* the way you'd validate a model: confirm your **known bugs land in the top percentile**
before trusting the ranking (here: `E1000TxTSOSend` #11, `E1000DevAsyncTx` #29). If it can't surface what
you already found, retune weights/seeds. Likewise validate the *methodology*: run the review loop on a known
bug and confirm it reproduces that bug's precondition violation.
**No prior bug to anchor on (a fresh module)?** Anchor instead on the **known attacker-entry handlers** — the
functions a guest/remote attacker provably drives (datagram/queue-pair/doorbell dispatch, packet `*_input`,
ioctl/DevControl) — and confirm *they* land top-percentile. That validates `seed_regex`+weights even without a
ground-truth defect. (tcpip4: prior findings F2/F3/F5 as anchors; vmci: no priors → anchored on
`VMCIQPBrokerAllocInt`/`VMCIDatagram_Dispatch`/the VMK-devops handlers, all top-14/599.)

## The ledger schema (sqlite — created/migrated by the scripts)
- **func**(addr, name, size, n_insns, cc, loops, n_mem, n_memidx, n_arith, n_call, n_callind, sink_calls,
  state_calls, parse_off, **reach, dist, score**) — one row/function: the static metrics + computed
  reachability/BugScore (the ranking).
- **edge**(caller, callee) — resolved direct call graph (addresses).
- **review**(addr, name, reviewed_at, reviewer, verdict, notes) — one Stage-2 review/function.
- **precondition**(id, func_addr, func_name, text, kind, **klass**, sink, status, attack_note) — the contract
  ledger; `klass` = the safety class (len-bound / no-overflow / lifetime / lock / field-consistency / …).
- **bug**(id, func_addr, func_name, desc, location, severity, confidence, why, **status**, **bug_class**).
- **audit**(id, func_name, verdict, evidence, guest_path, residual, next, confidence, **guard**) — Stage-3/4
  adjudication trail.

**v2 columns (analysis-type aware — added for the Stage-4 lens):**
- `bug.bug_class` ∈ {`oob`, `int-overflow`, `double-fetch`, `uaf-lifetime`, `uninit-disclosure`, `race`} —
  the exploited-class taxonomy; slice the ledger by class, e.g.
  `SELECT func_name,status FROM bug WHERE bug_class='double-fetch'`.
- `audit.guard` — the EXACT defusing check (+address) recorded on a `refuted`/`confirmed-latent` verdict
  (Stage-4 discipline: always record the guard — a sibling path missing it is the next lead).
- `bug.status` walks the **exploitability ladder**: `demonstrated` > `confirmed-latent` > `confirmed-violable`
  > `gated` > `candidate-needs-poc` > `partial` > `refuted` (+ decider-loop terminals
  `exhausted-guest-entry` / `-extsym` / `-depthcap` / `-cycle`). All worklists are plain SQL.
- Migrations are idempotent (`ALTER TABLE … ADD COLUMN`), so an existing pre-v2 ledger picks up `bug_class`
  and `guard` on the next ingest.

## Stage 4 — live validation: reachability ≠ exploitability (v2, the key correction)
The rank→infer→attack pipeline reliably **produces candidates**, but its `confirmed-violable` bar (static: a
caller-owed bound the guest can break) systematically **over-produces** — on live validation most candidates
were *guarded at runtime* by something the static pass can't see. So grade on a **reachability/exploitability
ladder**, not the static binary:
`demonstrated (live PSOD/leak)` > `confirmed-latent (precondition reachable, exploit window closed by a guard)`
> `gated (real defect, needs non-default config / different threat model)` > `refuted`.

**Adversarially verify every candidate (cheap, mandatory).** Spawn a skeptic that re-disassembles and *tries
to find the guard*. Most static looseness is defused by one of:
- **copy-then-use** — the guest value is copied into a host struct/local during validated setup; the use
  reads the host copy → no validate-then-refetch race, no live mutability. THE most common guard — and why
  **double-fetch lives in the live DATAPATH (ring/descriptor reads), not in the one-time-copied setup**.
- **architecturally-masked input** — the register/field can't hold the value the overflow needs (e.g. e1000
  `TDLEN` is a ~20-bit field, so `(TDLEN>>4)*0x40` can't wrap).
- **state invariant** — the dangerous count/state is reset on every path that reaches the sink (e.g. vmxnet3
  numRx is reset in `UnmapRQs` on every clean teardown before `ClearMemoryRegions` runs).
Record the **exact guard (with address)** even on a refutation — it's honest, and a *sibling path missing the
same guard* is the next lead.

**Verification techniques that worked (device backends):**
- **Host-side log oracle** — `/var/log/vmkernel.log` logs device-emulation rejects with the offending fields
  (`TxTSOSend: expectations not satisfied … IP settings: 14 24 1`). Use it as the iterate-signal for blind
  raw-device PoCs: send a *valid* baseline, confirm it passes, then perturb one field at a time.
- **i==j binary diff** — if the function is byte-identical between the suspected-vulnerable build and the
  vendor-patched build, the vendor never patched it → strong evidence it was never a real defect (refutes a
  static over-read fast).
- **Device rigs** — a guest LKM that forges the device's shared structs / programs the raw TX-RX ring
  directly (bypassing the in-guest driver's own validation) is what actually exercises the host path; the
  in-guest driver usually *can't* emit the malicious shape (it validates first).

**Calibrate against what's EXPLOITED, not just what you found.** Recent hypervisor escapes (Pwn2Own 2024-25:
VMXNET3 int-overflow, PVSCSI heap-overflow, VMCI underflow, USB UAF, TOCTOU) are dominated by four classes —
add them as first-class scoring features + review-checklist items, because plain loose-bound OOB (v1's focus)
is exactly the class that kept turning out guarded:
1. **integer-overflow-in-size** — guest field through `imul/shl/add/sub` into an alloc/copy size, bound
   checked on the *wrapped* value (or the bound uses the wrapped product while the copy uses raw operands).
2. **double-fetch / TOCTOU** — host loads the *same* guest ring/DMA field ≥2× with a check between, without
   copying to a local (a racing vCPU changes it). Hunt the live datapath, not setup.
3. **lifetime / UAF** — free/Destroy/refcount-dec then use; freed-on-one-context, used-on-another.
4. **uninitialized-disclosure** — non-zeroing alloc → partial fill → copy/DMA back to the guest.
(v2 detectors + per-surface notes: the v2 class list above; parallel v2-lens review harness:
`scripts/phase3-v2-lens-review.js` (worked example).)

**Net meta-lesson:** confidently *refuting* (with the guard recorded) is as valuable as finding — a hardened
surface honestly characterized is a real deliverable, and the guard taxonomy is reusable calibration for the
next product/version.

## Known limitations (be honest in reports)
- **Indirect-dispatch gap**: function-pointer/vtable/syscall-table edges are missing from the direct call
  graph, so some genuinely-reachable handlers show `dist=-1` and get floored. Mitigation: name-seed them; v2
  = recover indirect edges (`mov [ops+N], func` stores + jump tables).
- Features are static heuristics (call-name + addressing), not full dataflow; a TAINTDIST (taint→sink
  distance) refinement on the top-N via a decompiler is the next accuracy lever.
- readelf symbol *sizes* can be noisy — trust the decompiler's function size for any single-function claim.

## Operational notes (running the parallel harness at scale)
Validated on a 252-function review + a 28-bug phase-2 audit, all via background `Workflow` fan-out:
- **Embed the work-list in the script**, don't pass it via `args` — workflow `args` did not bind reliably
  (`pipeline() expects an array`); `prep_batch.py`/`prep_phase2.py` therefore template the list into
  `const FNS=[…]`/`const TASKS=[…]` (single line) via regex-swap of the template.
- **Pre-extract HLIL+asm to files; subagents Read them** — don't have N subagents each hit the decompiler
  (one BN/Ghidra instance ⇒ contention). The asm is authoritative where HLIL truncates (~60KB cap on
  megafunctions) and for the raw memory arithmetic.
- **Batch ~25 reviews / ~8 audits per workflow**, ~10–14 run concurrently (the harness cap). Commit a
  **save point after each batch** (`kreview.db` + progress md) so a crash costs ≤1 batch.
- **AUP content-filter**: occasionally one subagent is blocked mid-output ("violative cyber content") and
  returns nothing — detect via **assigned-minus-returned** (`set(batch) − set(results)`). Re-review blocked
  functions **solo at the very end**, after everything is committed, so a filter-trip on the *interactive*
  session can't bork the run mid-flight (resume from git). Queue them; don't do them inline.
- **Restart-survivable by construction**: all state is on disk (`kreview.db`, `batches.json` /
  `phase2-batches.json`, the `*-progress.md` trackers); the `review-wf-bN.js` are regenerable. Resume = read
  the progress tracker, `prep_*` the next batch, relaunch.
- **Honesty guardrails in the prompt pay off**: "default to `uncertain`, name the next function, this is
  contract verification not exploit-dev" produced calibrated verdicts (clean/needs-caller-analysis dominate;
  bugs are flagged with confidence + caller-audit targets, not fabricated).

## Composes with
`disasm-codemode` (bn-/gh- decompile for the HLIL+asm the review reads), `sbom-kb` (version-debt findings),
the precondition ledger format is the durable, shareable artifact. Generic beyond ESXi — point `seed_regex`
at any attack surface.
