# Kernel function-by-function code-review methodology (ESXi vmkernel, 8.0.3i)

A repeatable, skill-able pipeline for auditing a large symbol-rich kernel: **rank → contract-infer →
attack the contract.** Built 2026-06-23. Target = `$KAUDIT_BIN` (27,265 funcs). Generalizes to
any symbol-rich binary; intended to become a `kernel-audit` skill/plugin (give-back).

## The thesis
Most memory-safety bugs are **broken contracts**: a function assumes something about its inputs (a length
bound, non-NULL, no integer overflow, a held lock, an object still alive) that *some caller* fails to
guarantee. So the work splits cleanly:
1. **Local** — for each function, infer the *preconditions* it relies on, and classify each as
   self-checked / caller-guaranteed / unguaranteed.
2. **Global (phase 2)** — for every caller-guaranteed-or-unguaranteed precondition, hunt a caller path that
   violates it. That path is the bug.

The ranker decides *order*; the **precondition ledger** is the durable artifact that turns phase-1 reading
into a phase-2 worklist. (Our confirmed e1000 TSO OOB read *is* exactly this shape — precondition "IHL
consistent with HDRLEN/buffer length" was caller-owed and unchecked.)

## Stage 1 — the ranker (`scripts/extract.py` + `scripts/score.py` → `kreview.db`)
`BugScore(f) = Reach(f) · Σ wᵢ·percentile(featureᵢ)`. Reachability is a **multiplier** (an unreachable
megafunction scores ~0). Features, weights, and rationale:

| feature | w | captures | source |
|---|---|---|---|
| cc (CFG E−N+2) | 1.0 | control-flow density (McCabe/Shin-Williams: top size-normalized predictor) | capstone CFG |
| n_memidx (computed addressing) | 1.2 | **the mechanism** of memory corruption | capstone operands |
| sink_calls (memcpy/str*/alloc-class) | 1.0 | the dangerous sinks | resolved calls |
| parse_off (distinct [reg+disp] reads) | 0.7 | "decodes attacker-structured input" (parser signature) | capstone operands |
| loops (back-edges) | 0.6 | input-bounded loops = overflow territory | capstone |
| state_calls (free/lock/refcount) | 0.5 | UAF / double-free / race prior | resolved calls |
| n_arith | 0.4 | residual arithmetic density | capstone |
| n_insns (size) | 0.3 | residual (bigger = more bugs) | symbol size |
| fanin (caller count) | 0.5 | precondition-violation surface (heterogeneous callers) | call graph |

`Reach(f)=γ^dist(seed→f)`, γ=0.72, with a 0.03 floor for direct-edge-unreachable funcs. Seeds = the
"everything reachable" entry set (device backends, VMCI/backdoor, hypercall, net-RX, storage-target, UW
syscall/ioctl, VSI-set). **Calibration (validate the ranker on known bugs):** `E1000TxTSOSend` #11,
`E1000DevAsyncTx` #29, `Vmxnet3EnsDev_RxWithPerQBuffer` #45 — the ranker surfaces our known-hot code at the
top. Review by **call-tree from a ranked root**, not by flat rank: reviewing #11 `E1000TxTSOSend` pulls in
its callee `E1000ValidateTsoHdrs` (flat-ranked #1013, downweighted as a small leaf) — leaves get covered
through their hot callers.

### Known limitations (v1)
- **Indirect-dispatch gap:** device-ops / VSI / syscall tables dispatch via function pointers → those
  caller→callee edges are missing, so some genuinely-reachable handlers (e.g. `PsaNvmeAddControllerInt`,
  reached via NVMe ops table) show dist=−1 and get floored. Mitigation: they're often *also* name-seeded;
  v2 = recover indirect edges (jump tables + `mov [ops+N], func` stores).
- sink/taint features are call-name + addressing heuristics, not full dataflow — TAINTDIST (true
  taint→sink distance) is deferred to the BN-refine pass on the top-N.
- `.constprop/.isra/.part` clones are ranked separately (fine — they're distinct code).

## Stage 2 — per-function review loop (produces one ledger record each)
For each function (in call-tree order from the ranked roots):
1. **Orient** — subsystem; callers (`SELECT caller…`); the **provenance** of every parameter/global read
   (attacker-controlled? validated upstream? a kernel-internal invariant?).
2. **Contract inference** — for *every* memory access and sink-call, ask **"what must hold for this to be
   safe?"** Each answer is a **precondition**. Cover: index/length in-bounds; no integer overflow in size
   math; non-NULL; signedness; object alive (not freed); lock held; field-consistency (e.g. IHL vs buffer
   len); state/order (init-before-use).
3. **Classify** each precondition: `self` (the function checks it) / `caller` (assumed, a caller must
   ensure) / `unguaranteed` (nobody obviously ensures it). `caller`+`unguaranteed` = the attack surface.
4. **Desk-check** — classic pass against the body: OOB r/w, int overflow/truncation, off-by-one, UAF,
   double-free, TOCTOU/race, uninit read, type confusion, error-path cleanup, missing return-value checks.
5. **Record** — write the ledger entry + a verdict (`clean / needs-caller-analysis / suspicious / bug`).

Tools per function: BN HLIL (register-agnostic read), `objdump -d --start/--stop`, the call graph in
`kreview.db`. Decompiled output → `<root>/product/build/binary/function.{hlil.c,asm}` (per repo convention).

## Stage 3 — attack the contract (the phase-2 audit, parallelized)
For each suspected bug / `caller`+`unguaranteed` precondition, **trace the upstream callers** to decide if the
bound is established or violable. Tooled and batchable like Stage 2:
- `prep_phase2.py N` pulls, per bug function, its caller-owed preconditions + its callers (lynchpins) from the
  `edge` table, extracts their HLIL+asm, and emits `phase2-wf-bN.js`.
- The workflow runs **one subagent per bug**, each reading the **consumer** (what bound must hold) + its
  **lynchpin callers** (which must establish it), and emitting a verdict.
- `ingest_phase2.py` folds verdicts into the `audit` table + updates `bug.status`/`precondition.status`.
Every `violable-bug` → **verify against the shipped binary** before claiming it (verify-before-claim).

### Decider loop — driving `uncertain` to a fixpoint, with differentiated terminals
An `uncertain` names the next function *up* the chain, so resolution is iterative-deepening: `prep_deciders.py`
bootstraps a frontier from every `uncertain`/`partial` verdict's named decider; `Workflow(decider-wf-bN.js)`
audits it; `ingest_deciders.py` resolves the bug or pushes the chain one function higher (**depth-cap 5**,
cycle-guarded). Loop until the frontier empties (**fixpoint**). The verdict is sharpened to **six** outcomes so
the three terminal *stalls* — which carry very different epistemic weight — are never conflated:

| verdict | → bug.status | meaning |
|---|---|---|
| `established-safe` | `refuted` | bound enforced upstream — closed |
| `violable-bug` | `confirmed-violable` | concrete unsafe op + guest path — real bug |
| `guest-entry` | `exhausted-guest-entry` | value reaches attacker origin **unclamped** — **leans violable** |
| `uncertain-continue` | extend frontier | a real in-kernel fn above may clamp — pull it next |
| `uncertain-external` | `exhausted-extsym` | decider is external/library/`*_RA` — **undecidable here** |
| `partial` | `partial` | enforced on some paths only |
| (continue hits cap/cycle) | `exhausted-depthcap` / `exhausted-cycle` | **resumable** limit / loop |

Real candidate set = `confirmed-violable` + `exhausted-guest-entry`; undecided residue = `exhausted-extsym` +
`exhausted-depthcap` ("needs more," not "safe"); closed = `refuted` + `partial` + `exhausted-cycle`.

## Ledger schema (in `kreview.db`)
```
review(addr PK, name, reviewed_at, reviewer, verdict, notes)
precondition(id PK, func_addr, func_name, text, kind, klass, sink, status, attack_note)
   kind  ∈ {len-bound, no-overflow, nonnull, range, signed, lock, lifetime, state, field-consistency}
   klass ∈ {self, caller, unguaranteed}
   status∈ {open, confirmed-violable, refuted, partial, uncertain, n/a}
bug(id PK, func_addr, func_name, desc, location, severity, confidence, why, status)   -- phase-1 suspected bugs
audit(id PK, func_name, verdict, evidence, guest_path, residual, next, confidence)    -- phase-2 verdicts
```
Query that drives phase 2:
```sql
SELECT p.func_name,p.text,p.kind FROM precondition p JOIN func f ON f.addr=p.func_addr
WHERE p.klass IN ('caller','unguaranteed') AND p.status='open' AND f.reach>0
ORDER BY f.score DESC;
```

## Run
```
python3 scripts/extract.py $KAUDIT_BIN $KAUDIT_ROOT/kreview.db   # ~25s, metrics + call graph
python3 scripts/score.py   $KAUDIT_ROOT/kreview.db                             # reachability + BugScore + worklist
sqlite3 $KAUDIT_ROOT/kreview.db "SELECT name,score,cc,dist FROM func ORDER BY score DESC LIMIT 150;"
```
Worklist: `worklist-top150.csv`. Churn annotation (per Phil: static rank, churn as context) = TODO via
normalized g/h/j byte-compare → `func.churn` column.
