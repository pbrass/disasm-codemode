---
name: binary-audit
description: >
  (formerly kernel-audit.) Rank the functions of a large symbol-rich binary by guest-reachable memory
  corruption/disclosure and v2 race/lifetime bug-likelihood
  (reachability × cyclomatic complexity × memory-arithmetic × sink/parser/state signature), then drive a
  function-by-function CONTRACT-INFERENCE review that records a queryable PRECONDITION LEDGER — which
  becomes the worklist for caller-side violation hunting. Use when auditing a kernel / hypervisor / driver /
  large C binary for guest→host or remote corruption/disclosure/race/lifetime bugs and you need to spend review time where it
  pays off and keep a durable record of every function's safety contract. Then LIVE-VALIDATE candidates on a
  reachability/exploitability ladder — most static OOB looseness is runtime-guarded (copy-then-use,
  masked-input, state-invariant), and recent escapes are int-overflow/double-fetch/UAF/uninit, not loose
  bounds — so adversarial verification + the guard taxonomy are part of the skill, not an afterthought.
---

# binary-audit — rank → contract-infer → attack → live-validate

*(formerly `kernel-audit` — renamed because it audits any large symbol-rich binary, not just kernels.)
Generalized from the ESXi 8.0.3 vmkernel engagement; examples (e1000 TSO, vmxnet3 queue-count) are
illustrative. Point `seed_regex` at any attack surface — see `profiles/generic-c.json`.*

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

### Stripped binary / recovered-BNDB quickstart
When the useful symbols live in a Binary Ninja `.bndb` rather than the ELF symbol table, use the BN-backed
path. Keep the target open in Binary Ninja and point `KAUDIT_BVMATCH` at the tab name; this avoids `objdump`
address/rebase mistakes and captures recovered names, function ranges, and direct call edges.
```bash
export KAUDIT_BIN=/abs/path/target
export KAUDIT_ROOT=/abs/path/audit-root
export KAUDIT_BVMATCH=<open-binary-ninja-tab-substring>
export KAUDIT_PROFILE=/abs/path/profile.json
mkdir -p "$KAUDIT_ROOT"/hlil "$KAUDIT_ROOT"/asm
bn-audit-extract-bn --bv-match "$KAUDIT_BVMATCH" --db "$KAUDIT_ROOT/kreview.db" --profile "$KAUDIT_PROFILE"
python3 scripts/score.py "$KAUDIT_ROOT/kreview.db" "$KAUDIT_PROFILE"
bn-audit-make-batches --db "$KAUDIT_ROOT/kreview.db" --out "$KAUDIT_ROOT/batches.json" --batch-size 25 --limit 250
bn-audit-prep-batch-bn 1 --bv-match "$KAUDIT_BVMATCH" --root "$KAUDIT_ROOT" --profile "$KAUDIT_PROFILE"
# run the generated review workflow / fanout, save JSON, then:
python3 scripts/ingest.py "$KAUDIT_ROOT/reviews/batch01.combined.json"
bn-audit-make-phase2 --db "$KAUDIT_ROOT/kreview.db" --batch-size 8
bn-audit-prep-phase2-bn 1 --bv-match "$KAUDIT_BVMATCH" --root "$KAUDIT_ROOT"
bn-audit-prep-deciders-bn 1 --bv-match "$KAUDIT_BVMATCH" --root "$KAUDIT_ROOT"   # for uncertain/partial phase-2 frontiers
```
The BN extractor adds `func_meta` and `audit_text` helper tables in addition to the normal ledger tables.
`func_meta` records whether a name is still auto-generated and the observed caller/callee counts; `audit_text`
caches HLIL/asm by address so batches can be regenerated without re-decompiling everything.
For ad-hoc decider work after an `uncertain`, use:
```bash
bn-audit-prep-functions-bn --bv-match "$KAUDIT_BVMATCH" --root "$KAUDIT_ROOT" FuncA FuncB --addr 0x1234
```
It resolves names/addresses through `kreview.db`, extracts text from the open BNDB, and writes a manifest at
`$KAUDIT_ROOT/followup-functions.json` (or `--out ...`).
For indirect-dispatch gaps, first ask BN for data refs to the handler, then dump the table and pull the
dispatcher/producer functions:
```bash
bn-xrefs --bv-match "$KAUDIT_BVMATCH" HandlerName --data
bn-audit-dump-table-bn --bv-match "$KAUDIT_BVMATCH" --addr 0x17c9e60 --count 64 \
  --stride 16 --ptr-off 0 --flag-off 8 --out "$KAUDIT_ROOT/dispatch-table.json"
bn-audit-prep-functions-bn --bv-match "$KAUDIT_BVMATCH" --root "$KAUDIT_ROOT" Dispatcher ProducerFn HandlerName
```
Then verify both sides: the dispatcher must prove how the table index is selected, and the producer must prove
whether the handler's parsed fields are clamped before the shared command buffer is dispatched.

## Pipeline & interface
```
scripts/extract.py  <binary> <db> [profile.json]   # ~25s: capstone metrics + resolved call graph -> sqlite
scripts/extract_bn.py --bv-match <tab> --db <db> --profile <profile.json>
scripts/score.py    <db>        [profile.json]      # reachability gate + BugScore; writes back; prints top-40 + anchors
scripts/graph_report.py --db <db> --out graph-locality.json --md graph-locality.md
                                                        # address/callgraph locality report for stripped/recovered targets
scripts/make_graph_batches.py --db <db> --graph graph-locality.json --out graph-batches.json
                                                        # graph/locality-guided batches over high-score auto-name residue
# review (pick one):
scripts/prep_batch.py N   +   Workflow(scripts/review-wf-bN.js)   # parallel: 1 subagent/function -> structured records
scripts/prep_batch_bn.py N --bv-match <tab>                       # same, but address-safe for recovered BNDBs
scripts/prep_batch_bn.py N --batches graph-batches.json --graph-context graph-locality.json \
                           --workflow-out review-wf-graph-bN.js   # graph-guided unnamed batch with locality context
scripts/prep_functions_bn.py --bv-match <tab> FuncA --addr 0x...  # arbitrary follow-up/decider extraction
scripts/validate_reviews.py <combined.json> --workflow review-wf-bN.js  # pre-ingest schema/taxonomy/coverage gate
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
   nonnull, lifetime (UAF), lock (race), **field-consistency** (one input field bounding another), and
   **init-complete** (every byte of a buffer written into attacker-readable memory is defined). On *every* write
   of a struct/buffer into attacker-readable memory (guest RX/CQ/completion ring or descriptor, response/reply/
   SgCopyTo buffer, datagram, shared page) run **the disclosure lens**: non-zeroing alloc → partial/conditional
   fill → copy/DMA back = uninitialized host memory disclosed (stack bytes = return addresses → kASLR). Address
   randomization makes this a first-class objective, not an afterthought — a single leaked kernel pointer unblocks
   every write primitive.
3. **Classify**: `self` / `caller` / `unguaranteed`. caller + unguaranteed = attack surface.
4. **Desk-check** ALL classes: OOB r/w, int overflow/trunc/sign, off-by-one, UAF/double-free/refcount, TOCTOU
   (incl. a 2nd vCPU racing shared rings/headers), **uninit-disclosure**, and the classes prior passes
   UNDER-COVERED — hunt them explicitly: **null-deref** (unchecked callee-NULL/`*Alloc`/lookup deref — we
   demonstrated this as live PSODs and the v1 audit *missed* them, [[kernel-audit-callback-nullderef-gap]];
   controllable ones = corruption, not just a crash); **div-zero/#DE** (attacker-influenced divisor/modulus,
   no nonzero guard); **uninit-use** (uninit value used as a size/index/pointer = corruption, distinct from
   uninit-*disclosure*); **type-confusion** (attacker/restored tag/handle/opcode → wrong struct/union/handler);
   and for **privileged userworld targets**, **logic** bugs (command/path injection, file-op TOCTOU/symlink,
   privilege/credential checks) — escape-class with zero memory corruption. Then on every finding:
   - **leak-back** (for reads/uninit): reaches-attacker vs discarded(=DoS-not-leak) vs side-channel.
   - **reachability-origin**: `guest`/`userworld`/`rogue-peer`/`host-local`. **`*Cpt*`/`*Checkpoint*`/`*Restore*`/
     `*Load*`/`*SaveState*` = the checkpoint/migration path = forged by the trusted VMX or vMotion source =
     host-local/migration, NOT guest** — tag them so up front (this session burned cycles re-discovering it).
   - **impact**: the concrete attacker-OBSERVABLE outcome (host-psod/host-rce/guest-readable-leak/vmx-rce/
     privesc/none-or-guarded) — *what the attacker actually gets*, not the mechanism. This is the biggest
     calibration lever: it kills the static-loose-but-harmless findings (guarded at runtime, or over-read
     discarded) at review time.
   - the defusing **guard** (memset/exact-overwrite/0xFF tail-fill/clamp/NULL-check addr) even on a refutation —
     a sibling path (other caller, command, device variant) missing it is the next lead.
The parallel implementation (`review-wf*.js`) fans out the **`binary-audit-reviewer` agent** — one per
function (reads pre-extracted `hlil/<fn>.hlil.c` + `asm/<fn>.asm`) — which carries the full lens in its
system prompt (markdown, not a JS template literal), returns a schema-validated record, AND self-captures
it to `<KAUDIT_ROOT>/review-out/<fn>.json` (crash-resilient; glob those for ingest). `review-wf.js` keeps
only the `SCHEMA` + the slim per-function task. Solo works too — same loop. **Verify side:** the
`bn-triage` agent is the adversarial skeptic — fan it out (or run one) to try to REFUTE each surviving
candidate and record the defusing guard. Both agents are auto-discovered from the plugin's `agents/` dir
(install/update the plugin so `agentType` resolves in a workflow).

**Combine gate before ingest.** Do not load raw fanout blindly. First run
`bn-audit-validate-reviews "$KAUDIT_ROOT/reviews/batchNN.combined.json" --workflow "$KAUDIT_ROOT/review-wf-bN.js"`
and review the warnings:
- assigned-vs-returned must match; missing functions are queued for solo rerun, not silently skipped.
- taxonomy must be normalized to the schema enums (`kind`, `klass`, `confidence`, `bug_class`); ad-hoc labels
  from agents are edited before ingest.
- promote a `suspected_bugs` entry only when it has a concrete unsafe memory operation, an HLIL/ASM anchor, and
  a plausible attacker-controlled violation. Weak callee-contract or restore-parser speculation should remain
  a `caller`/`unguaranteed` precondition with `needs-caller-analysis`, not an open bug.
- default low-confidence leads to preconditions unless broad triage is explicitly desired. Medium/high suspected
  bugs should name the exact next invariant Stage 3 must prove or refute.

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
scripts/prep_phase2_bn.py N      # same, but extracts consumer/caller text from the open BNDB by address
                              # + its callers (lynchpins) from the edge table, extract HLIL+asm, emit phase2-wf-bN.js
Workflow(scripts/phase2-wf-bN.js)# 1 subagent/bug: read consumer + lynchpin callers -> trace the bound
scripts/ingest_phase2.py <out>   # verdicts -> `audit` table + bug.status / precondition.status
```
Build `phase2-batches.json` with `scripts/make_phase2_batches.py` / `bn-audit-make-phase2`. Default batches
open suspected bugs; add `--include-preconditions` when you want the broader caller-owned contract surface even
for functions that Stage 2 did not label as a suspected bug.
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

**Ranked partial follow-up loop.** After broad Stage 3 reaches a large `partial` residue, switch from linear
batches to small, high-signal follow-up loops. Recompute the normalized histogram after each loop, select the
next 5 partials most likely to close, extract only their named next-hop functions with
`bn-audit-prep-functions-bn`, run bounded read-only agents, ingest valid JSON, then re-rank from the updated DB.
Selection priority:
- favor partials with a concrete attacker-controlled tuple already named (`checkpoint`/`restore`/`migration`,
  descriptor/packet/count/length fields, stale pointer+length, or wrap/OOB language);
- favor cases where the residual is a short list of named helpers, constructors, restore callbacks, dispatch
  tables, or teardown paths that can be pulled in one manifest;
- deprioritize generic wrapper residue whose only blocker is broad registration provenance unless the callback
  set is small and concrete;
- group targets that share helper context (USB/RemoteUSB, xHCI rings, BusLogic restore, Vigor dispatch) so each
  manifest is dense and workers do not rediscover the same path;
- keep the closure standard strict: promote only with a named controlled path and exact violating tuple/race;
  refute only when constructors, restore helpers, locks/lifetime, and dispatch prove the invariant on every
  reachable path; otherwise return a narrower partial with exact next functions/addresses.
Operationally, run one loop as: SQL-rank partials → inspect starting artifacts → extract a focused
`followupN-functions.json` → create one prompt per target with "up to five trace cycles" → launch read-only
ephemeral workers at a resource-safe cap → validate `jq` → `ingest_phase2.py` without append so the old row is
replaced → checkpoint the selected targets, verdict changes, histogram, and resource state. Do not let a
confirmed adjacent corruption automatically promote another target; require an exact flow into that target's
own unsafe operation.

### Graph/locality steering for stripped targets
For recovered-name BNDBs, run `bn-audit-graph-report` after extraction/scoring and whenever a broad review pass
falls below the yield threshold:
```bash
bn-audit-graph-report --db "$KAUDIT_ROOT/kreview.db" \
  --out "$KAUDIT_ROOT/graph-locality.json" --md "$KAUDIT_ROOT/graph-locality.md"
bn-audit-make-graph-batches --db "$KAUDIT_ROOT/kreview.db" \
  --graph "$KAUDIT_ROOT/graph-locality.json" --out "$KAUDIT_ROOT/graph-batches.json" \
  --vmx-keywords --min-score 1.0 --limit 48
bn-audit-prep-batch-bn 1 --bv-match "$KAUDIT_BVMATCH" --root "$KAUDIT_ROOT" \
  --batches "$KAUDIT_ROOT/graph-batches.json" --graph-context "$KAUDIT_ROOT/graph-locality.json" \
  --workflow-out "$KAUDIT_ROOT/review-wf-graph-b1.js"
```
The report highlights:
- address-contiguous auto-name runs bounded by nearest named lower/higher functions;
- prefix-sandwiched functions where both sides or the local window agree on a family prefix;
- unnamed direct-call components with named boundary callers/callees and dominant boundary prefixes.
Use it in two ways. For **symbol recovery**, feed high-signal runs back into `symbolicate`'s
`bn-sym-prep-locality` rather than continuing the same exhausted second-pass queue. For **bug hunting**, treat
high-score unnamed runs/components near device, checkpoint, migration, VMCI/vsock, USB, storage, graphics, or RPC
families as audit expansion targets, especially when they contain sink/parser-heavy functions or sit on the
callgraph boundary of a confirmed candidate. Prefix agreement is evidence, not proof: reviewers should still
check the HLIL and direct callers/callees before accepting a name or claiming a reachable bug.

**Driving `uncertain` to a fixpoint — the decider loop.** An `uncertain` names the next function *up* the
chain, so resolution is iterative-deepening: `scripts/prep_deciders.py N` bootstraps a frontier from every
`uncertain`/`partial` verdict's named decider, `Workflow(decider-wf-bN.js)` audits that frontier, and
`scripts/ingest_deciders.py` either resolves the bug or pushes the chain one function higher (depth-capped,
cycle-guarded) — loop N=1,2,… until the frontier is empty (**fixpoint**). For stripped/recovered-BNDB targets,
use `scripts/prep_deciders_bn.py N` / `bn-audit-prep-deciders-bn` instead; it extracts consumer and decider
text from the open BNDB and keeps the workflow address-safe. The decider verdict is sharpened to
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
  state_calls, parse_off, **reach, dist, score**, **n_audited**) — one row/function: the static metrics + computed
  reachability/BugScore (the ranking). `n_audited` tracks how many Stage-3/4 audit passes have been run on this
  function (incremented by every ingest); use it to prioritize under-analyzed functions and measure diminishing
  returns (`SELECT name,n_audited,score FROM func WHERE n_audited>3 ORDER BY n_audited DESC`).
- **edge**(caller, callee) — resolved direct call graph (addresses).
- **review**(addr, name, reviewed_at, reviewer, verdict, notes) — one Stage-2 review/function.
- **precondition**(id, func_addr, func_name, text, kind, **klass**, sink, status, attack_note) — the contract
  ledger; `klass` = the safety class (len-bound / no-overflow / lifetime / lock / field-consistency / …).
- **bug**(id, func_addr, func_name, desc, location, severity, confidence, why, **status**, **bug_class**,
  **leak_back**, **disclosure_source**, **reachability**, **guarded_by**) — the last four (disclosure/threat-model
  lens, idempotent-migrated) let you triage by exfil + actor without re-reading: e.g. the real guest kASLR-leak
  set is `SELECT func_name FROM bug WHERE leak_back='reaches-attacker' AND reachability='guest' AND
  disclosure_source IN ('stack','heap','adjacent-object')`; `guarded_by` holds the defusing instruction on a
  refutation.
- **audit**(id, func_name, verdict, evidence, guest_path, residual, next, confidence, **guard**,
  **audit_pass**, **audited_at**) — Stage-3/4 adjudication trail. Each ingest APPENDS a new row (never
  replaces), so the full analysis history is preserved. `audit_pass` is a per-function sequence number
  (1, 2, 3, …) tracking how many times this function has been through the audit loop; `audited_at` is the
  UTC timestamp. Query the latest verdict: `SELECT * FROM audit WHERE func_name=? ORDER BY audit_pass DESC LIMIT 1`.
  Full history: `SELECT audit_pass,verdict,evidence FROM audit WHERE func_name=? ORDER BY audit_pass`.

**v2 columns (analysis-type aware — added for the Stage-4 lens):**
- `bug.bug_class` ∈ {`oob`, `int-overflow`, `double-fetch`, `uaf-lifetime`, `uninit-disclosure`, `uninit-use`, `null-deref`, `div-zero`, `type-confusion`, `race`, `logic`, `other`} and `bug.impact` ∈ {`host-psod`, `host-rce`, `host-mem-corruption`, `guest-readable-leak`, `vmx-rce`, `vmx-crash`, `privesc`, `dos-other`, `none-or-guarded`, `unknown`} (the observable-outcome filter) —
  the exploited-class taxonomy; slice the ledger by class, e.g.
  `SELECT func_name,status FROM bug WHERE bug_class='double-fetch'`.
- `audit.guard` — the EXACT defusing check (+address) recorded on a `refuted`/`confirmed-latent` verdict
  (Stage-4 discipline: always record the guard — a sibling path missing it is the next lead).
- `bug.status` walks the **exploitability ladder**: `demonstrated` > `confirmed-latent` > `confirmed-violable`
  > `gated` > `candidate-needs-poc` > `partial` > `refuted` (+ decider-loop terminals
  `exhausted-guest-entry` / `-extsym` / `-depthcap` / `-cycle`). All worklists are plain SQL.
- Migrations are idempotent (`ALTER TABLE … ADD COLUMN`), so an existing pre-v2 ledger picks up `bug_class`,
  `guard`, the disclosure columns (`leak_back`/`disclosure_source`/`reachability`/`guarded_by`), and `impact` on
  the next ingest.

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
- **full-init / anti-leak** (the disclosure refuter) — a buffer written to attacker-readable memory is fully
  defined before exposure: a `memset(0)` before populate, an exact-size full overwrite (every byte stored, e.g.
  the vmxnet3 RCD gen-bit rewrite forces all 16 bytes incl. rssHash←0), or a deliberate `0xFF`/`0x00` tail-fill
  on the alignment slack (vmci datagram delivery does this explicitly). **Calibration datum (ESXi 8.0.3):** the
  guest-facing completion paths — vmxnet3 RX desc, PVRDMA CQE (all 8 builders memset 0x40), vmci datagram —
  are *systematically* hardened this way, so most uninit-disclosure leads on guest device rings refute; the
  residual real leaks were `host-local` (PsaNvme LOG-SENSE stack over-read) or `userworld`-only
  (VMCIContext_GetCheckpointState heap) — i.e. the **reachability filter, not the bug filter, is what culls
  them**. Hunt the *short/error path* and *reserved fields* the fast-path zero-fill may skip, and the
  copy-length-exceeds-init-source shape (a guest length clamped only against the destination).
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
- **Indirect-dispatch gap (DO THIS — the highest-leverage reachability fix)**: function-pointer/vtable/
  ops-table/syscall-table edges are missing from the direct call graph, so the guest-reachable *device-op
  handlers* — reached ONLY via a dispatch table — show `dist=-1` and get floored to ~0, i.e. the audit ranks
  the WRONG functions. This is exactly why the v1 pass missed the nfs41client callback PSODs
  ([[kernel-audit-callback-nullderef-gap]]). **Before scoring, recover the dispatch-table targets and feed them
  in as reachability roots** via the profile's `anchors` list (or name-seed them in `seed_regex`): scan the data
  section for the `mov [ops+N], func` / vtable / jump-table stores (e.g. the vmkernel `vmkFuncTable`, the vmx
  device-ops tables — the vmx-audit's `dispatch-table-*.json` already holds these). A handler that is only ever
  called through `[ops+N]` is invisible to the direct graph but is the guest's actual entry point.
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
- **For stripped/recovered binaries, stay address-based after extraction**: use `extract_bn.py`,
  `make_batches.py`, `prep_batch_bn.py`, `prep_functions_bn.py`, `make_phase2_batches.py`, and
  `prep_phase2_bn.py` / `prep_deciders_bn.py`. For indirect dispatch, use `bn-xrefs --data` plus
  `dump_table_bn.py` / `bn-audit-dump-table-bn` to recover handler tables before deciding reachability.
  Avoid mixing a rebased BNDB address with
  `objdump --start-address` from the raw ELF unless you have verified the image base.
- **Stage-2 ingest is replace-by-function by default**: re-ingesting an improved review deletes that function's
  previous Stage-2 preconditions/bugs before inserting the new set. Use `ingest.py --append` only for intentional
  multi-pass comparison.
- **Pre-ingest validation is a save-point check**: `validate_reviews.py` / `bn-audit-validate-reviews` catches
  missing fanout results, duplicate records, invalid taxonomy, unanchored suspected bugs, and low-confidence bugs
  that should usually be carried as preconditions. Run it before every `ingest.py` call and keep the clean
  combined JSON in `reviews/`.
- **Honesty guardrails in the prompt pay off**: "default to `uncertain`, name the next function, this is
  contract verification not exploit-dev" produced calibrated verdicts (clean/needs-caller-analysis dominate;
  bugs are flagged with confidence + caller-audit targets, not fabricated).

## Sync the ledger back into the disassembler (`bn-audit-sync`)
Write the ledger's findings into the BinaryView as **function comments + a `binaudit` tag**, so the analysis
is visible in BN and travels with the `.bndb` (or a teammate's). Each comment is wrapped in
`[binaudit]…[/binaudit]` markers and is **regenerable** — re-run after the ledger updates and the block is
replaced, not duplicated.
```bash
bn-audit-sync LEDGER.db --bv-match <substr>          # preview: write comments into the OPEN tab (in memory)
bn-audit-sync LEDGER.db --bv-match <substr> --save   # + persist a snapshot to its .bndb
bn-audit-sync LEDGER.db --file /abs/path.bndb --save # load fresh, annotate, save
bn-audit-sync LEDGER.db --bv-match <substr> --all    # also annotate functions reviewed 'clean'
```
Each comment carries the review verdict, every `bug` (class/status/desc), the **caller-owed preconditions**
(`klass` in caller/unguaranteed — the attack surface), and the Stage-3/4 `audit` verdict + guest path. The
tag value mirrors the strongest signal (`violable` / `latent` / `gated` / `suspected` / `refuted` / `review`)
for one-glance triage + filtering in the GUI. Annotates any function with a bug, an audit, or a non-clean
review by default. (Ghidra: the equivalent — `setComment(PLATE_COMMENT)` + labels inside a transaction, saved
to the project — is straightforward via `gh-exec`; not yet wrapped.)

## Composes with
`disasm-codemode` (bn-/gh- decompile for the HLIL+asm the review reads), `sbom-kb` (version-debt findings),
the precondition ledger format is the durable, shareable artifact. **`bn-audit-sync` pushes it back into the
`.bndb` as comments/tags.** Generic beyond ESXi — point `seed_regex` at any attack surface.
