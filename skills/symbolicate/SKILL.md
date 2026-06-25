---
name: symbolicate
description: Mass-recover function names + role comments for a STRIPPED (or partially-stripped) symbol-poor binary by harvesting per-function evidence (referenced strings, call-neighborhood, log-domain tags) and naming in multi-pass propagation — deterministic exact names first, then a tiered parallel LLM pass over the evidence, with results accumulated in a git-tracked sidecar and synced into the disassembler database. Use when you open a big stripped binary (vmx, a firmware blob, a stripped daemon) and want it readable — names + analysis comments that travel with the .bndb — rather than reading sub_XXXXXX by hand.
---

# symbolicate — evidence-driven, multi-pass, parallel symbol recovery

## Thesis
Naming a stripped binary is an **evidence-propagation** problem, not a ranking problem. Ranking only orders
the work; it gives you no clue what a function *is*. So instead: (1) harvest the evidence that *identifies* a
function — the strings it references (esp. VMware-style `Identifier: message` / `__FUNCTION__` log prefixes),
its named call-neighborhood, domain tags; (2) name what's **provable** deterministically; (3) fan out a
**tiered LLM pass** over the remaining evidence; (4) **propagate** — newly-applied names become anchors that
enrich the next wave's evidence — and iterate to a fixpoint. Measure success by **coverage × confidence**, not
a priority list.

## When to use
- A big binary that is mostly `sub_XXXX` (stripped or partially-stripped) and you need it readable.
- It has *some* anchors: library symbols, log strings, a few named exports — the seeds propagation grows from.
- You want the result durable + reviewable: it lands in a **git-tracked sidecar** and syncs into the `.bndb`
  via `bn-re-apply` (the [binary-ninja] RE-sidecar tool) — names + comments + prototypes travel with the DB.

## Pipeline & interface
```
bn-sym-extract --bv-match <tab> --db symdb.sqlite --profile <prof>     # Pass 0: evidence DB (BN-side writes)
bn-sym-determ  --db symdb.sqlite --sidecar S.json --profile <prof>     # Pass 1: deterministic exact names
bn-sym-prep    --bv-match <tab> --db symdb.sqlite --out batch.json \   # Pass 3a: bundle a batch (HLIL+evidence),
               --n 100 [--spread] [--sidecar S.json]                   #   assign a tier, skip already-named
bn-sym-makewf  batch.json --out batch.wf.js                            # Pass 3b: -> self-contained naming Workflow
  Workflow(scriptPath="batch.wf.js")                                   #   one agent/function, model per tier
bn-sym-ingest  <wf-output.json> --sidecar S.json                       # Pass 3c: fold names -> sidecar (merge)
bn-re-apply    S.json --bv-match <tab>                                 # sync sidecar -> bndb (Ctrl+S to persist)
```
The **sidecar is the accumulator**: every pass writes/updates it with `name`/`comment`/`proto` plus provenance
(`_source` = determ-logstring / llm, `_confidence` = high/medium/low). Re-runnable and reviewable; you always
know what's proven vs. inferred.

### Pass 0 — evidence (`extract.py`)
Three BN passes → `symdb.sqlite`: `func(addr,name,size)`, `edge(caller,callee,callee_name)`,
`strref(func_addr,s,is_logpfx,pfx)`, `domain(func_addr,tag,source)`. Writes are done **inside BN** (sqlite, not
`open()` — the code-mode sandbox forbids file writes) so a 40k-function dump never hits the ~100 KB stdout cap.

### Pass 1 — deterministic names (`determ.py`)
The rule that needs no judgement: a function that is the **sole referencer** of a log string whose prefix is an
exact-name identifier (`Module_Verb`, e.g. `OvhdMem_PowerOn:`) almost certainly *is* that function (the binary
logs `__FUNCTION__`). High confidence, zero LLM. Also seeds **domain tags** from shared module prefixes.

### Pass 3 — tiered parallel LLM naming (`prep_batch` → `make_wf` → Workflow → `ingest`)
Each function is bundled with its HLIL + evidence and routed to a model **tier**: evidence-rich / self-identifying
→ a cheap model (Haiku), thin / needs-code-reasoning → a stronger one (Sonnet); escalate to Opus only if a
quality check demands it. `--spread` selects a tier MIX for trialing both. The agent returns
`{name, comment, confidence, proto}`; `ingest` merges into the sidecar without clobbering hand-authored or
higher-confidence entries. Prototypes that name not-yet-declared structs are fine — `bn-re-apply` auto-forward-
declares them as opaque types (a recovered struct-inventory to flesh out later).

**Abstention is a first-class outcome.** An agent with genuinely insufficient evidence returns `confidence:'none'`
(empty name) instead of fabricating a guess from noise — `ingest` leaves it unnamed. The abstained set IS the
next pass's worklist: once most of the binary is named, an abstained function's *callers and callees* are named,
which usually makes its role obvious on the second look. Don't force low-quality names early; let propagation
make them easy.

### Pass 4 — propagation (re-run to fixpoint)
After applying a wave, **re-run `extract`** so the call-neighborhood evidence reflects the new names, then prep
the next wave (`--sidecar` skips the done). Confidence compounds as the neighborhood fills in. Stop when a wave
yields little new. The hard residue (no strings, no named callees — ~40% in vmx) mostly resolves via propagation
once callees are named, or stays `sub_`.

## Profiles
`profiles/<name>.json` sets `log_prefix_re` (the `Identifier: ` convention), `exact_name_re` (what counts as an
exact name for Pass 1), `domain_tags` (the attack-surface clusters), and the naming convention. Ship `vmware.json`;
copy + retarget `log_prefix_re`/`domain_tags` for other ecosystems.

## Operational notes
- **Apply cadence — names+comments are free, prototypes are NOT.** Setting a function name or comment needs no
  analysis (a 739-function `bn-re-apply` is ~0.3s). Setting a *prototype* queues incremental analysis, so a big
  batch of them makes BN churn (a 700-fn apply with protos spent ~400s in analysis). So during the churn, sync
  with **`bn-re-apply … --no-protos --no-vars`** (instant — browse the named binary live), and apply prototypes
  **once at the end** (or in small batches, or not at all — names+comments are the deliverable; protos are a
  bonus). The sidecar always holds the protos; you choose when to pay for them.
- **Don't re-apply the whole sidecar every wave if it's slow** — names+comments are cheap so it's usually fine,
  but you can apply just the wave's new functions. The bndb is the live view; the sidecar is the source of truth.
- **Attack-surface first.** Prioritize the device/backdoor domains (the engagement's interest) in the first
  waves, then expand — `domain` tags + `--spread` make this easy.
- **Trial the tier before the churn.** Run ~50–100 with `--spread`, eyeball Haiku-tier vs Sonnet-tier quality,
  then commit the model choice. (Naming-from-evidence is squarely a Sonnet/Haiku task; Opus is rarely needed.)
- **Re-extract between waves** — propagation is where coverage compounds; don't run one giant pass.
- **Heavy BN iteration**: extract iterates 10k–100k items per pass; that's fine in one call, but avoid layering
  extra full-binary scans on top. The DB is the thing you query afterwards, not BN.

## Composes with
[binary-ninja] (`bn-re-apply`/`bn-re-vars` — the sidecar↔bndb sync this writes into), [binary-audit] (point its
ranker at the *now-named* binary for bug-hunting — naming first makes the audit far more legible), [bulk-decompile]
(offline reading of the recovered functions). Reusable beyond vmx: any large stripped symbol-poor target.
