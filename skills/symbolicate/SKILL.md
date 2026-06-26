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
bn-sym-prep-second --bv-match <tab> --db symdb.sqlite --sidecar S.json \
                   --out second_pass1.json --n 1200                   # targeted late residue; uses prior outputs
bn-sym-prep-locality --bv-match <tab> --db symdb.sqlite --sidecar S.json \
                     --out locality_pass1.json --n 1200 --sort address # late residue with address-neighbor
                                                                        # and callgraph-component context
bn-sym-split second_pass1.json --out-dir codex_second_pass1/chunks \
             --haiku-size 3 --sonnet-size 100                         # optional Codex/subagent fanout
bn-sym-combine --chunks codex_second_pass1/chunks \
               --results codex_second_pass1/results \
               --out codex_second_pass1/second_pass1.codex.combined.json # validate + combine fanout outputs
bn-sym-makewf  batch.json --out batch.wf.js                            # Pass 3b: -> self-contained naming Workflow
  Workflow(scriptPath="batch.wf.js")                                   #   one agent/function, model per tier
bn-sym-ingest  <wf-output.json> --sidecar S.json                       # Pass 3c: fold names -> sidecar (merge)
bn-re-apply    S.json --bv-match <tab>                                 # sync sidecar -> bndb (Ctrl+S to persist)
bn-sym-review-protos S.json --bv-match <tab> \                         # review-only prototype filter/parse queue
    --out proto_review.all.json --clean-out proto_review.clean_parse.json
bn-sym-slice-protos S.json proto_review.clean_parse.json \              # build small reviewed proto sidecars
    --sidecar-out proto_slices/boring_safe.001.sidecar.json --limit 50
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
(empty name) instead of fabricating a guess from noise — `ingest` leaves it unnamed. The abstained set is useful
input to later passes: once most of the binary is named, an abstained function's *callers and callees* are named,
which often makes its role obvious on the second look. Do not force low-quality names early; let propagation make
them easy.

Track or reconstruct abstentions when iterating. The stock sidecar only records accepted names, so a naive
`bn-sym-prep --sidecar S.json --offset 0` can keep selecting the same high-scoring functions that repeatedly
abstained. For a second pass, build the worklist from prior workflow outputs as well as the sidecar: skip or
down-rank addresses attempted many times with no name, and prefer never/rarely-attempted residue that now has
named callers/callees, domain tags, or strings. Named *callers* matter as much as named callees in late passes;
caller-heavy helpers with no strings can become identifiable only after enough callsites are named.

### Pass 4 — propagation (re-run to fixpoint)
After applying a wave, **re-run `extract`** so the call-neighborhood evidence reflects the new names, then prep
the next wave (`--sidecar` skips the done). Confidence compounds as the neighborhood fills in. Make stop/continue
decisions only after the full wave is complete: early-finishing chunks are biased toward low-signal/easy-abstain
work, while richer chunks can finish later. A practical first-pass stop rule is "finish and ingest the current
wave, then stop when net accepted names fall below a chosen threshold" (for vmx, ~250 names/wave worked well).
The hard residue (no strings, no named callees/callers, or repeatedly-abstained generic wrappers) mostly stays
`sub_` until a targeted second pass or manual analysis.

### Second pass — targeted residue
After the first pass hits the yield threshold, do not simply continue with the same offset-0 ranking. Re-extract
after applying the final wave, then use `bn-sym-prep-second` to reconstruct attempted/abstained addresses from
prior workflow outputs and prepare a narrower batch over the remaining high-context residue. By default it scans
`wave*.combined.json`, `codex_wave*/wave*.codex.combined.json`, and
`codex_second_pass*/second_pass*.codex.combined.json` under the output directory; pass repeated
`--attempt-glob` values if your layout differs. Good second-pass candidates are unnamed functions that:
have named callers and callees, are in an attack-surface domain, reference distinctive strings, or were never/rarely
sent to an agent. Poor candidates are repeated all-abstain thunks, source-file-only panic stubs, and generic free /
copy / lock wrappers unless a named callsite now exposes their role. Use the stronger tier by default for
caller/callee-heavy residue with few strings; the task is no longer cheap string matching, it is judgment over
weak contextual evidence. Mini/cheap models are still fine for tiny direct-string/domain chunks. Validate large
families before ingesting: wrapper families and string-return thunks can be high-value for readability, but they
also reveal naming-style consistency issues (for example `MksX_*` vs `X11_*`) that may deserve later cleanup.
Treat string literals visible in the HLIL call arguments as real semantic evidence even if the DB string-reference
ranking did not count them; large property-table wrapper families like `Vmx_SetProperty(..., "Disk", "SetPresent",
...)` can be high-confidence exact names after spot-checking the family shape.
As part of that validation, scan duplicate proposed names before ingest. If the evidence gives a real qualifier
(a single named caller, distinct direct-vs-list lookup behavior, etc.), disambiguate in the combined artifact
instead of relying on the ingest `_2` suffix. If the duplicate functions are genuinely indistinguishable from the
available evidence, leave the collision for later cleanup rather than inventing a fake semantic suffix. Vendored
inline/helper clones, such as SILK/CELT min/max/fixed-point helpers repeated under different callers, are acceptable
as family names with ingest suffixes unless a real caller-specific semantic qualifier is visible. Keep any surprisingly
safe prototypes in the sidecar for the later prototype pass, but continue applying active waves with `--no-protos
--no-vars`.
Also scan placeholder and "maybe" names: reject `Unknown`/`Todo`/`Maybe` as name components before ingest. If a
`Maybe` name's code shows the condition, prefer an explicit conditional name like
`ScheduleFooIfDue`, `ClearXIfZero`, or `InvokeProbeIfEnabled`; if the condition cannot be stated, the function is
usually a low-confidence candidate or an abstention. For allocation helpers, prefer names like `AllocOrNull` when
the HLIL shows a null-return failure path, reserving `MaybeFail` for cases where that wording is already an
established source/API family nearby.

When using Codex/subagent fanout instead of the generated Workflow runner, use `bn-sym-split` to make tiered chunk
files and `bn-sym-combine` after the workers finish. The combiner validates address order/counts against the input
chunks, normalizes `addr`/`tier`, clears abstention comments for ingest, reports duplicate and suspicious proposed
names, and supports manual disambiguation with repeated `--rename 0xADDR=Better_Name` or a `--rename-json` map.
Rerun the combiner with those renames after review so the combined artifact records the cleanup.

### Locality / graph residue pass
When direct string evidence and named call-neighborhood counts fall off, switch from isolated-function prep to
`bn-sym-prep-locality`. Late in recovery, address order often carries real semantic signal: adjacent functions from
one translation unit, vtable family, codec helper set, or virtual-device module are commonly clustered together.
For each still-unnamed function, locality prep adds:
- nearest named function below and above in address space, with byte distance;
- a window of nearby named functions and dominant prefixes such as `VMCISockStream`, `MSVGADX`, `SVGA3D`, or
  `PollVMX`;
- named callers/callees plus unnamed caller/callee addresses from the callgraph;
- an unnamed-run summary bounded by the nearest named address neighbors;
- an unnamed callgraph-component summary. Small/medium components include boundary named callers/callees and
  prefix counts. Giant weakly-connected components are marked `coarse: true`; treat those as weak/global context,
  not as one semantic family.

Use `--sort address` for locality waves so each chunk preserves address-contiguous families. In the worker prompt,
tell agents to use the whole chunk as context. A nearby family prefix is acceptable evidence only when the lower and
higher named neighbors agree and the HLIL/direct calls are compatible; do not force the prefix onto generic helpers
or obvious boundary functions. The right output is often a mix: exact family names for tight runs, behavior-shaped
names for helpers inside the run, and abstentions for functions that sit between families.

After combining a locality wave, review in three layers before ingest:
- combiner warnings: duplicate proposed names, suspicious placeholders/`Maybe`, accidental prototypes;
- global sidecar collisions: proposed high/medium names that already exist in the current sidecar. Either
  disambiguate with a real local qualifier visible in callers/neighbors, or defer them to a collision queue instead
  of accepting automatic `_2` suffixes in bulk;
- confidence filter: ingest high+medium only, with prototypes stripped unless this is an explicit prototype pass.

Locality waves can pay well after singleton second passes flatten out. Continue them while the reviewed high+medium
yield remains above the project threshold and quality survives the collision/suspicious-name filters; stop when the
yield falls off or the accepted names become mostly generic wrappers.

### Prototype review pass
Do not apply recovered prototypes directly from the naming sidecar. Build a review queue first:
```
bn-sym-review-protos i_vmx_full.sidecar.json --bv-match i_vmx_full \
  --out proto_review/proto_review.all.json \
  --clean-out proto_review/proto_review.clean_parse.json \
  --summary-out proto_review/proto_review.summary.md
```
This command is **review-only**: it reads the sidecar, sends candidate declarations to BN only for
`parse_type_string`, writes local JSON/Markdown review artifacts, and does not mutate the sidecar or assign
function types.

The initial clean-parse queue is deliberately conservative. A prototype is eligible only if it is at least
high-confidence, has no text-quality rejection flags, and parses in the current BN type environment without creating
opaque type stubs. Text rejection flags include: literal `?`, varargs/ellipsis guesses, function-pointer/callback
guesses, vague parameter names (`arg`, `argN`, `*_argN`, `paramN`, `*_paramN`, `unused`, `reserved`, `unknown`, `mystery`), missing
semicolon, many `void *` fragments (default reject at four or more), embedded comments/prose, non-ASCII punctuation,
C/C++ keyword parameter names such as `namespace`/`class`/`private`, and non-standard aliases such as
`int32`/`uint32`/`int64`/`uint64`.

Interpret the queues this way:
- `clean_parse`: mechanically plausible review candidates; still not automatically apply-ready.
- `needs_type_stub_review`: text passed, but BN reported unknown types. Keep these for a later explicit
  type-stub/struct pass; do not rewrite them to `void *` just to make them apply, since that usually discards the
  useful part of the prototype and BN's default analysis already recovers generic pointer shapes where it can.
- `parse_rejected`/`text_rejected`: do not apply without manual repair.

Initial manual judging criteria for `clean_parse`: prefer small scalar/string/out-parameter signatures whose function
name and prototype name agree (or where a vendored-source lowercase name is clearly intentional). Defer signatures
with broad `void *` ambiguity, callback-like semantics, guessed typedef families, suspicious return widths, or
parameter names that merely restate decompiler placeholders. Apply only small reviewed batches with
`bn-re-apply <filtered-sidecar> --bv-match <tab> --no-vars` and let BN analysis settle between batches.
`bn-re-apply` does not explicitly reanalyze after each individual prototype: it assigns all function types in the
sidecar, then calls one `update_analysis()` at the end if any prototypes/vars changed. BN may still enqueue internal
incremental work per assignment, so batch size is the practical control.

For the first low-risk slice, use:
```
bn-sym-slice-protos i_vmx_full.sidecar.json proto_review/proto_review.clean_parse.json \
  --queue-out proto_review/proto_slices/boring_safe.queue.json \
  --sidecar-out proto_review/proto_slices/boring_safe.001.sidecar.json \
  --limit 50 --offset 0
bn-re-apply proto_review/proto_slices/boring_safe.001.sidecar.json --bv-match i_vmx_full --no-vars
```
The slicer does not rewrite unknown/custom types to `void *`; it rejects them from the boring-safe queue and leaves
them for explicit review. Its default boring-safe tier requires parse-clean high-confidence prototypes with matching
prototype/function names, no custom type tokens, no pointer-to-pointer, at most two `*` fragments, at most one
`void *`, and at most five parameters.
After applying a batch, verify semantically rather than by raw type-string equality: BN may preserve or synthesize
parameter names (`arg1`, etc.) even when the sidecar prototype used unnamed parameters. Compare the live function
return type plus parameter type list against the parsed sidecar prototype; ignore parameter-name differences.

For a manual second slice, prefer reproducible address-list batches over ad hoc sidecar edits:
```
bn-sym-slice-protos i_vmx_full.sidecar.json proto_review/proto_review.clean_parse.json \
  --queue-out proto_review/proto_slices/boring_safe.queue.json \
  --sidecar-out proto_review/proto_slices/manual_review.001.sidecar.json \
  --select-tier needs_manual \
  --allow-reasons too_many_void_ptrs,too_many_pointers,pointer_to_pointer,too_many_params \
  --addr-list reviewed_addrs.txt --limit 9999
```
Good manual apply candidates are clean-parse high-confidence prototypes with no custom types, no prototype/name
mismatch, matching live BN arity, changed return/parameter type semantics, non-void returns, and at least one useful
type clarification such as `const char *`, fixed-width integer widths, or explicit output-pointer shape. Defer
prototypes that only replace BN's existing specific pointer information (`char *`, `int64_t *`, known `struct *`,
etc.) with plain `void *`; that is usually a downgrade even if the recovered parameter name is plausible. Also defer
same-semantic prototypes that only rename parameters, `param1`/`param2` placeholder names, arity-changing signatures,
and void-return changes unless you have checked the decompile/callers directly.

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
  bonus). The sidecar always holds the protos; you choose when to pay for them. Before a prototype pass, filter
  aggressively: high-confidence alone is not enough. First do a review-only pass and reject placeholders (`?`),
  varargs/ellipsis guesses, function-pointer or callback guesses, `argN`/`paramN`/`unused`/`reserved`/`unknown` parameter
  names, comment text inside the prototype, non-ASCII punctuation, C/C++ keyword parameter names such as
  `namespace`/`class`/`private`, non-standard aliases such as `int32`/`uint32`, and prototypes that need opaque
  type stubs unless you explicitly want to create those stubs. Parse-test the survivors in BN with
  `parse_type_string` before applying, and treat many-`void *` signatures as low-value even when they parse. Then
  apply only small reviewed batches with `--no-vars` so BN can analyze between batches. Applying all LLM protos
  blindly is usually too noisy.
- **Don't re-apply the whole sidecar every wave if it's slow** — names+comments are cheap so it's usually fine,
  but you can apply just the wave's new functions. The bndb is the live view; the sidecar is the source of truth.
- **Attack-surface first.** Prioritize the device/backdoor domains (the engagement's interest) in the first
  waves, then expand — `domain` tags + `--spread` make this easy.
- **Trial the tier before the churn.** Run ~50–100 with `--spread`, eyeball Haiku-tier vs Sonnet-tier quality,
  then commit the model choice. (Naming-from-evidence is squarely a Sonnet/Haiku task; Opus is rarely needed.)
- **Re-extract between waves** — propagation is where coverage compounds; don't run one giant pass.
- **Measure yields by complete waves, not early completions.** Completion time can correlate with yield, but it is
  confounded by staggered queue launches and by low-signal chunks finishing quickly. If you want timing/yield
  analysis, compare chunks launched in the same initial batch rather than the whole refill queue.
- **Heavy BN iteration**: extract iterates 10k–100k items per pass; that's fine in one call, but avoid layering
  extra full-binary scans on top. The DB is the thing you query afterwards, not BN.

## Composes with
[binary-ninja] (`bn-re-apply`/`bn-re-vars` — the sidecar↔bndb sync this writes into), [binary-audit] (point its
ranker at the *now-named* binary for bug-hunting — naming first makes the audit far more legible), [bulk-decompile]
(offline reading of the recovered functions). Reusable beyond vmx: any large stripped symbol-poor target.
