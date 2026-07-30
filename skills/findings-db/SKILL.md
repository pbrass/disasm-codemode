---
name: findings-db
description: >-
  One SQLite store for an assessment's findings — across targets, builds, components and
  discovery methods (patch-diff / SBOM n-day / binary-audit / fuzz / source-review / post-ex).
  Gives every finding a stable slug plus a canonical id, keeps every legacy signifier alive in an
  alias table, records which builds are affected/fixed/latent (so "Affected Products" is a query,
  not a re-derivation), tracks disclosure state per finding, and links back to the producer ledgers
  (binary-audit kreview.db, sbom-kb sbom.db) it was promoted from — with an orphan view that
  surfaces adjudicated-real bugs that never became a finding. Use when an assessment has outgrown a
  markdown tracker: several ID namespaces have collided, "which builds does this affect" needs a
  grep, or you want cross-target method-yield numbers.
---

# findings-db — the assessment's finding store

## Why
Long assessments accrete stores: an audit ledger per binary, an SBOM KB per product, a markdown
disclosure tracker, per-finding writeups. Each is good at its own job and none of them knows
about the others, so three things rot:

- **ID collision.** Each workstream starts its own numbering (`D1..`, `F1..`, `P4-1..`), they
  overlap, and two of them turn out to be the same bug — discovered by hand, months later.
- **Scope lives in directory names.** "Which builds is this present on, and how do we know?"
  is answered by grepping prose, and the answer drifts from what was actually tested.
- **Producer bugs get dropped.** An audit ledger adjudicates a bug `violable-bug`, nobody
  writes it up, and nothing ever notices.

This skill fixes those three specifically. It does **not** replace the producer stores — an
audit ledger is still where per-function reviews and preconditions live. Findings are *promoted*
into this DB; the ledger row is referenced, not copied.

## Model
```
engagement ─ target ─ build ─ component          Layer A: scope. Everything hangs off this.
                 │       │        │
finding ─┬─ finding_alias                        Layer B: the finding, and every name it ever had
         ├─ finding_affects (build, component, state, confirmed_how)
         ├─ finding_location (func_name, addr)
         ├─ evidence (poc / coredump / pcap / writeup ...)
         ├─ provenance (where it was imported from)      Layer C
         └─ disclosure (vendor, tracking id, CVE, embargo) Layer D

ledger ─ ledger_bug ─(finding_id)                Layer E: pointers into producer DBs
```
Key ideas:
- **`slug` is the stable key; `canonical_id` is the public one.** Renumbering breaks vendor
  correspondence already sent, so aliases are permanent and cheap.
- **`finding_affects` is per (finding, build, component)** with a `state`
  (`affected/fixed/latent/not-present/untested`) and `confirmed_how`
  (`static/live-demo/patch-diff/version-inference/source-review`). `untested` is a first-class
  state — the honest answer, and the thing prose trackers silently omit.
- **Every taxonomy column is CHECK-constrained.** Free-text status/severity drifts; eight stores
  spelled the same concept three ways.
- **Producer ledgers are referenced, not absorbed.** `ledger_bug` holds the func name, the
  producer's status, the adjudicated verdict and a `disposition` for anything deliberately not
  promoted.

## Commands
```bash
fdb init                                        # create/upgrade the schema (idempotent)
fdb new-target --slug S --vendor V --build B    # register a target + first build, print the flow
fdb load spec.json                              # idempotent bulk upsert -- the backfill path
fdb resolve P4-4                                # legacy signifier -> canonical finding
fdb register-ledger --path K --kind audit [--target T --build B --component C]
                                                # scope flags optional: a ledger written by
                                                # binary-audit >= 0.15.0 records its own, and any
                                                # flag passed overrides what it recorded
fdb import-audit  kreview.db                    # promote bug/audit rows as ledger_bug pointers
fdb import-sbom   sbom.db                       # register an SBOM KB + its host/binary counts
fdb stats                                       # row counts, yield by target x method, orphans
fdb query "SELECT ..." [--json] [--write]       # raw SQL; refuses non-SELECT without --write
```
DB path: `--db`, else `$FDB_DB`, else `./assessment.db`. Stdlib only, no network.

## Starting a new appliance
```bash
fdb init
fdb new-target --slug gateway-vpx --vendor examplecorp --product "Gateway VPX" \
               --kind appliance --build 14125 --version 14.1-25.53 \
               --obtainability "free trial ISO"
```
Then follow the five steps it prints — they are the same five every time, with this target's slug
and build already substituted in:

1. **Inventory** the image: one `component` row per binary you intend to audit.
2. **Audit** a component with `binary-audit`, exporting `KAUDIT_TARGET`/`KAUDIT_BUILD`/
   `KAUDIT_COMPONENT` so the ledger records its own scope. *Calibrate the ranking before trusting
   it.*
3. **Promote**: `register-ledger` (no scope flags needed) → `import-audit` → check `v_orphans`.
4. **Sweep** the bundled components: `import-sbom` for this build.
5. **Load** the findings by spec, then `fdb stats`.

The first build of a new target is marked `is_fleet_current` unless you pass `--not-fleet-current`
— severity framing reads that column, so leaving it unset quietly under-rates everything found on
it. `new-target` writes only rows a spec could write, and is idempotent; its real job is that a new
appliance has **one** entry point that ends by naming the next command. The reason to bother:
findings from a new target then come out of the same views (`v_method_yield`, `v_findings`,
`v_disclosure_queue`) as every existing one. Comparable cross-target numbers are the deliverable;
a second pile of markdown is the failure mode.

## The load spec
One JSON file, sections applied in dependency order, every section optional. Parents are
referenced by slug/build, never by rowid, so a spec is diffable and re-runnable:

```json
{
  "targets":    [{"slug": "appliance-a", "vendor": "ExampleCorp", "product": "Widget OS",
                  "kind": "appliance", "obtainability": "free trial ISO"}],
  "builds":     [{"target": "appliance-a", "version": "1.0", "build": "1234567",
                  "is_fleet_current": 1}],
  "components": [{"target": "appliance-a", "build": "1234567", "name": "authd",
                  "path": "/usr/sbin/authd", "kind": "userworld"}],
  "findings":   [{"slug": "authd-parse-oob", "canonical_id": "X1",
                  "title": "Length field OOB write in the request parser",
                  "discovery_method": "binary-audit", "bug_class": "oob-write",
                  "attacker": "unauth-remote", "impact": "rce", "severity": "high",
                  "status": "static-confirmed", "gating": "default-on", "novelty": "0day"}],
  "aliases":    [{"finding": "authd-parse-oob", "alias": "B7", "namespace": "legacy-audit"}],
  "affects":    [{"finding": "authd-parse-oob", "target": "appliance-a", "build": "1234567",
                  "component": "/usr/sbin/authd", "state": "affected",
                  "confirmed_how": "static"}],
  "locations":  [{"finding": "authd-parse-oob", "func_name": "ParseRequest"}],
  "evidence":   [{"finding": "authd-parse-oob", "kind": "poc", "path": "poc/authd-oob/"}],
  "disclosures":[{"finding": "authd-parse-oob", "vendor": "ExampleCorp",
                  "vendor_status": "not-submitted"}]
}
```
**Idempotency is the contract.** Re-running `load` on an unchanged spec reports every row
`unchanged` and writes nothing (`first_seen`/`last_updated` are stamped only on real change).
That is what makes a spec safe to keep in the notes tree and re-apply as the source of truth.
Caveat: a `null` in a spec means "leave alone", not "clear this field" — clear with
`fdb query --write`.

## Promoting from a producer ledger
```bash
fdb register-ledger --path audit/kreview.db --kind audit   # scope read from the ledger itself
fdb import-audit audit/kreview.db          # -> ledger_bug rows + a row_counts snapshot
fdb query "SELECT * FROM v_orphans"        # adjudicated-real, never promoted, no disposition
```
A ledger written by `binary-audit` >= 0.15.0 carries an `audit_scope` row naming the
target/build/component it audited, so registration needs no flags; `register-ledger` prints what it
read. Older ledgers recorded nothing but their directory path — pass `--target/--build/--component`
for those, or it says so and their bugs promote unscoped.

`import-audit` tolerates producer schema drift (it reads `PRAGMA table_info(bug)` and takes what
is there) and picks the **strongest** adjudication per function — a function reviewed twice must
not be filed under whichever verdict landed last.

### The verdict vocabulary
Producer ledgers drift. The same concept gets spelled `violable-bug` in one pass,
`confirmed-violable` in another, `reverify:confirmed-violable[reachability]` in a third, and
`refuted: <a paragraph of prose>` in a fourth. A funnel that misses a spelling silently
under-counts — which looks exactly like "we found nothing there". So `import-audit` normalizes
into one ranked vocabulary and keeps the producer's own label in `verdict_raw`:

| tier | verdict | means |
|------|---------|-------|
| 1 | `demonstrated` | proven on a running target |
| 2 | `violable` | the bound is breakable from an attacker-reachable path |
| 3 | `gated` | real, but off by configuration on a stock build |
| 4 | `latent` | real, but the path is not built/enabled on the builds in scope |
| 5 | `candidate` | a concrete unsafe op; reachability or liveness not yet proven |
| 6 | `partial` | enforced on some paths, not all |
| 7 | `uncertain` | static analysis could not settle it — **not** a refutation |
| 8 | `refuted` | the bound is enforced, or the path is unreachable |

An unmappable label is **reported loudly** rather than stored as NULL, because a label nothing
maps to is a bug invisible to both `v_funnel` and `v_orphans`. Extend `VERDICT_MAP` in `fdb.py`
when a new producer spelling shows up; `normalize_verdict()` already handles the annotated
(`x[note]`), pass-prefixed (`stage4:x`) and prose-suffixed (`x: because...`) shapes.

Two caveats worth knowing before you read a funnel:
- **Verdicts join to bugs by function name** — that is the only key producer ledgers carry. Where
  a late pass recorded its verdict against the *decider* rather than the flagged function, the
  verdict does not attach, and the bug lands in `unadjudicated`. That column is a to-do list, not
  a clean bill of health.
- **`uncertain` is not `refuted`.** Trace-state labels (`guest-entry`, `terminal-exhausted-*`)
  mean the trace ran out of static road, so they normalize to `uncertain`.

Then either promote or dispose of each orphan; both close the loop:
```bash
fdb query --write "UPDATE ledger_bug SET finding_id=(SELECT id FROM finding WHERE slug='...')
                    WHERE id=42"
fdb query --write "UPDATE ledger_bug SET disposition='not reachable pre-auth' WHERE id=43"
```

## Views
| view | question it answers |
|------|--------------------|
| `v_findings` | the finding list, with affected targets, evidence count, disclosure state |
| `v_advisory_affects` | the "Affected Products" block for an advisory, per finding |
| `v_method_yield` | findings per target × discovery method — which method paid off where |
| `v_funnel` | per producer ledger: bugs by verdict tier → promoted → violable-but-unpromoted |
| `v_orphans` | adjudicated-real (demonstrated/violable/gated/latent) ledger bugs with no finding and no disposition, `tier`-ranked |
| `v_alias` | every legacy signifier → its canonical finding |
| `v_disclosure_queue` | reportable findings with no disclosure record yet |

## Adopting it on a live assessment
1. **Snapshot the producer DBs first.** Copy them aside with a manifest of row counts; every
   importer below is read-only against them, but you want a before-picture to diff against.
2. **Scope before findings.** Load targets/builds/components first — a finding cannot be loaded
   against a build that does not exist, and that is the point.
3. **Aliases before renumbering.** Load each legacy signifier as an alias *before* assigning
   canonical ids, so `fdb resolve <old-id>` works from day one.
4. **Import ledgers, then work `v_orphans` to zero.** Expect it to surface real bugs that were
   adjudicated and never written up. Each one gets a finding or a `disposition`.
5. **Invert the markdown.** Once the DB is populated, generate the tracker document *from* the
   DB rather than maintaining both — otherwise you have added a store instead of unifying them.

## Notes
- The DB is engagement data, not tooling: keep `assessment.db` in the notes/engagement repo, not
  next to the skill.
- `fdb query` is read-only unless `--write`, so it is safe to hand to an agent for reporting.
- `provenance` is written by importers; hand-authored findings can record their own source with a
  `provenance` row via `--write` if you care where a claim came from.
