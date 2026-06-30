---
name: sbom-kb
description: >-
  Build and query a SQLite SBOM + vulnerability knowledge base for bundled-component / patch-diff /
  reachability audits of an appliance, fleet, or any binary that wraps outdated OSS. Maps net-facing
  binaries -> their dynamically AND statically/vendored-linked libraries + OS packages, resolves the
  REAL upstream versions (from build-path strings in .rodata, not the RPM), attaches CVEs + silent
  upstream fixes, scores reachability (pre-auth / post-auth / local), and tracks audit completeness
  via work-status views (v_preauth_ndays = the "money" query). Reusable schema, query cookbook, and
  build tooling — point it at any appliance. Use when hunting version-based n-days across a product's
  bundled components, prioritizing a patch-diff, or proving "is this vulnerable library actually
  reachable pre-auth?".
---

# sbom-kb — SBOM + vulnerability knowledge base

A queryable SQLite KB that formalizes the **bundled-component n-day** thesis: net-facing binaries on
modern appliances are hardened vendor wrappers over *outdated* upstream OSS (OpenSSL, expat, curl,
gRPC, ICU, ...). The n-days live in those bundled libs and in the deltas a vendor silently ships
between builds. This skill turns "which outdated library, in which reachable binary, with which CVE,
fixed in which patch?" into SQL.

## When to use
- Hunting **version-based n-days** in an appliance / fleet / firmware target.
- Prioritizing a **patch-diff**: a vendor bumped a 3rd-party lib build N->N+1 => they fixed something
  => it's a live n-day on build N (the fleet). `v_patched_packages` / `v_todo` rank these.
- Answering **reachability**: "libexpat has CVE-X -- but is attacker-controlled XML parsed *pre-auth*
  by a listening binary, or is it dead weight?" (`v_preauth_ndays`, the `analysis` table).
- Tracking **completeness** across a big surface ("have we versioned + CVE-triaged every dep of every
  pre-auth binary?") via `v_completeness` / `v_binary_rollup`.

## Quickstart -- build a KB for YOUR target

The schema + queries + technique are general. The build scripts are a reference implementation you
point at your targets:

1. **Edit the CONFIG block** in `scripts/build_sbom.py` (or set env vars): `SBOM_HOST` (ssh alias of
   a live host of the *current/vulnerable* build), the `ATTACKABLE` net-facing binary list,
   `DLOPEN_PLUGINS`, the two package lists (`SBOM_PKGS_CUR`/`SBOM_PKGS_SUCC` = `rpm -qa` of the
   current vs patched build), and `VENDOR_PKG_RE` (your vendor's own package names).
2. **Run** `./scripts/rebuild.sh` (writes `./sbom.db` by default, or `$SBOM_DB`). It runs, in order:
   `build_sbom.py` (packages + ldd dep-graph + seeds + artifacts) -> `resolve_and_classify.py` (real
   lib versions from build-path strings + classify vendor-internal libs) -> `scan_static_deps.py`
   (statically-linked/vendored libs ldd misses, via `.rodata` version banners -- finds the
   ICU/gRPC/rapidjson-style hidden deps). Stages 2-3 need a live `SBOM_HOST`.
3. **Add seeds** with your findings -- CVEs, reachability verdicts, github-review log. The shipped
   `seeds/example.sql` shows the format; add your own `seed*.sql` files (loaded in sort order).
4. **Query** with `./scripts/q.sh` / `sqlite3 sbom.db`.

> Querying needs nothing; *building* needs live ssh access to a host of your target build (for `ldd`
> + version-grep). No host yet? Run with `SBOM_HOST` unset to load just packages + seeds, then
> enrich later.

## The data model (`schema.sql`)
`host` -> `artifact` (acquisition provenance: which build/host/path + sha256) . `binary`
(role, listen_ports, **reachability**, work_status) -`link`-> `library` (soname, **real version**,
upstream, github, provenance, static-bundled vs dynamic) . `package` (version_cur/succ,
changed_in_patch, is_third_party) . `cve` (present_on_fleet, fixed_in_patch, present_on_successor,
triage_status) . `analysis` (per-CVE reachability + exploitability + verdict + gating condition) .
`upstream_fix` (CVE-less silent security commits) . `github_review` (commit/issue review log) .
`residual_check` (the "present but gated on X, confirm by Y" follow-ups). **Every entity carries a
work-status** so `v_completeness`/`v_todo` answer "are we done?".

## Query cookbook (key views -- full list in queries.md)
| view | answers |
|------|---------|
| `v_preauth_ndays` | **the money query** -- fleet-present CVEs, pre-auth-reachable first |
| `v_patched_packages` | 3rd-party pkgs the vendor bumped in the patch (each = candidate live n-day) |
| `v_findings` | ranked actionable findings (reachable + severe first) + gating condition |
| `v_todo` | the outstanding worklist, one row per open item + what it needs |
| `v_completeness` | done/total at each level (binaries, libs, CVEs, patched pkgs) |
| `v_binary_rollup` | per-binary: #deps, #versioned, #open CVEs |
| `v_github_coverage` | github-review coverage per component (silent-fix hunting) |

## Extending (record findings)
Curated knowledge lives in `seeds/*.sql` (loaded last, so they override). To add a CVE + its
reachability verdict, append to a seed file:
```sql
INSERT INTO cve(cve_id,component,component_type,severity,present_on_fleet,fixed_in_patch,present_on_successor,summary,url,triage_status)
  VALUES('CVE-2026-XXXX','libexpat.so.1','library','High',1,1,0,'...','https://...','todo');
INSERT INTO analysis(cve_id,component,reachable,exploitability,reachability_condition,confirm_step,verdict,status)
  VALUES('CVE-2026-XXXX','libexpat.so.1','preauth-remote','plausible','attacker XML hits expat parser pre-auth','send malformed XML to :443','live n-day if reachable','open');
```
For silent (CVE-less) upstream fixes, use `upstream_fix`; log every commit/issue you review (incl.
dead-ends) in `github_review` so coverage is auditable. Then re-run `rebuild.sh` (it regenerates the
DB from schema + seeds -- seeds are the source of truth; the .db is disposable).

## Going deeper: the three ldd-invisible dependency sources
`ldd <binary>` gives the full *dynamic* transitive closure -- but three classes of dependency are
invisible to it, and each can hide an outdated, reachable OSS component. A complete audit runs all three:

1. **Statically-vendored OSS inside a binary OR a `.so`.** Compiled-in code still leaves version
   banners in `.rodata`. `scan_static_deps.py` greps a banner dictionary over **every binary AND
   every library** (not just the net-facing binaries) and records hits as `link_type='static-bundled'`
   (in a binary) / `'static-in-lib'` (inside a shared lib, reachability propagated to the binaries
   that load it). **Scanning the libraries is essential** -- a vendor's "internal" `.so` routinely
   vendors OSS (e.g. an internal framework lib bundling zlib + ICU), which breaks the "internal
   lib = no upstream-CVE surface" assumption.

2. **Runtime `dlopen` loads (steady-state).** `collect_proc_maps.py` snapshots `/proc/<pid>/maps` of
   the live daemons and diffs it against `ldd(exe)` (by realpath) -> the `proc_map` table +
   `v_dlopen_loads` view. Catches plugins already loaded at snapshot time: PAM/NSS modules, OpenSSL
   providers (`fips.so`/`legacy.so`), SASL mechs.

3. **Lazy `dlopen` loads (call-site).** A snapshot misses plugins loaded only on an un-exercised code
   path. `scan_dlopen_callers.py` flags every binary/lib that *imports* `dlopen`; resolve the actual
   target with the disasm code-mode skills (`gh-callsites --sink dlopen` / `bn-callsites --sink dlopen`)
   across the flagged files -- libraries included (`libsasl2` dlopens its mechs, `libcrypto` its providers).

Run order (after `build_sbom` / `resolve_and_classify`): `scan_static_deps` -> `collect_proc_maps`
(needs the daemons running) -> `scan_dlopen_callers` (+ a decompiler for the format-string targets).

## Caveats
- `changed_in_patch` (hash differs build->build) is **BuildID-noisy** -- a wholesale rebuild changes
  every hash. A hash delta does NOT prove a *code* change; confirm with a per-function diff.
- CVE/reachability rows are **curated**, not auto-scraped -- they're only as complete as the seeds.
  Treat `v_todo` as the live worklist.
- "Real version" comes from build-path/banner strings in the binary, which is far more reliable than
  the system RPM version (vendors vendor + rename), but verify before reporting a CVE as present.
