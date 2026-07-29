# Query cookbook

Run against a KB you built (`SBOM_DB=./sbom.db`).
Helper: `./scripts/q.sh "<SQL>"` (pretty output; defaults to the money query with no args).
Raw: `sqlite3 -header -column sbom.db "<SQL>"`.

## The headline queries (views)
```sql
-- THE MONEY QUERY: fleet-present (live n-day) CVEs, pre-auth-reachable first
SELECT * FROM v_preauth_ndays;

-- Patch-diff leads: 3rd-party pkgs the vendor bumped current->patched (each bump = an acknowledged
-- fix = candidate live n-day on the current/fleet build). Start here on a fresh target.
SELECT * FROM v_patched_packages;

-- Ranked actionable findings (reachable + severe + demonstrated first) with the gating condition
SELECT * FROM v_findings;

-- "Are we done?" dashboard + the outstanding worklist
SELECT * FROM v_completeness;
SELECT * FROM v_todo;                 -- one row per open item + what it needs
SELECT * FROM v_binary_rollup;        -- per-binary: #deps, #versioned, #open CVEs
SELECT * FROM v_github_coverage;      -- silent-fix review coverage per component
```

## Ad-hoc recipes
```sql
-- Entry point A: a reachable binary -> its libraries (version + github) -> any CVEs
SELECT b.name, b.reachability, l.library_soname, lib.version, lib.upstream, c.cve_id, c.severity
FROM binary b
JOIN link l   ON l.binary_path = b.path
JOIN library lib ON lib.soname = l.library_soname
LEFT JOIN cve c  ON c.component = lib.soname
WHERE b.reachability = 'preauth-remote'
ORDER BY b.name, lib.upstream;

-- Statically-linked / vendored deps (the ldd-invisible ones -- ICU, gRPC, rapidjson, ...)
SELECT binary_path, library_soname, link_type FROM link WHERE link_type = 'static-bundled';

-- Third-party packages the vendor changed in the patch but we haven't CVE-mapped yet (worklist)
SELECT name, version_cur, version_succ FROM package
WHERE changed_in_patch = 1 AND is_third_party = 1 AND work_status != 'complete'
ORDER BY name;

-- n-days STILL live on the patched/successor build too (present_on_fleet AND present_on_successor)
SELECT cve_id, component, severity, summary FROM cve
WHERE present_on_fleet = 1 AND present_on_successor = 1;

-- A specific library's full picture: version, provenance, links, CVEs
SELECT * FROM library  WHERE soname LIKE '%expat%';
SELECT * FROM cve      WHERE component LIKE '%expat%';
SELECT binary_path FROM link WHERE library_soname LIKE '%expat%';

-- CVE-less silent upstream fixes to diff (repo + ref + how to confirm)
SELECT * FROM upstream_fix;

-- Residual "present but gated, confirm by X" follow-ups still open
SELECT * FROM residual_check WHERE status = 'open';

-- Acquisition provenance: where did each local copy come from + its sha256?
SELECT component, source_host, build, remote_path, sha256 FROM artifact ORDER BY component;
```

## Tips
- The `analysis` table is where the *verdict* lives (`reachable`, `exploitability`,
  `reachability_condition`, `confirm_step`, `verdict`). A `cve` row with no `analysis` row = untriaged.
- Severity sorts text-wise; filter `severity IN ('Critical','High')` for the short list.
- To see the schema for any table/view: `sqlite3 sbom.db ".schema v_preauth_ndays"`.
