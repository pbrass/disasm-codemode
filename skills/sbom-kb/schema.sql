-- SBOM + vulnerability knowledge base
-- Two entry points:
--   (A) attackable binary -> linked library (version, github) -> CVEs -> reachability/exploitability
--   (B) installed package (version) -> CVEs -> reachability/exploitability
-- Single SQLite file, git-trackable, query with: sqlite3 sbom.db < queries.

PRAGMA foreign_keys = ON;

-- ---------- hosts we acquired artifacts from (provenance reference) ----------
CREATE TABLE IF NOT EXISTS host (
    alias       TEXT PRIMARY KEY,   -- ssh alias
    ip          TEXT,
    build       TEXT,               -- build number / version identifier
    os_version  TEXT,
    role        TEXT,               -- fleet-current | successor-patch
    notes       TEXT
);

-- ---------- acquisition provenance: every binary/lib copy we pulled, with WHERE from ----------
CREATE TABLE IF NOT EXISTS artifact (
    id              INTEGER PRIMARY KEY,
    component       TEXT,           -- binary.path or library.soname
    component_type  TEXT,           -- binary | library
    source_host     TEXT REFERENCES host(alias),
    build           TEXT,
    os_version      TEXT,
    remote_path     TEXT,           -- path on the appliance it came from
    local_path      TEXT,           -- where we stored it locally
    sha256          TEXT,
    acquired        TEXT            -- date acquired
);

-- ---------- installed packages (entry point B) ----------
CREATE TABLE IF NOT EXISTS package (
    name            TEXT PRIMARY KEY,
    version_cur     TEXT,          -- on the fleet/current (vulnerable) build
    version_succ    TEXT,          -- on the successor/patched build
    changed_in_patch INTEGER,      -- 1 = vendor bumped it current->patched (=> fixed something)
    is_third_party  INTEGER,       -- 1 = upstream OSS (not vendor-versioned)
    upstream        TEXT,          -- upstream project
    github_url      TEXT,
    -- WORK TRACKING: todo -> cve-mapped -> reach-assessed -> complete
    work_status     TEXT DEFAULT 'todo',
    notes           TEXT
);

-- ---------- attackable binaries (entry point A) ----------
CREATE TABLE IF NOT EXISTS binary (
    path            TEXT PRIMARY KEY,
    name            TEXT,
    role            TEXT,          -- e.g. "LDAP directory", "reverse proxy", "SSH"
    listen_ports    TEXT,          -- externally-open ports it owns (csv) or ''
    reachability    TEXT,          -- preauth-remote | postauth-remote | local | internal-loopback
    changed_in_patch INTEGER,      -- hash differs current->patched (BuildID-noisy; needs fn-diff to confirm code change)
    analyzed        INTEGER,       -- 1 = we audited the binary's own code
    verdict         TEXT,          -- our finding/verdict
    -- WORK TRACKING: full SBOM+reachability sign-off for this executable incl. ALL its deps
    --   todo -> deps-mapped -> deps-versioned -> cves-mapped -> reach-assessed -> complete
    work_status     TEXT DEFAULT 'todo',
    notes           TEXT
);

-- ---------- libraries (shared/bundled) ----------
CREATE TABLE IF NOT EXISTS library (
    soname          TEXT PRIMARY KEY,   -- e.g. liblber-2.4.so.2
    path            TEXT,
    version         TEXT,               -- resolved real version (from build-path/strings), NOT the system RPM
    upstream        TEXT,
    github_url      TEXT,
    provenance      TEXT,               -- build path / source tree
    changed_in_patch INTEGER,
    -- WORK TRACKING: todo -> version-resolved -> cves-mapped -> audited
    audit_status    TEXT DEFAULT 'todo',
    notes           TEXT
);

-- ---------- binary -> library dependency graph ----------
CREATE TABLE IF NOT EXISTS link (
    binary_path     TEXT REFERENCES binary(path),
    library_soname  TEXT REFERENCES library(soname),
    link_type       TEXT,               -- dynamic | static-bundled | static-in-lib | dlopen-*
    PRIMARY KEY (binary_path, library_soname)
);

-- ---------- CVEs (attached to a package OR a library) ----------
CREATE TABLE IF NOT EXISTS cve (
    cve_id          TEXT,
    component       TEXT,               -- package.name or library.soname or binary.path
    component_type  TEXT,               -- package | library | vendor-code
    year            INTEGER,
    severity        TEXT,
    affected_range  TEXT,
    fixed_version   TEXT,
    present_on_fleet INTEGER,           -- 1 = the fleet build version is in the affected range
    fixed_in_patch  INTEGER,            -- 1 = patched build addresses it (=> live n-day on fleet)
    summary         TEXT,
    url             TEXT,
    cvss            TEXT,               -- CVSS score/vector if known
    present_on_successor INTEGER,       -- 1 = STILL vulnerable in the patched build
    -- WORK TRACKING per CVE: todo (recorded, not assessed) -> reachability-done -> complete (verdict reached)
    triage_status   TEXT DEFAULT 'todo',
    PRIMARY KEY (cve_id, component)
);

-- ---------- reachability / exploitability analysis ----------
CREATE TABLE IF NOT EXISTS analysis (
    id              INTEGER PRIMARY KEY,
    component       TEXT,               -- package / library / binary
    cve_id          TEXT,               -- optional, '' for a general component verdict
    reachable       TEXT,               -- preauth-remote | postauth | local | internal | client-ssrf-gated | client-mitm-gated | not-reachable | unknown
    exploitability  TEXT,               -- demonstrated | likely | theoretical | dos-only | none | unknown
    verdict         TEXT,               -- our conclusion
    reachability_condition TEXT,        -- the GATE: "only if X"
    confirm_step    TEXT,               -- the concrete check that would prove/disprove reachability
    evidence        TEXT,               -- file ref / how we know
    status          TEXT                -- confirmed | refuted | open | not-pursued
);

-- ---------- residual reachability-confirmation checks ----------
CREATE TABLE IF NOT EXISTS residual_check (
    id          INTEGER PRIMARY KEY,
    component   TEXT,
    cve_id      TEXT,
    priority    TEXT,                   -- high | med | low
    description TEXT,                   -- the concrete check to run
    status      TEXT DEFAULT 'open'     -- open | done | dropped
);

-- ---------- upstream security fixes WITHOUT a CVE (silent fixes in commits/branches) ----------
CREATE TABLE IF NOT EXISTS upstream_fix (
    id              INTEGER PRIMARY KEY,
    component       TEXT,               -- package.name or library.soname
    repo_url        TEXT,               -- github/gitlab
    ref             TEXT,               -- commit hash / branch / tag
    date            TEXT,
    landed_version  TEXT,               -- upstream version it first shipped in
    present_on_fleet INTEGER,           -- 1 = our pinned version predates this fix
    security_relevance TEXT,            -- why it looks security-relevant
    summary         TEXT,
    url             TEXT
);

-- ---------- github/upstream commit-review log ----------
CREATE TABLE IF NOT EXISTS github_review (
    id              INTEGER PRIMARY KEY,
    component       TEXT,
    url             TEXT,
    ref_type        TEXT,               -- commit | issue | PR | changelog | release | advisory | source
    reviewed_date   TEXT,
    security_relevant TEXT,             -- yes | no | maybe
    reachable       TEXT,               -- preauth | postauth | not | n/a
    analysis        TEXT,               -- brief record of what we concluded
    links_to        TEXT                -- cve_id / upstream_fix it produced, or ''
);

-- ---------- convenience views ----------
-- The money query: pre-auth-reachable components carrying a fleet-present (live n-day) CVE.
CREATE VIEW IF NOT EXISTS v_preauth_ndays AS
SELECT c.cve_id, c.component, c.component_type, c.severity, c.fixed_in_patch,
       a.reachable, a.exploitability, a.verdict
FROM cve c LEFT JOIN analysis a ON a.cve_id = c.cve_id AND a.component = c.component
WHERE c.present_on_fleet = 1
ORDER BY (a.reachable='preauth-remote') DESC, c.severity DESC;

-- Packages the vendor patched current->successor (each bump = an acknowledged fix = candidate live n-day).
CREATE VIEW IF NOT EXISTS v_patched_packages AS
SELECT name, version_cur, version_succ, upstream, github_url, work_status, notes
FROM package WHERE changed_in_patch = 1 AND is_third_party = 1
ORDER BY name;

-- ========== WORK-TRACKING / "are we done?" ==========
CREATE VIEW IF NOT EXISTS v_todo AS
  SELECT 'cve'     AS kind, cve_id AS item, component AS ctx, triage_status AS state,
         'needs reachability/exploitability verdict' AS needs
    FROM cve WHERE triage_status != 'complete'
  UNION ALL
  SELECT 'library', soname, COALESCE(version,'(version unresolved)'), audit_status,
         CASE WHEN version IS NULL OR version='' THEN 'resolve version' ELSE 'map CVEs + audit' END
    FROM library WHERE audit_status != 'audited'
  UNION ALL
  SELECT 'binary', name, reachability, work_status, 'full SBOM+reachability sign-off'
    FROM binary WHERE work_status != 'complete'
  UNION ALL
  SELECT 'package', name, version_cur||'->'||version_succ, work_status, 'map CVEs + reachability'
    FROM package WHERE changed_in_patch=1 AND is_third_party=1 AND work_status != 'complete'
  UNION ALL
  SELECT 'residual', COALESCE(cve_id,component), priority, status, description
    FROM residual_check WHERE status='open';

-- Ranked actionable findings
CREATE VIEW IF NOT EXISTS v_findings AS
SELECT c.cve_id, c.component, c.severity, c.cvss, c.present_on_successor,
       a.reachable, a.exploitability, a.reachability_condition, a.status, c.summary
FROM cve c LEFT JOIN analysis a ON a.cve_id=c.cve_id AND a.component=c.component
WHERE c.present_on_fleet=1
ORDER BY (a.reachable='preauth-remote') DESC, (a.exploitability='demonstrated') DESC,
         (c.severity IN ('Critical','High')) DESC;

-- Dashboard
CREATE VIEW IF NOT EXISTS v_github_coverage AS
SELECT component, COUNT(*) AS reviews,
       SUM(security_relevant='yes') AS sec_relevant,
       GROUP_CONCAT(DISTINCT NULLIF(links_to,'')) AS findings
FROM github_review GROUP BY component ORDER BY component;

CREATE VIEW IF NOT EXISTS v_completeness AS
  SELECT 'binaries (attackable)' AS level,
         SUM(work_status='complete') AS done, COUNT(*) AS total FROM binary
  UNION ALL
  SELECT 'libraries', SUM(audit_status='audited'), COUNT(*) FROM library
  UNION ALL
  SELECT 'CVEs/findings', SUM(triage_status='complete'), COUNT(*) FROM cve
  UNION ALL
  SELECT 'patched 3rd-party pkgs', SUM(work_status='complete'),
         COUNT(*) FROM package WHERE changed_in_patch=1 AND is_third_party=1;

CREATE VIEW IF NOT EXISTS v_binary_rollup AS
SELECT b.name, b.reachability, b.work_status,
       COUNT(DISTINCT l.library_soname) AS deps,
       SUM(DISTINCT CASE WHEN lib.version IS NOT NULL AND lib.version!='' THEN 1 ELSE 0 END) AS deps_versioned,
       (SELECT COUNT(*) FROM cve c WHERE c.component IN
           (SELECT library_soname FROM link WHERE binary_path=b.path) AND c.triage_status!='complete') AS open_cves
FROM binary b
LEFT JOIN link l ON l.binary_path=b.path
LEFT JOIN library lib ON lib.soname=l.library_soname
GROUP BY b.path;

-- ---------- runtime process maps (captures dlopen/runtime loads that ldd misses) ----------
CREATE TABLE IF NOT EXISTS proc_map (
    build TEXT, pid INTEGER, process TEXT, exe TEXT, lib_path TEXT, soname TEXT,
    dlopen_only INTEGER,           -- 1 = mapped at runtime but NOT in ldd(exe) => dlopen/runtime load
    snapshot_date TEXT, PRIMARY KEY (build, pid, lib_path));
CREATE VIEW IF NOT EXISTS v_dlopen_loads AS
  SELECT soname, GROUP_CONCAT(DISTINCT process) AS loaded_by, MAX(lib_path) AS path
  FROM proc_map WHERE dlopen_only=1 GROUP BY soname ORDER BY soname;
