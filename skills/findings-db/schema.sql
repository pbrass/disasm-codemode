-- findings-db: one store for an assessment's findings, across targets and methods.
--
-- Design notes
--   * Scope first (engagement/target/build/component). Every other store this
--     replaces lacked it, so "what was audited" lived only in a directory name.
--   * Findings carry a stable slug + an optional public canonical_id, and every
--     legacy signifier survives in finding_alias. Renumbering breaks already-sent
--     vendor correspondence; aliases are cheap.
--   * Producer ledgers (audit DBs, SBOM KBs) are referenced, not absorbed:
--     ledger/ledger_bug hold a pointer + verdict, provenance records the origin.
--   * Enums are CHECK-constrained. The stores this replaces used free text and
--     drifted (the same concept spelled three ways across eight DBs).

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_rev(
  rev INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL,
  note TEXT);

-- ---------------------------------------------------------------- Layer A: scope

CREATE TABLE IF NOT EXISTS engagement(
  id INTEGER PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  name TEXT,
  client TEXT,
  started TEXT,
  ended TEXT,
  notes TEXT);

CREATE TABLE IF NOT EXISTS target(
  id INTEGER PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,             -- 'appliance-a', 'gateway-vm'
  vendor TEXT,
  product TEXT,
  kind TEXT CHECK(kind IN ('hypervisor','appliance','nas','firewall','bmc',
                           'controller','container-platform','other')),
  obtainability TEXT,                    -- how an image is acquired (free ISO / trial / portal)
  notes TEXT);

CREATE TABLE IF NOT EXISTS build(
  id INTEGER PRIMARY KEY,
  target_id INTEGER NOT NULL REFERENCES target(id),
  version TEXT,                          -- marketing version
  build TEXT NOT NULL,                   -- vendor build number; the join key in practice
  marketing_name TEXT,
  release_date TEXT,
  image_path TEXT,
  image_sha256 TEXT,
  is_fleet_current INTEGER NOT NULL DEFAULT 0,   -- the in-scope build (severity framing)
  notes TEXT,
  UNIQUE(target_id, build));

CREATE TABLE IF NOT EXISTS component(
  id INTEGER PRIMARY KEY,
  build_id INTEGER NOT NULL REFERENCES build(id),
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  kind TEXT CHECK(kind IN ('kmod','userworld','shared-lib','jar','go-bin',
                           'script','firmware','package','other')),
  sha256 TEXT,
  stripped INTEGER,
  arch TEXT,
  notes TEXT,
  UNIQUE(build_id, path));

-- ------------------------------------------------------------- Layer B: findings

CREATE TABLE IF NOT EXISTS finding(
  id INTEGER PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  canonical_id TEXT UNIQUE,              -- public id; NULL until assigned
  engagement_id INTEGER REFERENCES engagement(id),
  title TEXT NOT NULL,
  discovery_method TEXT NOT NULL CHECK(discovery_method IN
    ('patch-diff','sbom','binary-audit','fuzz','source-review','manual','postex')),
  bug_class TEXT CHECK(bug_class IN
    ('oob-write','oob-read','uaf','double-free','uninit-disclosure','uninit-use',
     'auth-bypass','missing-authz','null-deref','div-zero','type-confusion',
     'int-overflow','recursion-dos','resource-leak','stack-clash','race-toctou',
     'path-traversal','injection','logic','crypto','other')),
  cwe TEXT,
  attacker TEXT CHECK(attacker IN
    ('unauth-remote','auth-remote','guest','rogue-peer','container','local',
     'host-local','physical')),
  impact TEXT CHECK(impact IN
    ('host-psod','host-rce','root-rce','rce','privesc','auth-bypass',
     'guest-readable-leak','info-disclosure','dos','none-or-guarded')),
  severity TEXT CHECK(severity IN ('critical','high','medium','low','informational')),
  cvss_vector TEXT,
  cvss_score REAL,
  status TEXT NOT NULL CHECK(status IN
    ('suspected','static-confirmed','violable','demonstrated','refuted',
     'withdrawn','gated','latent')),
  gating TEXT CHECK(gating IN
    ('default-on','config-gated','feature-gated','non-default','unknown')),
  novelty TEXT CHECK(novelty IN ('0day','nday','hardening','upstream-only')),
  first_seen TEXT,
  last_updated TEXT,
  summary TEXT,
  mechanism TEXT,
  recommendation TEXT,
  doc_path TEXT);                        -- the authoritative writeup, while md is still truth

CREATE TABLE IF NOT EXISTS finding_alias(
  finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  alias TEXT NOT NULL,
  namespace TEXT NOT NULL,
  note TEXT,
  PRIMARY KEY(alias, namespace));

CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  kind TEXT CHECK(kind IN
    ('poc','coredump','crash-screenshot','pcap','log','writeup','decompilation',
     'patch-diff','asan-report','screenshot','other')),
  path TEXT,
  sha256 TEXT,
  captured_at TEXT,
  host TEXT,
  notes TEXT);

CREATE TABLE IF NOT EXISTS finding_affects(
  finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  build_id INTEGER NOT NULL REFERENCES build(id),
  component_id INTEGER REFERENCES component(id),
  state TEXT NOT NULL CHECK(state IN
    ('affected','fixed','latent','not-present','untested')),
  confirmed_how TEXT CHECK(confirmed_how IN
    ('static','live-demo','patch-diff','version-inference','source-review')),
  evidence_id INTEGER REFERENCES evidence(id),
  note TEXT,
  PRIMARY KEY(finding_id, build_id, component_id));

CREATE TABLE IF NOT EXISTS finding_location(
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  component_id INTEGER REFERENCES component(id),
  func_name TEXT,
  func_addr INTEGER,
  detail TEXT);

-- ----------------------------------------------------------- Layer C: provenance

CREATE TABLE IF NOT EXISTS provenance(
  id INTEGER PRIMARY KEY,
  finding_id INTEGER REFERENCES finding(id) ON DELETE CASCADE,
  source_kind TEXT CHECK(source_kind IN ('ledger','sbom','markdown','fuzz','manual')),
  source_path TEXT,
  source_table TEXT,
  source_rowid INTEGER,
  imported_at TEXT,
  importer_version TEXT);

-- ----------------------------------------------------------- Layer D: disclosure

CREATE TABLE IF NOT EXISTS disclosure(
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  vendor TEXT,
  channel TEXT,
  submitted TEXT,
  vendor_tracking_id TEXT,
  vendor_status TEXT CHECK(vendor_status IN
    ('not-submitted','ack','triage','disputed','accepted','fixed','wontfix','duplicate')),
  cve TEXT,
  advisory_url TEXT,
  embargo_until TEXT,
  advisory_ref TEXT,
  last_correspondence TEXT,
  notes TEXT);

-- ------------------------------------------------- Layer E: producer ledger links

CREATE TABLE IF NOT EXISTS ledger(
  id INTEGER PRIMARY KEY,
  path TEXT UNIQUE NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('audit','sbom','graph-only')),
  target_id INTEGER REFERENCES target(id),
  build_id INTEGER REFERENCES build(id),
  component_id INTEGER REFERENCES component(id),
  schema_rev TEXT,
  row_counts TEXT,                       -- JSON snapshot at import time
  last_synced TEXT,
  notes TEXT);

CREATE TABLE IF NOT EXISTS ledger_bug(
  id INTEGER PRIMARY KEY,
  ledger_id INTEGER NOT NULL REFERENCES ledger(id) ON DELETE CASCADE,
  src_rowid INTEGER NOT NULL,
  func_name TEXT,
  bug_class TEXT,
  confidence TEXT,
  status TEXT,                           -- as recorded by the producer
  verdict TEXT,                          -- adjudication, NORMALIZED (see fdb.py VERDICT_MAP)
  verdict_raw TEXT,                      -- the producer's own label, kept verbatim
  impact TEXT,
  reachability TEXT,
  descr TEXT,
  finding_id INTEGER REFERENCES finding(id),   -- NULL = not promoted
  disposition TEXT,                      -- why an unpromoted row is not a finding
  UNIQUE(ledger_id, src_rowid));

-- One row per (CVE, bundled component) an SBOM KB says is present on a build.
-- The point is the same as ledger_bug: an inventory row is NOT a finding, but a
-- reachable one that never became a finding is a gap, so it needs either a
-- finding_id or a written disposition. Keeps the producer's own vocabulary --
-- SBOM tools disagree about severity words and reachability labels, and
-- rewriting them here would lose the ability to diff against the source KB.
CREATE TABLE IF NOT EXISTS sbom_cve(
  id INTEGER PRIMARY KEY,
  ledger_id INTEGER NOT NULL REFERENCES ledger(id) ON DELETE CASCADE,
  build_id INTEGER REFERENCES build(id),
  component_id INTEGER REFERENCES component(id),   -- when the bundled lib is a scoped component
  cve_id TEXT NOT NULL,
  component_name TEXT NOT NULL,          -- as the KB named it (package / soname / binary path)
  component_type TEXT,
  version TEXT,                          -- the version actually shipped, when the KB resolved it
  severity TEXT,
  cvss TEXT,
  fixed_version TEXT,
  present_on_fleet INTEGER,              -- shipped version is in the affected range
  present_on_successor INTEGER,          -- still vulnerable on the successor build
  fixed_in_patch INTEGER,                -- the successor bump addresses it => live n-day on fleet
  reachable TEXT,                        -- preauth-remote / postauth / local / not-reachable / ...
  exploitability TEXT,                   -- demonstrated / likely / theoretical / dos-only / none
  adjudication TEXT,                     -- the KB's own conclusion, verbatim
  gate TEXT,                             -- the reachability condition ("only if X")
  triage_status TEXT,                    -- the KB's work-tracking state
  summary TEXT,
  url TEXT,
  finding_id INTEGER REFERENCES finding(id),
  disposition TEXT,                      -- why a reachable CVE is not a finding
  src_rowid INTEGER,
  UNIQUE(ledger_id, cve_id, component_name));

CREATE INDEX IF NOT EXISTS ix_alias_finding    ON finding_alias(finding_id);
CREATE INDEX IF NOT EXISTS ix_affects_build    ON finding_affects(build_id);
CREATE INDEX IF NOT EXISTS ix_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS ix_ledgerbug_ledger ON ledger_bug(ledger_id);
CREATE INDEX IF NOT EXISTS ix_ledgerbug_find   ON ledger_bug(finding_id);
CREATE INDEX IF NOT EXISTS ix_build_target     ON build(target_id);
CREATE INDEX IF NOT EXISTS ix_component_build  ON component(build_id);
CREATE INDEX IF NOT EXISTS ix_sbomcve_ledger   ON sbom_cve(ledger_id);
CREATE INDEX IF NOT EXISTS ix_sbomcve_find     ON sbom_cve(finding_id);

-- ------------------------------------------------------------------------ views

DROP VIEW IF EXISTS v_findings;
CREATE VIEW v_findings AS
SELECT f.id, f.canonical_id, f.slug, f.title, f.discovery_method, f.bug_class,
       f.attacker, f.impact, f.severity, f.status, f.gating, f.novelty,
       e.slug AS engagement,
       (SELECT group_concat(DISTINCT t.slug)
          FROM finding_affects fa
          JOIN build b ON b.id = fa.build_id
          JOIN target t ON t.id = b.target_id
         WHERE fa.finding_id = f.id AND fa.state = 'affected') AS targets,
       -- DISTINCT build: affects is keyed per (build, component), so a finding present
       -- in two components of one build is one affected build, not two.
       (SELECT count(DISTINCT fa.build_id) FROM finding_affects fa
         WHERE fa.finding_id = f.id AND fa.state = 'affected')  AS affected_builds,
       (SELECT count(*) FROM evidence ev WHERE ev.finding_id = f.id) AS evidence_items,
       d.vendor_status, d.cve, d.submitted
  FROM finding f
  LEFT JOIN engagement e ON e.id = f.engagement_id
  LEFT JOIN disclosure  d ON d.finding_id = f.id;

-- "Affected Products" for an advisory, as a query instead of a re-derivation.
DROP VIEW IF EXISTS v_advisory_affects;
CREATE VIEW v_advisory_affects AS
SELECT f.canonical_id, f.slug, f.title,
       t.vendor, t.product, b.version, b.build, b.marketing_name,
       fa.state, fa.confirmed_how, b.is_fleet_current,
       COALESCE(b.marketing_name, t.product || ' ' || COALESCE(b.version,'') ||
                ', build ' || b.build) AS affected_line
  FROM finding f
  JOIN finding_affects fa ON fa.finding_id = f.id
  JOIN build  b ON b.id = fa.build_id
  JOIN target t ON t.id = b.target_id
 ORDER BY f.canonical_id, t.slug, b.build;

-- Yield per discovery method per target: the cross-target comparison.
-- Collapse to one row per (finding, target) FIRST. finding_affects has a row per
-- (build, component), so aggregating over the join directly counts a finding once per
-- affected build -- which inflates every sum() above the finding count and makes the
-- headline "which method paid off" number wrong in the flattering direction.
DROP VIEW IF EXISTS v_method_yield;
CREATE VIEW v_method_yield AS
WITH ft AS (
  SELECT DISTINCT f.id, f.discovery_method, f.status, f.severity,
         COALESCE(t.slug, '(unscoped)') AS target
    FROM finding f
    LEFT JOIN finding_affects fa ON fa.finding_id = f.id AND fa.state = 'affected'
    LEFT JOIN build  b ON b.id = fa.build_id
    LEFT JOIN target t ON t.id = b.target_id
)
SELECT target, discovery_method,
       count(*) AS findings,
       sum(status = 'demonstrated')                   AS demonstrated,
       sum(status IN ('static-confirmed','violable')) AS confirmed,
       sum(severity IN ('critical','high'))           AS high_or_crit
  FROM ft
 GROUP BY target, discovery_method;

-- The audit funnel per producer ledger: reviews -> preconditions -> bugs -> promoted.
DROP VIEW IF EXISTS v_funnel;
CREATE VIEW v_funnel AS
SELECT l.id, l.path, l.kind, l.row_counts,
       count(lb.id)                                     AS ledger_bugs,
       sum(lb.verdict = 'demonstrated')                 AS demonstrated,
       sum(lb.verdict IN ('violable','demonstrated'))   AS violable,
       sum(lb.verdict IN ('gated','latent'))            AS real_but_not_live,
       sum(lb.verdict = 'candidate')                    AS candidate,
       sum(lb.verdict IN ('partial','uncertain'))       AS unresolved,
       sum(lb.verdict IS NULL)                          AS unadjudicated,
       sum(lb.finding_id IS NOT NULL)                   AS promoted,
       sum(lb.finding_id IS NULL AND lb.disposition IS NULL
           AND lb.verdict IN ('violable','demonstrated')) AS violable_unpromoted
  FROM ledger l
  LEFT JOIN ledger_bug lb ON lb.ledger_id = l.id
 GROUP BY l.id;

-- Adjudicated-real ledger bugs that never became a finding, with no explicit
-- disposition. The "did we drop one?" check. Includes gated/latent: those are real
-- bugs whose reachability is conditional, not refutations, and they are the easiest
-- kind to lose track of. Order by tier to work the sweep strongest-first.
DROP VIEW IF EXISTS v_orphans;
CREATE VIEW v_orphans AS
SELECT l.path AS ledger, lb.id, lb.func_name, lb.bug_class, lb.verdict, lb.verdict_raw,
       CASE lb.verdict WHEN 'demonstrated' THEN 1 WHEN 'violable' THEN 2
                       WHEN 'gated' THEN 3 WHEN 'latent' THEN 4 ELSE 5 END AS tier,
       lb.impact, lb.reachability, lb.confidence, lb.descr
  FROM ledger_bug lb
  JOIN ledger l ON l.id = lb.ledger_id
 WHERE lb.finding_id IS NULL
   AND lb.disposition IS NULL
   AND (lb.verdict IN ('violable', 'demonstrated', 'gated', 'latent')
        OR lb.status IN ('confirmed-violable', 'confirmed', 'demonstrated'));

-- The SBOM half of the orphan sweep: a CVE the KB says is present on the fleet
-- build AND reachable (or already exploited) that no finding covers and nobody
-- wrote off. Same discipline as v_orphans -- an inventory row is allowed to be
-- boring, but not silently dropped.
DROP VIEW IF EXISTS v_sbom_orphans;
CREATE VIEW v_sbom_orphans AS
SELECT s.id, l.path AS ledger, s.cve_id, s.component_name, s.version, s.severity,
       s.reachable, s.exploitability, s.fixed_in_patch, s.gate, s.adjudication, s.summary
  FROM sbom_cve s
  JOIN ledger l ON l.id = s.ledger_id
 WHERE s.finding_id IS NULL
   AND s.disposition IS NULL
   AND s.present_on_fleet = 1
   AND (s.reachable LIKE 'pre%'
        OR s.exploitability IN ('demonstrated', 'likely'))
 ORDER BY (s.exploitability = 'demonstrated') DESC, s.severity, s.cve_id;

-- How far the SBOM triage actually got. `unassessed` is the honest number: a CVE
-- with no reachability call is not a refutation, it is work not done, and it is
-- invisible in any view that only lists conclusions.
DROP VIEW IF EXISTS v_sbom_coverage;
CREATE VIEW v_sbom_coverage AS
SELECT l.path AS ledger, t.slug AS target, b.build,
       count(*)                                              AS cves,
       sum(s.present_on_fleet = 1)                           AS on_fleet,
       sum(s.reachable IS NULL)                              AS unassessed,
       sum(s.reachable LIKE 'pre%')                          AS preauth,
       sum(s.exploitability = 'demonstrated')                AS demonstrated,
       sum(s.finding_id IS NOT NULL)                         AS promoted,
       sum(s.disposition IS NOT NULL)                        AS disposed
  FROM sbom_cve s
  JOIN ledger l ON l.id = s.ledger_id
  LEFT JOIN build  b ON b.id = s.build_id
  LEFT JOIN target t ON t.id = b.target_id
 GROUP BY l.id;

DROP VIEW IF EXISTS v_alias;
CREATE VIEW v_alias AS
SELECT a.alias, a.namespace, f.canonical_id, f.slug, f.title, f.status
  FROM finding_alias a JOIN finding f ON f.id = a.finding_id;

-- Findings worth reporting that have no disclosure record yet.
DROP VIEW IF EXISTS v_disclosure_queue;
CREATE VIEW v_disclosure_queue AS
SELECT f.canonical_id, f.slug, f.title, f.severity, f.status, f.novelty
  FROM finding f
  LEFT JOIN disclosure d ON d.finding_id = f.id
 WHERE f.status IN ('demonstrated','static-confirmed','violable')
   AND f.novelty IN ('0day','nday')
   AND (d.id IS NULL OR d.vendor_status = 'not-submitted')
 ORDER BY f.severity, f.canonical_id;
