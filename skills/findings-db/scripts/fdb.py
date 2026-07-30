#!/usr/bin/env python3
"""fdb -- the findings database for an assessment.

One store for findings across targets, builds and discovery methods, plus thin
links back to the producer ledgers (audit DBs, SBOM KBs) they were promoted from.

  fdb init                                  create/upgrade the schema
  fdb load spec.json                        idempotent bulk upsert (the backfill path)
  fdb resolve P4-4                          legacy signifier -> canonical finding
  fdb register-ledger --path ... --kind ... register a producer DB
  fdb import-audit <kreview.db>             promote bug/audit rows as ledger_bug pointers
  fdb import-sbom  <sbom.db>                link an SBOM KB's hosts/binaries
  fdb stats                                 row counts + the funnel
  fdb query "SELECT ..."                    raw SQL (read-only unless --write)

The database path comes from --db, else $FDB_DB, else ./assessment.db.
Stdlib only; no network.
"""
import argparse, json, os, sqlite3, sys, hashlib, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(os.path.dirname(HERE), "schema.sql")
SCHEMA_REV = 2
VERSION = "0.2.0"


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db_path(args):
    return args.db or os.environ.get("FDB_DB") or "assessment.db"


def connect(args, create=False):
    p = db_path(args)
    if not create and not os.path.exists(p):
        sys.exit(f"[fdb] no database at {p} -- run 'fdb init' first")
    con = sqlite3.connect(p)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


# ------------------------------------------------------------------ init

# Columns added after rev 1. CREATE TABLE IF NOT EXISTS cannot add a column to an
# existing table and views are dropped/recreated by the script, so only columns need
# an explicit migration step.
ADDED_COLUMNS = [
    (2, "ledger_bug", "verdict_raw", "TEXT"),
]


def cmd_init(args):
    con = connect(args, create=True)
    existing = os.path.exists(db_path(args)) and con.execute(
        "SELECT count(*) c FROM sqlite_master WHERE type='table' AND name='schema_rev'"
    ).fetchone()["c"] > 0
    prev = (con.execute("SELECT max(rev) AS r FROM schema_rev").fetchone()["r"]
            if existing else None)
    with open(SCHEMA) as fh:
        con.executescript(fh.read())
    added = []
    for rev, table, col, decl in ADDED_COLUMNS:
        cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
        if col not in cols:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            added.append(f"{table}.{col}")
    if prev is None:
        con.execute("INSERT INTO schema_rev(rev, applied_at, note) VALUES(?,?,?)",
                    (SCHEMA_REV, now(), f"initial schema, fdb {VERSION}"))
    elif prev < SCHEMA_REV:
        con.execute("INSERT INTO schema_rev(rev, applied_at, note) VALUES(?,?,?)",
                    (SCHEMA_REV, now(),
                     f"upgraded from rev {prev} by fdb {VERSION}: " +
                     (", ".join(added) if added else "views only")))
    con.commit()
    if prev is not None and prev < SCHEMA_REV:
        print(f"[fdb] upgraded rev {prev} -> {SCHEMA_REV}" +
              (f" (added {', '.join(added)})" if added else " (views rebuilt)"))
        if added:
            print("      re-run the importers to populate the new column(s)")
    print(f"[fdb] schema rev {SCHEMA_REV} ready at {db_path(args)}")
    return 0


# ------------------------------------------------------- generic upsert helpers

def _upsert(con, table, keys, row):
    """Insert or update `row` in `table`, matching on the `keys` columns.
    Returns (rowid, 'inserted'|'updated'|'unchanged')."""
    where = " AND ".join(f"{k} = ?" for k in keys)
    found = con.execute(f"SELECT * FROM {table} WHERE {where}",
                        [row[k] for k in keys]).fetchone()
    cols = [c for c in row if c not in keys]
    if found is None:
        allc = list(row)
        con.execute(f"INSERT INTO {table} ({','.join(allc)}) "
                    f"VALUES ({','.join('?' * len(allc))})", [row[c] for c in allc])
        return con.execute("SELECT last_insert_rowid() AS i").fetchone()["i"], "inserted"
    changed = {c: row[c] for c in cols
               if row[c] is not None and (c not in found.keys() or found[c] != row[c])}
    if not changed:
        return found["id"] if "id" in found.keys() else found[keys[0]], "unchanged"
    con.execute(f"UPDATE {table} SET {','.join(f'{c}=?' for c in changed)} WHERE {where}",
                list(changed.values()) + [row[k] for k in keys])
    return found["id"] if "id" in found.keys() else found[keys[0]], "updated"


def _lookup(con, table, col, val, what):
    if val is None:
        return None
    r = con.execute(f"SELECT id FROM {table} WHERE {col} = ?", (val,)).fetchone()
    if r is None:
        sys.exit(f"[fdb] {what} '{val}' not found -- define it before referencing it")
    return r["id"]


def _component_id(con, build_id, comp):
    """Resolve a component within a build by path or by name."""
    r = con.execute("SELECT id FROM component WHERE build_id = ? AND (path = ? OR name = ?)",
                    (build_id, comp, comp)).fetchone()
    if r is None:
        sys.exit(f"[fdb] component '{comp}' not found in that build")
    return r["id"]


def _build_id(con, target_slug, build):
    r = con.execute("SELECT b.id FROM build b JOIN target t ON t.id = b.target_id "
                    "WHERE t.slug = ? AND b.build = ?", (target_slug, build)).fetchone()
    if r is None:
        sys.exit(f"[fdb] build {target_slug}/{build} not found")
    return r["id"]


# ------------------------------------------------------------------ load (bulk)

SECTIONS = ["engagements", "targets", "builds", "components", "findings",
            "aliases", "affects", "locations", "evidence", "disclosures", "ledgers"]


def cmd_load(args):
    con = connect(args)
    with open(args.spec) as fh:
        spec = json.load(fh)
    unknown = [k for k in spec if k not in SECTIONS]
    if unknown:
        sys.exit(f"[fdb] unknown section(s) in spec: {unknown}\n       known: {SECTIONS}")
    tally = {}

    def bump(section, verb):
        tally.setdefault(section, {}).setdefault(verb, 0)
        tally[section][verb] += 1

    for e in spec.get("engagements", []):
        _, v = _upsert(con, "engagement", ["slug"], e); bump("engagements", v)

    for t in spec.get("targets", []):
        _, v = _upsert(con, "target", ["slug"], t); bump("targets", v)

    for b in spec.get("builds", []):
        b = dict(b)
        b["target_id"] = _lookup(con, "target", "slug", b.pop("target"), "target")
        _, v = _upsert(con, "build", ["target_id", "build"], b); bump("builds", v)

    for c in spec.get("components", []):
        c = dict(c)
        c["build_id"] = _build_id(con, c.pop("target"), c.pop("build"))
        _, v = _upsert(con, "component", ["build_id", "path"], c); bump("components", v)

    for f in spec.get("findings", []):
        f = dict(f)
        if "engagement" in f:
            f["engagement_id"] = _lookup(con, "engagement", "slug",
                                         f.pop("engagement"), "engagement")
        # stamp the timestamps ourselves only when the spec does not carry them,
        # and only when something actually changed -- otherwise a re-load looks
        # like an edit and the idempotency check is useless
        autostamp = "last_updated" not in f
        fid, v = _upsert(con, "finding", ["slug"], f)
        if v == "inserted" and "first_seen" not in f:
            con.execute("UPDATE finding SET first_seen = ? WHERE id = ?", (now(), fid))
        if autostamp and v != "unchanged":
            con.execute("UPDATE finding SET last_updated = ? WHERE id = ?", (now(), fid))
        bump("findings", v)

    for a in spec.get("aliases", []):
        a = dict(a)
        a["finding_id"] = _lookup(con, "finding", "slug", a.pop("finding"), "finding")
        _, v = _upsert(con, "finding_alias", ["alias", "namespace"], a); bump("aliases", v)

    for a in spec.get("affects", []):
        a = dict(a)
        fid = _lookup(con, "finding", "slug", a.pop("finding"), "finding")
        bid = _build_id(con, a.pop("target"), a.pop("build"))
        comp = a.pop("component", None)
        cid = _component_id(con, bid, comp) if comp else None
        a.update(finding_id=fid, build_id=bid, component_id=cid)
        # component_id NULL participates in the PK, so match it explicitly
        ex = con.execute("SELECT rowid FROM finding_affects WHERE finding_id=? AND "
                         "build_id=? AND component_id IS ?", (fid, bid, cid)).fetchone()
        if ex:
            cur = con.execute("SELECT * FROM finding_affects WHERE rowid = ?",
                              (ex["rowid"],)).fetchone()
            sets = {k: v for k, v in a.items()
                    if k not in ("finding_id", "build_id", "component_id")
                    and v is not None and cur[k] != v}
            if sets:
                con.execute(f"UPDATE finding_affects SET "
                            f"{','.join(f'{k}=?' for k in sets)} WHERE rowid=?",
                            list(sets.values()) + [ex["rowid"]])
                bump("affects", "updated")
            else:
                bump("affects", "unchanged")
        else:
            con.execute(f"INSERT INTO finding_affects ({','.join(a)}) "
                        f"VALUES ({','.join('?' * len(a))})", list(a.values()))
            bump("affects", "inserted")

    for l in spec.get("locations", []):
        l = dict(l)
        l["finding_id"] = _lookup(con, "finding", "slug", l.pop("finding"), "finding")
        _, v = _upsert(con, "finding_location", ["finding_id", "func_name"], l)
        bump("locations", v)

    for ev in spec.get("evidence", []):
        ev = dict(ev)
        ev["finding_id"] = _lookup(con, "finding", "slug", ev.pop("finding"), "finding")
        _, v = _upsert(con, "evidence", ["finding_id", "path"], ev); bump("evidence", v)

    for d in spec.get("disclosures", []):
        d = dict(d)
        d["finding_id"] = _lookup(con, "finding", "slug", d.pop("finding"), "finding")
        _, v = _upsert(con, "disclosure", ["finding_id"], d); bump("disclosures", v)

    for l in spec.get("ledgers", []):
        l = dict(l)
        target = l.pop("target", None)
        build = l.pop("build", None)
        comp = l.pop("component", None)
        if build and not target:
            sys.exit(f"[fdb] ledger {l.get('path')}: 'build' needs a 'target' to resolve against")
        if target:
            l["target_id"] = _lookup(con, "target", "slug", target, "target")
        if build:
            l["build_id"] = _build_id(con, target, build)
            if comp:
                l["component_id"] = _component_id(con, l["build_id"], comp)
        elif comp:
            sys.exit(f"[fdb] ledger {l.get('path')}: 'component' needs a 'build'")
        l["path"] = os.path.abspath(os.path.expanduser(l["path"]))
        _, v = _upsert(con, "ledger", ["path"], l); bump("ledgers", v)

    con.commit()
    for sec in SECTIONS:
        if sec in tally:
            print(f"  {sec:<13} " + "  ".join(f"{v} {k}" for k, v in sorted(tally[sec].items())))
    print(f"[fdb] loaded {args.spec}")
    return 0


# --------------------------------------------------------------- ledger imports

def cmd_register_ledger(args):
    con = connect(args)
    row = {"path": os.path.abspath(args.path), "kind": args.kind, "notes": args.notes,
           "last_synced": now()}
    if args.target:
        row["target_id"] = _lookup(con, "target", "slug", args.target, "target")
    if args.build:
        row["build_id"] = _build_id(con, args.target, args.build)
    lid, verb = _upsert(con, "ledger", ["path"], row)
    con.commit()
    print(f"[fdb] ledger {verb}: id={lid} {row['path']}")
    return 0


AUDIT_ROWCOUNT_TABLES = ["func", "edge", "review", "precondition", "bug", "audit"]

# Producer ledgers drift: the Stage-3 taxonomy is 'violable-bug'/'established-safe'/
# 'partial'/'uncertain', but per-module runs invented 'confirmed-violable'/
# 'confirmed-latent'/'gated', later passes prefixed and annotated them
# ('reverify:confirmed-violable[reachability]', 'stage4:demonstrated-live'), and the
# live-validation pass added its own tier ('live-gated'/'live-latent'/'live-refuted').
# Normalize on the way in and keep the producer's own label in verdict_raw --
# otherwise a cross-ledger funnel silently under-counts whichever spelling it missed.
VERDICT_MAP = {
    # proven on a running target
    "demonstrated": "demonstrated", "demonstrated-live": "demonstrated",
    # the bound is breakable from an attacker-reachable path
    "violable-bug": "violable", "confirmed-violable": "violable", "confirmed": "violable",
    "violable": "violable", "default-reachable-leak": "violable",
    # real, but off by configuration on a stock build
    "gated": "gated", "config-gated": "gated", "live-gated": "gated",
    # real, but the code path is not built/enabled on the builds in scope
    "confirmed-latent": "latent", "latent": "latent", "live-latent": "latent",
    # a concrete unsafe operation, reachability or liveness not yet proven
    "candidate": "candidate", "candidate-needs-poc": "candidate",
    "deepdive-needs-live-poc": "candidate",
    # the bound holds on some paths but not all
    "partial": "partial",
    # static analysis could not settle it -- NOT a refutation
    "uncertain": "uncertain", "has-uncertain": "uncertain",
    "uncertain-continue": "uncertain", "uncertain-external": "uncertain",
    # trace-state labels: the pass stopped without an answer. 'guest-entry' and
    # 'terminal-exhausted-*' mean "walked as far as static analysis goes and the
    # establishing check was never found" -- unresolved, not confirmed either way.
    "guest-entry": "uncertain",
    "terminal-exhausted-extsym": "uncertain", "terminal-exhausted-guest-entry": "uncertain",
    "re-complete-live-blocked": "uncertain",
    # the bound is enforced, or the path is unreachable
    "established-safe": "refuted", "all-established-safe": "refuted", "refuted": "refuted",
    "not-a-bug": "refuted", "deepdive-refuted": "refuted", "live-refuted": "refuted",
    "refuted-unreachable": "refuted",
}
# Strongest first: how sure are we this is a real, live bug?
VERDICT_RANK = ["demonstrated", "violable", "gated", "latent", "candidate",
                "partial", "uncertain", "refuted"]


def normalize_verdict(raw):
    """Producer verdict label -> the shared vocabulary. Returns None if unmappable."""
    if not raw:
        return None
    v = raw.strip().lower().split("[", 1)[0].strip()   # 'confirmed-violable[reachability]'
    if v in VERDICT_MAP:
        return VERDICT_MAP[v]
    if ":" not in v:
        return None
    # A colon is used two opposite ways. Pass prefixes put the verdict LAST
    # ('stage4:demonstrated-live'); free-text rationale puts it FIRST
    # ('refuted: known callers', 'partial: no guest path'). Try both ends.
    head, tail = v.split(":", 1)[0].strip(), v.rsplit(":", 1)[1].strip()
    return VERDICT_MAP.get(tail) or VERDICT_MAP.get(head)


def cmd_import_audit(args):
    """Promote a binary-audit ledger's bug/audit rows to thin ledger_bug pointers."""
    con = connect(args)
    src_path = os.path.abspath(args.path)
    lrow = con.execute("SELECT * FROM ledger WHERE path = ?", (src_path,)).fetchone()
    if lrow is None:
        sys.exit(f"[fdb] {src_path} is not registered -- run 'fdb register-ledger' first")
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row

    def has(table):
        return src.execute("SELECT count(*) c FROM sqlite_master WHERE type='table' "
                           "AND name=?", (table,)).fetchone()["c"] > 0

    counts = {t: src.execute(f"SELECT count(*) c FROM {t}").fetchone()["c"]
              for t in AUDIT_ROWCOUNT_TABLES if has(t)}

    def stamp():
        con.execute("UPDATE ledger SET row_counts = ?, last_synced = ? WHERE id = ?",
                    (json.dumps(counts), now(), lrow["id"]))
        con.commit()

    if not has("bug"):
        # a graph-only ledger (extract+score, no review pass) still has a useful
        # row-count snapshot -- record it and say so, rather than failing
        stamp()
        print(f"[fdb] {src_path}\n      counts {counts}\n"
              f"      no 'bug' table (graph-only ledger) -- row counts recorded, "
              f"nothing to promote")
        return 0

    # audit verdicts are keyed by function name, not by bug id, in every revision
    verdicts, unmapped = {}, {}
    if has("audit"):
        for a in src.execute("SELECT func_name, verdict FROM audit"):
            norm = normalize_verdict(a["verdict"])
            if norm is None and a["verdict"]:
                unmapped[a["verdict"]] = unmapped.get(a["verdict"], 0) + 1
            verdicts.setdefault(a["func_name"], []).append((norm, a["verdict"]))

    cols = {r[1] for r in src.execute("PRAGMA table_info(bug)")}
    ins = upd = 0
    for b in src.execute("SELECT rowid AS rid, * FROM bug"):
        v = verdicts.get(b["func_name"], [])
        # a function can carry several adjudications; the strongest one wins, so a
        # later 'established-safe' on one path cannot bury an earlier 'violable-bug'
        verdict = verdict_raw = None
        for pref in VERDICT_RANK:
            hit = next((x for x in v if x[0] == pref), None)
            if hit:
                verdict, verdict_raw = hit
                break
        if verdict is None and v:                    # only unmappable labels
            verdict_raw = v[0][1]
        row = {
            "ledger_id": lrow["id"], "src_rowid": b["rid"],
            "func_name": b["func_name"],
            "bug_class": b["bug_class"] if "bug_class" in cols else None,
            "confidence": b["confidence"] if "confidence" in cols else None,
            "status": b["status"] if "status" in cols else None,
            "verdict": verdict, "verdict_raw": verdict_raw,
            "impact": b["impact"] if "impact" in cols else None,
            "reachability": b["reachability"] if "reachability" in cols else None,
            "descr": (b["desc"] if "desc" in cols else None),
        }
        _, verb = _upsert(con, "ledger_bug", ["ledger_id", "src_rowid"], row)
        ins += verb == "inserted"
        upd += verb == "updated"
    stamp()
    print(f"[fdb] {src_path}\n      counts {counts}\n      ledger_bug: {ins} inserted, "
          f"{upd} updated")
    if unmapped:
        # loud on purpose: an unmapped label is a bug that will not show up in
        # v_funnel or v_orphans, which is the exact failure this store exists to stop
        print("      ** unmapped verdict label(s) -- extend VERDICT_MAP:")
        for lbl, n in sorted(unmapped.items(), key=lambda kv: -kv[1]):
            print(f"           {n:>4}x {lbl!r}")
    return 0


def cmd_import_sbom(args):
    """Register an SBOM KB and map its hosts to builds (link only; no row copy)."""
    con = connect(args)
    src_path = os.path.abspath(args.path)
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    tabs = {r["name"] for r in src.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    counts = {t: src.execute(f"SELECT count(*) c FROM {t}").fetchone()["c"]
              for t in ("host", "binary", "library", "package", "cve", "analysis")
              if t in tabs}
    row = {"path": src_path, "kind": "sbom", "row_counts": json.dumps(counts),
           "last_synced": now()}
    if args.target:
        row["target_id"] = _lookup(con, "target", "slug", args.target, "target")
    if args.build:
        row["build_id"] = _build_id(con, args.target, args.build)
    lid, verb = _upsert(con, "ledger", ["path"], row)
    con.commit()
    print(f"[fdb] sbom ledger {verb}: id={lid}\n      counts {counts}")

    # An SBOM KB records the hosts it was collected from, and those carry build
    # numbers -- so it can say whether the scope this DB knows about matches the
    # scope the KB was actually built from. Report, don't reconcile silently.
    if "host" not in tabs:
        return 0
    hcols = [r[1] for r in src.execute("PRAGMA table_info(host)")]
    idcol = next((c for c in ("alias", "name", "host", "hostname") if c in hcols), hcols[0])
    sel = ", ".join(c for c in (idcol, "build", "os_version", "role") if c in hcols)
    for h in src.execute(f"SELECT {sel} FROM host ORDER BY 1"):
        b = h["build"] if "build" in hcols else None
        if b is None:
            mark = "no build recorded"
        else:
            m = con.execute("SELECT t.slug FROM build bu JOIN target t ON t.id = bu.target_id "
                            "WHERE bu.build = ?", (str(b),)).fetchall()
            mark = ("-> " + ",".join(r["slug"] for r in m)) if m else "** no matching build row"
        extra = " ".join(str(h[c]) for c in ("os_version", "role") if c in hcols and h[c])
        print(f"      host {h[idcol]:<12} build {b or '-':<12} {extra:<28} {mark}")
    return 0


# ---------------------------------------------------------------------- queries

def cmd_resolve(args):
    con = connect(args)
    rows = con.execute(
        "SELECT alias, namespace, canonical_id, slug, title, status FROM v_alias "
        "WHERE alias = ? COLLATE NOCASE", (args.alias,)).fetchall()
    if not rows:
        r = con.execute("SELECT canonical_id, slug, title, status FROM finding "
                        "WHERE canonical_id = ? COLLATE NOCASE OR slug = ? COLLATE NOCASE",
                        (args.alias, args.alias)).fetchone()
        if not r:
            print(f"[fdb] '{args.alias}' is not a known signifier")
            return 1
        print(f"{r['canonical_id'] or '-'}  {r['slug']}\n  {r['title']}\n  status: {r['status']}")
        return 0
    for r in rows:
        print(f"{r['alias']} ({r['namespace']})  ->  {r['canonical_id'] or '-'}  {r['slug']}\n"
              f"  {r['title']}\n  status: {r['status']}")
    return 0


def cmd_stats(args):
    con = connect(args)
    print(f"db: {db_path(args)}")
    for t in ("engagement", "target", "build", "component", "finding", "finding_alias",
              "finding_affects", "evidence", "disclosure", "ledger", "ledger_bug"):
        n = con.execute(f"SELECT count(*) c FROM {t}").fetchone()["c"]
        print(f"  {t:<16} {n}")
    rows = con.execute("SELECT * FROM v_method_yield ORDER BY target, discovery_method").fetchall()
    if rows:
        print("\nyield by target x method:")
        print(f"  {'target':<14} {'method':<14} {'n':>3} {'demo':>5} {'conf':>5} {'hi/crit':>8}")
        for r in rows:
            print(f"  {r['target']:<14} {r['discovery_method']:<14} {r['findings']:>3} "
                  f"{r['demonstrated'] or 0:>5} {r['confirmed'] or 0:>5} {r['high_or_crit'] or 0:>8}")
    orph = con.execute("SELECT count(*) c FROM v_orphans").fetchone()["c"]
    if orph:
        print(f"\n  ** {orph} adjudicated-real ledger bug(s) with no finding and no "
              f"disposition -- see 'fdb query \"SELECT * FROM v_orphans\"'")
    return 0


def cmd_query(args):
    con = connect(args)
    sql = args.sql.strip()
    if not args.write and not sql.lower().startswith(("select", "with", "pragma", "explain")):
        sys.exit("[fdb] refusing a non-SELECT without --write")
    cur = con.execute(sql)
    rows = cur.fetchall()
    if args.json:
        print(json.dumps([dict(r) for r in rows], indent=2, default=str))
    elif rows:
        cols = rows[0].keys()
        w = {c: max(len(str(c)), max(len(str(r[c] if r[c] is not None else "")) for r in rows))
             for c in cols}
        w = {c: min(v, 60) for c, v in w.items()}
        print("  ".join(str(c)[:w[c]].ljust(w[c]) for c in cols))
        print("  ".join("-" * w[c] for c in cols))
        for r in rows:
            print("  ".join(str(r[c] if r[c] is not None else "")[:w[c]].ljust(w[c]) for c in cols))
        print(f"\n({len(rows)} rows)")
    else:
        print("(0 rows)")
    if args.write:
        con.commit()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fdb", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", help="database path (default $FDB_DB or ./assessment.db)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create/upgrade the schema").set_defaults(fn=cmd_init)

    p = sub.add_parser("load", help="idempotent bulk upsert from a JSON spec")
    p.add_argument("spec"); p.set_defaults(fn=cmd_load)

    p = sub.add_parser("register-ledger", help="register a producer DB")
    p.add_argument("--path", required=True)
    p.add_argument("--kind", required=True, choices=["audit", "sbom", "graph-only"])
    p.add_argument("--target"); p.add_argument("--build"); p.add_argument("--notes")
    p.set_defaults(fn=cmd_register_ledger)

    p = sub.add_parser("import-audit", help="promote an audit ledger's bugs as pointers")
    p.add_argument("path"); p.set_defaults(fn=cmd_import_audit)

    p = sub.add_parser("import-sbom", help="register an SBOM KB and map its hosts")
    p.add_argument("path"); p.add_argument("--target"); p.add_argument("--build")
    p.set_defaults(fn=cmd_import_sbom)

    p = sub.add_parser("resolve", help="legacy signifier -> canonical finding")
    p.add_argument("alias"); p.set_defaults(fn=cmd_resolve)

    sub.add_parser("stats", help="row counts, yield, orphans").set_defaults(fn=cmd_stats)

    p = sub.add_parser("query", help="raw SQL")
    p.add_argument("sql"); p.add_argument("--json", action="store_true")
    p.add_argument("--write", action="store_true", help="allow non-SELECT")
    p.set_defaults(fn=cmd_query)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
