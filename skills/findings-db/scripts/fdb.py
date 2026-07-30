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
SCHEMA_REV = 1
VERSION = "0.1.0"


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

def cmd_init(args):
    con = connect(args, create=True)
    with open(SCHEMA) as fh:
        con.executescript(fh.read())
    cur = con.execute("SELECT max(rev) AS r FROM schema_rev").fetchone()
    if cur["r"] is None:
        con.execute("INSERT INTO schema_rev(rev, applied_at, note) VALUES(?,?,?)",
                    (SCHEMA_REV, now(), f"initial schema, fdb {VERSION}"))
    con.commit()
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
        cid = None
        if comp:
            r = con.execute("SELECT id FROM component WHERE build_id = ? AND (path = ? "
                            "OR name = ?)", (bid, comp, comp)).fetchone()
            if r is None:
                sys.exit(f"[fdb] component '{comp}' not found in that build")
            cid = r["id"]
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
        if "target" in l:
            l["target_id"] = _lookup(con, "target", "slug", l.pop("target"), "target")
        if "build" in l:
            tgt = con.execute("SELECT slug FROM target WHERE id=?",
                              (l.get("target_id"),)).fetchone()
            l["build_id"] = _build_id(con, tgt["slug"], l.pop("build")) if tgt else None
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
    if not has("bug"):
        sys.exit(f"[fdb] {src_path} has no 'bug' table (graph-only ledger?) -- "
                 f"registered with counts only")

    # audit verdicts are keyed by function name, not by bug id, in every revision
    verdicts = {}
    if has("audit"):
        for a in src.execute("SELECT func_name, verdict, confidence FROM audit"):
            verdicts.setdefault(a["func_name"], []).append(a)

    cols = {r[1] for r in src.execute("PRAGMA table_info(bug)")}
    ins = upd = 0
    for b in src.execute("SELECT rowid AS rid, * FROM bug"):
        v = verdicts.get(b["func_name"], [])
        # a function can have several adjudications; the strongest one wins
        verdict = None
        for pref in ("violable-bug", "partial", "uncertain", "established-safe"):
            if any(x["verdict"] == pref for x in v):
                verdict = pref
                break
        row = {
            "ledger_id": lrow["id"], "src_rowid": b["rid"],
            "func_name": b["func_name"],
            "bug_class": b["bug_class"] if "bug_class" in cols else None,
            "confidence": b["confidence"] if "confidence" in cols else None,
            "status": b["status"] if "status" in cols else None,
            "verdict": verdict,
            "impact": b["impact"] if "impact" in cols else None,
            "reachability": b["reachability"] if "reachability" in cols else None,
            "descr": (b["desc"] if "desc" in cols else None),
        }
        _, verb = _upsert(con, "ledger_bug", ["ledger_id", "src_rowid"], row)
        ins += verb == "inserted"
        upd += verb == "updated"
    con.execute("UPDATE ledger SET row_counts = ?, last_synced = ? WHERE id = ?",
                (json.dumps(counts), now(), lrow["id"]))
    con.commit()
    print(f"[fdb] {src_path}\n      counts {counts}\n      ledger_bug: {ins} inserted, "
          f"{upd} updated")
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
    hosts = [r[0] for r in src.execute("SELECT DISTINCT name FROM host")] if "host" in tabs else []
    print(f"[fdb] sbom ledger {verb}: id={lid}\n      counts {counts}\n      hosts {hosts}")
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
