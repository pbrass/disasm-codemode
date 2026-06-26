#!/usr/bin/env python3
"""make_phase2_batches.py - build Stage-3 caller-audit batches from kreview.db.

Default mode batches functions with open suspected bugs. With
--include-preconditions it also includes functions that have open caller-owned
or unguaranteed preconditions but no suspected bug record, which is useful when
tracing the full contract surface.
"""
import argparse
import json
import os
import sqlite3
from pathlib import Path


def _table_exists(cur, name):
    return cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def main():
    ap = argparse.ArgumentParser(description="Create phase2-batches.json from the review ledger.")
    ap.add_argument("--db", default=None, help="kreview.db path; defaults to $KAUDIT_ROOT/kreview.db")
    ap.add_argument("--out", default=None, help="output JSON path; defaults to $KAUDIT_ROOT/phase2-batches.json")
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0, help="max functions to batch; 0 means all")
    ap.add_argument("--include-preconditions", action="store_true",
                    help="also batch functions with open caller/unguaranteed preconditions and no bug")
    args = ap.parse_args()

    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be positive")

    root = os.environ.get("KAUDIT_ROOT", ".")
    dbpath = args.db or os.path.join(root, "kreview.db")
    outpath = Path(args.out or os.path.join(root, "phase2-batches.json"))
    con = sqlite3.connect(dbpath)
    cur = con.cursor()

    if not _table_exists(cur, "bug"):
        names = []
    else:
        sql = """
            SELECT b.func_name, MAX(COALESCE(f.score,0)) AS s,
                   MAX(CASE b.confidence WHEN 'high' THEN 3 WHEN 'med' THEN 2 ELSE 1 END) AS c
            FROM bug b LEFT JOIN func f ON f.addr=b.func_addr
            WHERE COALESCE(b.status,'open')='open'
            GROUP BY b.func_name
        """
        names = [r[0] for r in cur.execute(sql).fetchall() if r[0]]

    if args.include_preconditions and _table_exists(cur, "precondition"):
        rows = cur.execute("""
            SELECT p.func_name, MAX(COALESCE(f.score,0)) AS s
            FROM precondition p LEFT JOIN func f ON f.addr=p.func_addr
            WHERE COALESCE(p.status,'open')='open'
              AND p.klass IN ('caller','unguaranteed')
            GROUP BY p.func_name
            ORDER BY s DESC, p.func_name
        """).fetchall()
        seen = set(names)
        names.extend(r[0] for r in rows if r[0] and r[0] not in seen)

    order = {name: i for i, name in enumerate(names)}
    scored = []
    for nm in names:
        r = cur.execute("SELECT COALESCE(score,0) FROM func WHERE name=?", (nm,)).fetchone()
        scored.append((float(r[0]) if r else 0.0, order[nm], nm))
    names = [nm for _s, _i, nm in sorted(scored, key=lambda x: (-x[0], x[1]))]
    if args.limit and args.limit > 0:
        names = names[:args.limit]

    batches = [names[i:i + args.batch_size] for i in range(0, len(names), args.batch_size)]
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(json.dumps(batches, indent=2) + "\n")
    print("[make-phase2-batches] wrote %s" % outpath)
    print("[make-phase2-batches] selected=%d batches=%d batch_size=%d" % (
        len(names), len(batches), args.batch_size))
    if names:
        print("[make-phase2-batches] first=%s last=%s" % (names[0], names[-1]))
    con.close()


if __name__ == "__main__":
    main()
