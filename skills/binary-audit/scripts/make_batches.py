#!/usr/bin/env python3
"""make_batches.py - write ranked Stage-2 review batches from kreview.db.

  bn-audit-make-batches --db kaudit/kreview.db --out kaudit/batches.json --batch-size 25 --limit 250
"""
import argparse
import json
import os
import sqlite3
from pathlib import Path


def _has(cur, table, col):
    return col in [r[1] for r in cur.execute("PRAGMA table_info(%s)" % table)]


def main():
    ap = argparse.ArgumentParser(description="Create binary-audit review batches ordered by score.")
    ap.add_argument("--db", default=None, help="kreview.db path; defaults to $KAUDIT_ROOT/kreview.db")
    ap.add_argument("--out", default=None, help="batches JSON path; defaults to $KAUDIT_ROOT/batches.json")
    ap.add_argument("--batch-size", type=int, default=25)
    ap.add_argument("--limit", type=int, default=250, help="max functions to batch; 0 means all")
    ap.add_argument("--min-score", type=float, default=None)
    ap.add_argument("--include-auto", action="store_true", help="include sub_* auto names")
    ap.add_argument("--skip-reviewed", action="store_true", help="exclude functions already in review")
    args = ap.parse_args()

    root = os.environ.get("KAUDIT_ROOT", ".")
    dbpath = args.db or os.path.join(root, "kreview.db")
    outpath = Path(args.out or os.path.join(root, "batches.json"))
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be positive")

    con = sqlite3.connect(dbpath)
    cur = con.cursor()
    where = []
    params = []
    if not args.include_auto:
        where.append("name NOT LIKE 'sub_%'")
        where.append("name NOT LIKE 'j_sub_%'")
        where.append("name NOT LIKE 'nullsub_%'")
    if args.min_score is not None:
        where.append("score >= ?")
        params.append(args.min_score)
    if args.skip_reviewed:
        cur.execute("CREATE TABLE IF NOT EXISTS review(addr INTEGER PRIMARY KEY, name TEXT, reviewed_at TEXT, reviewer TEXT, verdict TEXT, notes TEXT)")
        where.append("addr NOT IN (SELECT addr FROM review WHERE addr IS NOT NULL)")
    sql = "SELECT name, score FROM func"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY score DESC, name"
    if args.limit and args.limit > 0:
        sql += " LIMIT ?"
        params.append(args.limit)
    names = [r[0] for r in cur.execute(sql, params).fetchall()]
    batches = [names[i:i + args.batch_size] for i in range(0, len(names), args.batch_size)]
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(json.dumps(batches, indent=2) + "\n")

    total = cur.execute("SELECT COUNT(*) FROM func").fetchone()[0]
    scored = cur.execute("SELECT COUNT(*) FROM func WHERE score IS NOT NULL").fetchone()[0] if _has(cur, "func", "score") else 0
    print("[make-batches] wrote %s" % outpath)
    print("[make-batches] selected=%d batches=%d batch_size=%d funcs=%d scored=%d" % (
        len(names), len(batches), args.batch_size, total, scored))
    if names:
        print("[make-batches] first=%s last=%s" % (names[0], names[-1]))
    con.close()


if __name__ == "__main__":
    main()
