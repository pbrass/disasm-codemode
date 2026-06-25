#!/usr/bin/env python3
"""extract.py — Pass 0 of the symbolicate pipeline: harvest per-function EVIDENCE into a sqlite DB.

Evidence (not metrics) is what lets you NAME a stripped function: the strings it references (esp. VMware
'Identifier: message' log prefixes), its call neighborhood (named callees/callers), and domain tags. This
runs three passes over the open BinaryView and writes rows to <db> from INSIDE Binary Ninja (the BN host is
local) — so a 40k-function evidence dump never hits the code-mode ~100 KB stdout cap.

  bn-sym-extract --bv-match i_vmx_full --db phil_notes/vmx-re/symdb.sqlite --profile <plugin>/skills/symbolicate/profiles/vmware.json

Tables (created here): func(addr,name,size) · edge(caller,callee,callee_name) · strref(func_addr,s,is_logpfx,pfx)
· domain(func_addr,tag,source). Counts (ncallers/ncallees/nstrings) are derived by SQL in determ/prep.
Idempotent per pass: each pass clears+rewrites its own table, so re-running re-harvests cleanly.
"""
import sys, os, json, argparse, sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm


SCHEMA = """
CREATE TABLE IF NOT EXISTS func(addr INTEGER PRIMARY KEY, name TEXT, size INTEGER);
CREATE TABLE IF NOT EXISTS edge(caller INTEGER, callee INTEGER, callee_name TEXT);
CREATE TABLE IF NOT EXISTS strref(func_addr INTEGER, s TEXT, is_logpfx INTEGER, pfx TEXT);
CREATE TABLE IF NOT EXISTS domain(func_addr INTEGER, tag TEXT, source TEXT);
CREATE INDEX IF NOT EXISTS ix_edge_caller ON edge(caller);
CREATE INDEX IF NOT EXISTS ix_edge_callee ON edge(callee);
CREATE INDEX IF NOT EXISTS ix_strref_fa ON strref(func_addr);
CREATE INDEX IF NOT EXISTS ix_domain_fa ON domain(func_addr);
"""

BODY_FUNCS = r'''
import sqlite3
_c = sqlite3.connect(_db, timeout=120)
_c.execute("DELETE FROM func")
_rows = []; _n = 0
for _f in _bv.functions:
    _rows.append((_f.start, _f.name, _f.total_bytes)); _n += 1
    if len(_rows) >= 4000:
        _c.executemany("INSERT OR REPLACE INTO func(addr,name,size) VALUES(?,?,?)", _rows); _rows = []
if _rows:
    _c.executemany("INSERT OR REPLACE INTO func(addr,name,size) VALUES(?,?,?)", _rows)
_c.commit(); _c.close()
print("[extract] funcs=%d" % _n)
'''

BODY_EDGE = r'''
import sqlite3
_c = sqlite3.connect(_db, timeout=300)
_c.execute("DELETE FROM edge")
_rows = []; _n = 0
for _f in _bv.functions:
    for _ce in _f.callees:
        _rows.append((_f.start, _ce.start, _ce.name)); _n += 1
        if len(_rows) >= 6000:
            _c.executemany("INSERT INTO edge(caller,callee,callee_name) VALUES(?,?,?)", _rows); _rows = []
if _rows:
    _c.executemany("INSERT INTO edge(caller,callee,callee_name) VALUES(?,?,?)", _rows)
_c.commit(); _c.close()
print("[extract] edges=%d" % _n)
'''

BODY_STR = r'''
import sqlite3, re as _re
_c = sqlite3.connect(_db, timeout=300)
_c.execute("DELETE FROM strref")
_c.execute("DELETE FROM domain")
_rows = []; _drows = []; _n = 0; _np = 0
for _s in _bv.strings:
    _v = _s.value
    if len(_v) < 4:
        continue
    _m = _re.match(_logpfx, _v)
    _pfx = _m.group(1) if _m else None
    # drop BN auto-string NOISE: x86 prologue bytes ("AWAVAUATUSH" = push r15;r14;... ), "HcC8H", "ATUSL".
    # a REAL string has a space, or >=3 lowercase letters, or path/key/format punctuation — or is a log prefix.
    _low = 0
    for _ch in _v:
        if _ch.islower():
            _low += 1
    _realish = (" " in _v) or (_low >= 3) or ("." in _v) or ("/" in _v) or ("%" in _v)
    if not _realish and not _pfx:
        continue
    _fset = set()
    for _r in _bv.get_code_refs(_s.start):
        if _r.function is not None:
            _fset.add(_r.function.start)
    for _fa in _fset:
        _rows.append((_fa, _v[:500], 1 if _pfx else 0, _pfx)); _n += 1
        if _pfx:
            _np += 1
            for _tag in _domain_tags:
                if _pfx == _tag or _pfx.startswith(_tag):
                    _drows.append((_fa, _tag, "logpfx")); break
    if len(_rows) >= 6000:
        _c.executemany("INSERT INTO strref(func_addr,s,is_logpfx,pfx) VALUES(?,?,?,?)", _rows); _rows = []
    if len(_drows) >= 6000:
        _c.executemany("INSERT INTO domain(func_addr,tag,source) VALUES(?,?,?)", _drows); _drows = []
if _rows:
    _c.executemany("INSERT INTO strref(func_addr,s,is_logpfx,pfx) VALUES(?,?,?,?)", _rows)
if _drows:
    _c.executemany("INSERT INTO domain(func_addr,tag,source) VALUES(?,?,?)", _drows)
_c.commit(); _c.close()
print("[extract] strrefs=%d logpfx=%d" % (_n, _np))
'''


def main():
    ap = argparse.ArgumentParser(description="Harvest per-function naming evidence into a sqlite DB (BN-side writes).")
    bncm.add_target_args(ap)
    ap.add_argument("--db", required=True, help="path to the evidence sqlite DB to (re)build")
    ap.add_argument("--profile", required=True, help="path to a symbolicate profile JSON (log_prefix_re, domain_tags)")
    ap.add_argument("--pass", dest="which", choices=["funcs", "edges", "strings", "all"], default="all")
    args = ap.parse_args()
    if not os.path.exists(args.profile):
        bncm.die("profile not found: %s" % args.profile)
    prof = json.load(open(args.profile))
    db = os.path.abspath(args.db)
    os.makedirs(os.path.dirname(db), exist_ok=True)
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    con.commit(); con.close()

    base = bncm.target_params(args)
    if args.which in ("funcs", "all"):
        bncm.run(BODY_FUNCS, _db=db, **base)
    if args.which in ("edges", "all"):
        bncm.run(BODY_EDGE, _db=db, **base)
    if args.which in ("strings", "all"):
        bncm.run(BODY_STR, _db=db, _logpfx=prof["log_prefix_re"], _domain_tags=list(prof.get("domain_tags") or []), **base)


if __name__ == "__main__":
    main()
