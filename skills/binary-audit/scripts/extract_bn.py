#!/usr/bin/env python3
"""extract_bn.py - BN-backed binary-audit extractor for stripped/recovered binaries.

Writes the same kreview.db schema as extract.py, but harvests functions, names,
ranges, direct edges, and structural metrics from an open Binary Ninja view.
This is the right path for a stripped binary whose useful names live in the
.bndb rather than the ELF symbol table.

  bn-audit-extract-bn --bv-match i_vmx_full --db kaudit/kreview.db --profile vmx-userworld.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm


SCHEMA = """
DROP TABLE IF EXISTS func;
DROP TABLE IF EXISTS edge;
DROP TABLE IF EXISTS func_meta;
CREATE TABLE func(
  addr INTEGER PRIMARY KEY,
  name TEXT,
  size INT,
  n_insns INT,
  cc INT,
  loops INT,
  n_mem INT,
  n_memidx INT,
  n_arith INT,
  n_call INT,
  n_callind INT,
  sink_calls INT,
  state_calls INT,
  parse_off INT
);
CREATE TABLE edge(caller INTEGER, callee INTEGER);
CREATE TABLE func_meta(
  addr INTEGER PRIMARY KEY,
  end_addr INTEGER,
  source TEXT,
  is_auto_name INTEGER,
  has_user_name INTEGER,
  indirect_calls INT,
  callees INT,
  callers INT
);
CREATE INDEX IF NOT EXISTS ix_edge_callee ON edge(callee);
CREATE INDEX IF NOT EXISTS ix_edge_caller ON edge(caller);
CREATE INDEX IF NOT EXISTS ix_func_name ON func(name);
"""


BODY = r'''
import json as _json, re as _re, sqlite3 as _sqlite3
_arith = set("add sub imul mul shl sal shr sar and or xor lea inc dec adc sbb neg not rol ror".split())

def _auto_name(_name):
    if not _name:
        return True
    return _name.startswith("sub_") or _name.startswith("j_sub_") or _name.startswith("nullsub_")

def _insn_rows(_f):
    _rows = []
    try:
        for _bb in _f.basic_blocks:
            for _dt in _bb.get_disassembly_text():
                _rows.append((_dt.address, str(_dt)))
    except Exception:
        pass
    return _rows

def _metrics(_f, _sink_regex=_sink_regex, _state_regex=_state_regex, _arith=_arith, _re=_re, _insn_rows=_insn_rows):
    _bbs = []
    try:
        _bbs = list(_f.basic_blocks)
    except Exception:
        _bbs = []
    _N = len(_bbs)
    _E = 0
    _loops = 0
    for _bb in _bbs:
        try:
            _outs = list(_bb.outgoing_edges)
        except Exception:
            _outs = []
        _E += len(_outs)
        for _edge in _outs:
            try:
                if _edge.target.start <= _bb.start:
                    _loops += 1
            except Exception:
                pass
    _cc = max(1, _E - _N + 2) if _N else 1

    _n_mem = 0
    _n_memidx = 0
    _n_arith = 0
    _n_call = 0
    _n_callind = 0
    _parse = set()
    _insns = _insn_rows(_f)
    for _addr, _txt in _insns:
        _s = _txt.strip()
        _mn = _s.split(None, 1)[0].lower() if _s else ""
        if _mn in _arith:
            _n_arith += 1
        if "[" in _s and "]" in _s:
            _n_mem += 1
            _mems = _re.findall(r"\[([^\]]+)\]", _s)
            for _m in _mems:
                if "*" in _m or _re.search(r"\b(r[a-z0-9]+|e[a-z0-9]+|[abcd]x|[sd]i|[bs]p)\s*\+", _m, _re.I):
                    _n_memidx += 1
                    break
                _dm = _re.search(r"(?:\+|-)\s*0x([0-9a-f]+)", _m, _re.I)
                if _dm:
                    try:
                        _d = int(_dm.group(1), 16)
                        if 0 < _d < 0x4000:
                            _parse.add(_d)
                    except Exception:
                        pass
        if _mn == "call":
            _n_call += 1
            _op = _s.split(None, 1)[1] if len(_s.split(None, 1)) > 1 else ""
            if ("[" in _op and "]" in _op) or _op.startswith("rax") or _op.startswith("rcx") or _op.startswith("rdx") or _op.startswith("r8") or _op.startswith("r9"):
                _n_callind += 1

    _sink = 0
    _state = 0
    _callees = []
    try:
        _callees = list(_f.callees)
    except Exception:
        _callees = []
    for _ce in _callees:
        _nm = getattr(_ce, "name", "") or ""
        if _re.search(_sink_regex, _nm, _re.I):
            _sink += 1
        if _re.search(_state_regex, _nm, _re.I):
            _state += 1
    if _n_call < len(_callees):
        _n_call = len(_callees)
    return (len(_insns), _cc, _loops, _n_mem, _n_memidx, _n_arith, _n_call, _n_callind, _sink, _state, len(_parse), len(_callees))

_c = _sqlite3.connect(_db, timeout=300)
_c.executescript(_schema)
_rows = []
_meta = []
_edges = []
_n = 0
_errs = 0
for _f in _bv.functions:
    try:
        _start = int(_f.start)
        _name = _f.name or ("sub_%x" % _start)
        try:
            _size = int(_f.total_bytes)
        except Exception:
            _size = 0
        try:
            _end = int(_f.highest_address)
        except Exception:
            _end = _start + _size
        _m = _metrics(_f)
        _rows.append((_start, _name, _size) + _m[:11])
        _callees = []
        try:
            _callees = list(_f.callees)
        except Exception:
            _callees = []
        for _ce in _callees:
            _edges.append((_start, int(_ce.start)))
        _callers = 0
        try:
            _callers = len(list(_f.callers))
        except Exception:
            _callers = 0
        _meta.append((_start, _end, "binary-ninja", 1 if _auto_name(_name) else 0, 0 if _auto_name(_name) else 1, _m[7], _m[11], _callers))
        _n += 1
        if len(_rows) >= 1000:
            _c.executemany("INSERT OR REPLACE INTO func VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", _rows); _rows = []
            _c.executemany("INSERT OR REPLACE INTO func_meta VALUES(?,?,?,?,?,?,?,?)", _meta); _meta = []
        if len(_edges) >= 6000:
            _c.executemany("INSERT INTO edge VALUES(?,?)", _edges); _edges = []
    except Exception:
        _errs += 1
if _rows:
    _c.executemany("INSERT OR REPLACE INTO func VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", _rows)
if _meta:
    _c.executemany("INSERT OR REPLACE INTO func_meta VALUES(?,?,?,?,?,?,?,?)", _meta)
if _edges:
    _c.executemany("INSERT INTO edge VALUES(?,?)", _edges)
_c.commit()
_ec = _c.execute("SELECT COUNT(*) FROM edge").fetchone()[0]
_c.close()
print("[audit-extract-bn] functions=%d edges=%d errors=%d" % (_n, _ec, _errs))
'''


def main():
    ap = argparse.ArgumentParser(description="Extract binary-audit metrics from an open Binary Ninja view.")
    bncm.add_target_args(ap)
    ap.add_argument("--db", required=True, help="kreview.db path to rebuild")
    ap.add_argument("--profile", help="profile JSON with sink_regex/state_regex")
    args = ap.parse_args()

    prof = {}
    if args.profile:
        prof = json.load(open(args.profile))
    sink = prof.get("sink_regex", r"(memcpy|memmove|memset|bcopy|strcpy|strncpy|strcat|strlcpy|sprintf|snprintf|malloc|calloc|realloc|free|Alloc|Copy|Clone)")
    state = prof.get("state_regex", r"(Free|Release|Destroy|Close|Unref|Ref|RefCount|Lock|Unlock|Mutex|Sema|Atomic|Put|Get)")
    db = os.path.abspath(args.db)
    os.makedirs(os.path.dirname(db), exist_ok=True)
    bncm.run(BODY, _db=db, _schema=SCHEMA, _sink_regex=sink, _state_regex=state, **bncm.target_params(args))


if __name__ == "__main__":
    main()
