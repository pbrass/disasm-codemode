#!/usr/bin/env python3
"""prep_functions_bn.py - extract arbitrary BN functions for follow-up audit.

Use this for decider/follow-up work when the next functions are named by a
phase-2 `uncertain` result rather than by ranked batches.

Examples:
  bn-audit-prep-functions-bn --bv-match i_vmx_full --root kaudit UsbDev_AllocURB Checkpoint_Restore_3
  bn-audit-prep-functions-bn --bv-match i_vmx_full --addr 0xb07ef0 --addr 0x699ea0
"""
import argparse
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

_SD = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm


BODY = r'''
import json as _json, sqlite3 as _sqlite3
_items = _json.loads(_items_json)
_max_hlil = int(_max_hlil)
_max_asm = int(_max_asm)
_c = _sqlite3.connect(_db, timeout=180)
_c.execute("CREATE TABLE IF NOT EXISTS audit_text(addr INTEGER PRIMARY KEY, hlil TEXT, asm TEXT)")
_rows = []
_missing = []
for _it in _items:
    _a = int(_it["addr"])
    _f = _bv.get_function_at(_a)
    if _f is None:
        _missing.append(_it.get("name") or ("0x%x" % _a))
        continue
    try:
        _hlil = str(_f.hlil)
    except Exception:
        _hlil = ""
    _alines = []
    try:
        for _bb in _f.basic_blocks:
            for _dt in _bb.get_disassembly_text():
                if len(_alines) >= _max_asm:
                    break
                _alines.append("%08x  %s" % (_dt.address, str(_dt)))
            if len(_alines) >= _max_asm:
                break
    except Exception:
        pass
    _rows.append((_a, _hlil[:_max_hlil], "\n".join(_alines)))
_c.executemany("INSERT OR REPLACE INTO audit_text(addr,hlil,asm) VALUES(?,?,?)", _rows)
_c.commit(); _c.close()
print("[prep-functions-bn] extracted text for %d/%d functions" % (len(_rows), len(_items)))
if _missing:
    print("[prep-functions-bn] missing: %s" % ", ".join(_missing[:20]))
'''


def _safe_name(name, addr):
    safe = re.sub(r"[^A-Za-z0-9_.+-]+", "_", name or "func").strip("._")
    if not safe:
        safe = "func"
    return "%016x_%s" % (addr, safe[:150])


def _parse_addr(s):
    return int(s, 0)


def _resolve(cur, names, addrs):
    items = {}
    missing = []
    for name in names:
        row = cur.execute("SELECT addr,name FROM func WHERE name=?", (name,)).fetchone()
        if not row:
            rows = cur.execute("SELECT addr,name FROM func WHERE name LIKE ? ORDER BY score DESC LIMIT 5",
                               ("%" + name + "%",)).fetchall()
            if len(rows) == 1:
                row = rows[0]
            else:
                missing.append(name)
                continue
        items[int(row[0])] = {"addr": int(row[0]), "name": row[1]}
    for addr_s in addrs:
        addr = _parse_addr(addr_s)
        row = cur.execute("SELECT addr,name FROM func WHERE addr=?", (addr,)).fetchone()
        if not row:
            row = cur.execute("SELECT addr,name FROM func WHERE addr<=? AND addr+size>?",
                              (addr, addr)).fetchone()
        if not row:
            missing.append(addr_s)
            continue
        items[int(row[0])] = {"addr": int(row[0]), "name": row[1]}
    return list(items.values()), missing


def main():
    ap = argparse.ArgumentParser(description="Extract arbitrary functions from an open BNDB into audit hlil/asm files.")
    bncm.add_target_args(ap)
    ap.add_argument("names", nargs="*", help="function names to extract")
    ap.add_argument("--addr", action="append", default=[], help="function start or contained address, hex or decimal")
    ap.add_argument("--root", default=os.environ.get("KAUDIT_ROOT", "."))
    ap.add_argument("--db", default=None, help="kreview.db path; defaults to <root>/kreview.db")
    ap.add_argument("--out", default=None, help="manifest path; defaults to <root>/followup-functions.json")
    ap.add_argument("--max-hlil", type=int, default=90000)
    ap.add_argument("--max-asm", type=int, default=8000)
    args = ap.parse_args()

    if not args.names and not args.addr:
        raise SystemExit("give at least one function name or --addr")
    root = Path(args.root)
    dbpath = Path(args.db or (root / "kreview.db")).resolve()
    outpath = Path(args.out or (root / "followup-functions.json"))
    con = sqlite3.connect(str(dbpath))
    cur = con.cursor()
    items, missing = _resolve(cur, args.names, args.addr)
    for m in missing:
        print("  MISSING %s" % m)
    if not items:
        raise SystemExit("no functions resolved")

    bncm.run(BODY, _db=str(dbpath), _items_json=json.dumps(items),
             _max_hlil=str(args.max_hlil), _max_asm=str(args.max_asm),
             **bncm.target_params(args))

    (root / "hlil").mkdir(parents=True, exist_ok=True)
    (root / "asm").mkdir(parents=True, exist_ok=True)
    manifest = []
    for item in items:
        row = cur.execute("SELECT hlil, asm FROM audit_text WHERE addr=?", (item["addr"],)).fetchone()
        if not row:
            print("  TEXT-MISSING %s" % item["name"])
            continue
        stem = _safe_name(item["name"], item["addr"])
        hl_path = root / "hlil" / ("%s.hlil.c" % stem)
        asm_path = root / "asm" / ("%s.asm" % stem)
        hl_path.write_text(row[0] or "")
        asm_path.write_text(row[1] or "")
        manifest.append({
            "name": item["name"],
            "addr": "0x%x" % item["addr"],
            "hlil": str(hl_path),
            "asm": str(asm_path),
        })
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(json.dumps(manifest, indent=2) + "\n")
    con.close()
    print("[prep-functions-bn] wrote %d entries -> %s" % (len(manifest), outpath.resolve()))
    for entry in manifest:
        print("  {addr} {name}".format(**entry))


if __name__ == "__main__":
    main()
