#!/usr/bin/env python3
"""prep_phase2_bn.py N - prepare Stage-3 caller-audit tasks using Binary Ninja.

This is the stripped/BNDB-safe sibling of prep_phase2.py. It reads
$KAUDIT_ROOT/phase2-batches.json, gathers open bugs + caller-owned
preconditions + top direct callers, extracts HLIL/asm for all consumers and
lynchpins through the open BN view, and emits phase2-wf-bN.js.
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
for _it in _items:
    _a = int(_it["addr"])
    _f = _bv.get_function_at(_a)
    if _f is None:
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
print("[prep-phase2-bn] extracted text for %d/%d functions" % (len(_rows), len(_items)))
'''


def _safe_name(name, addr):
    safe = re.sub(r"[^A-Za-z0-9_.+-]+", "_", name or "func").strip("._")
    if not safe:
        safe = "func"
    return ("%016x_%s" % (addr, safe[:150]))


def _func_for_name(cur, name):
    return cur.execute("SELECT addr,name FROM func WHERE name=? ORDER BY score DESC LIMIT 1", (name,)).fetchone()


def _ensure_text(cur, root, item):
    row = cur.execute("SELECT hlil, asm FROM audit_text WHERE addr=?", (item["addr"],)).fetchone()
    if not row:
        return None
    stem = _safe_name(item["name"], item["addr"])
    hl_path = root / "hlil" / ("%s.hlil.c" % stem)
    asm_path = root / "asm" / ("%s.asm" % stem)
    hl_path.write_text(row[0] or "")
    asm_path.write_text(row[1] or "")
    return {"name": item["name"], "hlil": str(hl_path), "asm": str(asm_path)}


def main():
    ap = argparse.ArgumentParser(description="Prepare phase-2 caller-audit tasks using BN for HLIL and asm.")
    bncm.add_target_args(ap)
    ap.add_argument("batch", type=int, help="1-based batch number from $KAUDIT_ROOT/phase2-batches.json")
    ap.add_argument("--root", default=os.environ.get("KAUDIT_ROOT", "."))
    ap.add_argument("--db", default=None, help="kreview.db path; defaults to <root>/kreview.db")
    ap.add_argument("--max-callers", type=int, default=3)
    ap.add_argument("--max-hlil", type=int, default=70000)
    ap.add_argument("--max-asm", type=int, default=5000)
    args = ap.parse_args()

    root = Path(args.root)
    dbpath = Path(args.db or (root / "kreview.db")).resolve()
    batches = json.loads((root / "phase2-batches.json").read_text())
    if args.batch < 1 or args.batch > len(batches):
        raise SystemExit("batch %d out of range 1..%d" % (args.batch, len(batches)))
    names = batches[args.batch - 1]

    con = sqlite3.connect(str(dbpath))
    cur = con.cursor()
    items = {}
    task_specs = []
    for fn in names:
        frow = _func_for_name(cur, fn)
        if not frow:
            print("  MISSING %s" % fn)
            continue
        addr, canon = int(frow[0]), frow[1]
        items[addr] = {"addr": addr, "name": canon}
        bugs = cur.execute(
            "SELECT desc,why,location,confidence,severity FROM bug WHERE func_addr=? AND COALESCE(status,'open')='open'",
            (addr,)).fetchall()
        preconds = cur.execute(
            """SELECT text,kind,attack_note FROM precondition
               WHERE func_addr=? AND klass IN ('caller','unguaranteed')
                 AND COALESCE(status,'open')='open'""",
            (addr,)).fetchall()
        callers = cur.execute(
            """SELECT cf.addr, cf.name FROM edge e JOIN func cf ON cf.addr=e.caller
               WHERE e.callee=? GROUP BY cf.addr,cf.name
               ORDER BY MAX(COALESCE(cf.score,0)) DESC LIMIT ?""",
            (addr, args.max_callers)).fetchall()
        for ca, cn in callers:
            items[int(ca)] = {"addr": int(ca), "name": cn}
        task_specs.append((addr, canon, bugs, preconds, [(int(ca), cn) for ca, cn in callers]))

    (root / "hlil").mkdir(parents=True, exist_ok=True)
    (root / "asm").mkdir(parents=True, exist_ok=True)
    if items:
        bncm.run(BODY, _db=str(dbpath), _items_json=json.dumps(list(items.values())),
                 _max_hlil=str(args.max_hlil), _max_asm=str(args.max_asm),
                 **bncm.target_params(args))

    tasks = []
    for addr, fn, bugs, preconds, callers in task_specs:
        cons = _ensure_text(cur, root, {"addr": addr, "name": fn})
        if not cons:
            print("  TEXT-MISSING %s" % fn)
            continue
        lyn = []
        for ca, cn in callers:
            txt = _ensure_text(cur, root, {"addr": ca, "name": cn})
            if txt:
                lyn.append(txt)
        desc = " || ".join(b[0] or "" for b in bugs)
        why = " || ".join(b[1] or "" for b in bugs)
        loc = " ; ".join(b[2] or "" for b in bugs)
        preconditions = [
            {"text": t, "kind": k, "attack_note": a or ""}
            for (t, k, a) in preconds
        ][:8]
        tasks.append({
            "id": fn,
            "theme": ((bugs[0][3] if bugs else "precondition") + "/" +
                      ((bugs[0][4] or "")[:30] if bugs else "caller-owned")),
            "bug_desc": desc[:1200],
            "bug_why": why[:800],
            "bug_location": loc[:300],
            "preconditions": preconditions,
            "consumer": cons,
            "lynchpins": lyn,
        })

    tmpl = Path(_SD, "phase2-template.js").read_text()
    tmpl = re.sub(r"^const TASKS = .*$", lambda m: "const TASKS = " + json.dumps(tasks),
                  tmpl, count=1, flags=re.M)
    outp = root / ("phase2-wf-b%d.js" % args.batch)
    outp.write_text(tmpl)
    con.close()
    print("[prep-phase2-bn] batch%d: %d/%d tasks -> %s" % (
        args.batch, len(tasks), len(names), outp.resolve()))


if __name__ == "__main__":
    main()
