#!/usr/bin/env python3
"""prep_deciders_bn.py N - prepare decider-loop tasks from an open BNDB.

This is the stripped/BNDB-safe sibling of prep_deciders.py. It bootstraps
decider-worklist.json from phase-2 audit rows whose verdict is uncertain or
partial, extracts the current consumer/decider functions through Binary Ninja,
and emits decider-wf-bN.js.
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
print("[prep-deciders-bn] extracted text for %d/%d functions" % (len(_rows), len(_items)))
if _missing:
    print("[prep-deciders-bn] missing: %s" % ", ".join(_missing[:20]))
'''


def _safe_name(name, addr):
    safe = re.sub(r"[^A-Za-z0-9_.+-]+", "_", name or "func").strip("._")
    if not safe:
        safe = "func"
    return "%016x_%s" % (addr, safe[:150])


def _find_sym(text, symbols):
    if not text:
        return None
    m = re.search(r"[Pp]ull\s+([A-Za-z_][\w.]+)", text)
    if m and m.group(1) in symbols:
        return m.group(1)
    m = re.search(r"(?:recommended_next|next)\s*[:=]\s*([A-Za-z_][\w.]+)", text)
    if m and m.group(1) in symbols:
        return m.group(1)
    for s in sorted((x for x in symbols if x), key=len, reverse=True):
        if len(s) > 6 and s in text:
            return s
    return None


def _row_for(cur, fn):
    row = cur.execute("SELECT addr,name FROM func WHERE name=?", (fn,)).fetchone()
    if row:
        return int(row[0]), row[1]
    return None


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


def _bootstrap_worklist(cur, symbols):
    wl = {"frontier": [], "audited": {}, "round": 0}
    seen = set()
    rows = cur.execute("""
        SELECT a.func_name, a.next
        FROM audit a JOIN bug b ON b.func_name=a.func_name
        WHERE a.verdict IN ('uncertain','partial')
          AND b.status IN ('uncertain','partial')
        GROUP BY a.func_name, a.next
    """).fetchall()
    for fn, nxt in rows:
        dec = _find_sym(nxt or "", symbols)
        if not dec or dec == fn or (fn, dec) in seen:
            continue
        seen.add((fn, dec))
        b = cur.execute("SELECT desc FROM bug WHERE func_name=? LIMIT 1", (fn,)).fetchone()
        wl["frontier"].append({
            "consumer": fn,
            "decider": dec,
            "bug_desc": (b[0] if b else fn)[:600],
            "precondition": (nxt or "")[:1000],
            "status": "pending",
            "depth": 1,
        })
    return wl


def main():
    ap = argparse.ArgumentParser(description="Prepare BNDB-safe decider-loop tasks.")
    bncm.add_target_args(ap)
    ap.add_argument("batch", type=int, help="decider round number")
    ap.add_argument("--root", default=os.environ.get("KAUDIT_ROOT", "."))
    ap.add_argument("--db", default=None, help="kreview.db path; defaults to <root>/kreview.db")
    ap.add_argument("--max-tasks", type=int, default=8)
    ap.add_argument("--max-hlil", type=int, default=90000)
    ap.add_argument("--max-asm", type=int, default=8000)
    args = ap.parse_args()

    if args.batch <= 0:
        raise SystemExit("batch must be positive")
    root = Path(args.root)
    dbpath = Path(args.db or (root / "kreview.db")).resolve()
    wlpath = root / "decider-worklist.json"
    con = sqlite3.connect(str(dbpath))
    cur = con.cursor()
    symbols = set(r[0] for r in cur.execute("SELECT name FROM func") if r[0])

    if wlpath.exists():
        wl = json.loads(wlpath.read_text())
    else:
        wl = _bootstrap_worklist(cur, symbols)
        print("bootstrapped frontier: %d (bug,decider) pairs" % len(wl["frontier"]))

    wl["round"] = args.batch
    pending = [p for p in wl["frontier"] if p.get("status") == "pending"][: max(1, args.max_tasks)]
    task_pairs = []
    extract_items = {}
    for p in pending:
        cons = _row_for(cur, p["consumer"])
        dec = _row_for(cur, p["decider"])
        if not cons or not dec:
            p["status"] = "exhausted-extsym"
            continue
        c_item = {"addr": cons[0], "name": cons[1]}
        d_item = {"addr": dec[0], "name": dec[1]}
        extract_items[c_item["addr"]] = c_item
        extract_items[d_item["addr"]] = d_item
        p["status"] = "inflight"
        task_pairs.append((p, c_item, d_item))

    root.mkdir(parents=True, exist_ok=True)
    (root / "hlil").mkdir(parents=True, exist_ok=True)
    (root / "asm").mkdir(parents=True, exist_ok=True)
    if extract_items:
        bncm.run(BODY, _db=str(dbpath), _items_json=json.dumps(list(extract_items.values())),
                 _max_hlil=str(args.max_hlil), _max_asm=str(args.max_asm),
                 **bncm.target_params(args))

    tasks = []
    for p, c_item, d_item in task_pairs:
        cons = _ensure_text(cur, root, c_item)
        dec = _ensure_text(cur, root, d_item)
        if not cons or not dec:
            p["status"] = "text-missing"
            continue
        tasks.append({
            "id": "%s__via__%s" % (p["consumer"], p["decider"]),
            "consumer": cons,
            "decider": dec,
            "bug_desc": p.get("bug_desc", "")[:2000],
            "precondition": p.get("precondition", "")[:1000],
        })

    wlpath.write_text(json.dumps(wl, indent=0) + "\n")
    if not tasks:
        print("NO PENDING TASKS - frontier exhausted (fixpoint).")
        con.close()
        return
    tmpl = Path(_SD, "decider-template.js").read_text()
    tmpl = re.sub(r"^const TASKS = .*$", lambda m: "const TASKS = " + json.dumps(tasks),
                  tmpl, count=1, flags=re.M)
    outp = root / ("decider-wf-b%d.js" % args.batch)
    outp.write_text(tmpl)
    con.close()
    print("decider-round%d: %d tasks -> %s | frontier pending left: %d" % (
        args.batch, len(tasks), outp.resolve(),
        sum(1 for p in wl["frontier"] if p.get("status") == "pending")))


if __name__ == "__main__":
    main()
