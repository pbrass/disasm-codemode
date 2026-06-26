#!/usr/bin/env python3
"""prep_batch_bn.py N - prepare Stage-2 audit batch using Binary Ninja addresses.

This is the stripped/BNDB-safe sibling of prep_batch.py. It reads
$KAUDIT_ROOT/batches.json, pulls HLIL and disassembly from the open BN view in
one code-mode call, writes files under $KAUDIT_ROOT/hlil and asm, and emits the
same review-wf-bN.js template.

  bn-audit-prep-batch-bn 1 --bv-match i_vmx_full
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
_addrs = _json.loads(_addrs_json)
_max_hlil = int(_max_hlil)
_max_asm = int(_max_asm)
_c = _sqlite3.connect(_db, timeout=180)
_c.execute("CREATE TABLE IF NOT EXISTS audit_text(addr INTEGER PRIMARY KEY, hlil TEXT, asm TEXT)")
_rows = []
for _a in _addrs:
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
print("[prep-batch-bn] extracted text for %d/%d functions" % (len(_rows), len(_addrs)))
'''


def _safe_name(name, addr):
    safe = re.sub(r"[^A-Za-z0-9_.+-]+", "_", name or "func").strip("._")
    if not safe:
        safe = "func"
    if len(safe) > 160:
        safe = safe[:160]
    return "%016x_%s" % (addr, safe)


def _load_graph_context(path):
    if not path:
        return {}
    data = json.load(open(path))
    out = {}

    def addr_int(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value, 16) if value.startswith("0x") else int(value)
        return None

    def prefix(value):
        if not isinstance(value, dict):
            return ""
        return (
            value.get("boundary_common_prefix")
            or value.get("window_common_prefix")
            or ((value.get("dominant_neighbor_prefixes") or value.get("boundary_prefixes") or [[""]])[0][0])
            or ""
        )

    def merge(addr, key, ctx):
        if addr is None:
            return
        rec = out.setdefault(addr, {})
        rec[key] = ctx

    for rec in data.get("prefix_sandwiches") or []:
        merge(addr_int(rec.get("addr")), "prefix_sandwich", {
            "prefix": prefix(rec),
            "run_count": rec.get("run_count"),
            "index_in_run": rec.get("index_in_run"),
            "nearest_lower": rec.get("nearest_lower"),
            "nearest_higher": rec.get("nearest_higher"),
        })
    for rec in data.get("address_runs") or []:
        ctx = {
            "start": rec.get("start"),
            "end": rec.get("end"),
            "count": rec.get("count"),
            "prefix": prefix(rec),
            "nearest_lower": rec.get("nearest_lower"),
            "nearest_higher": rec.get("nearest_higher"),
            "dominant_neighbor_prefixes": rec.get("dominant_neighbor_prefixes", [])[:5],
        }
        for func in rec.get("top_functions") or []:
            merge(addr_int(func.get("addr")), "address_run", ctx)
    for rec in data.get("graph_components") or []:
        ctx = {
            "start": rec.get("start"),
            "end": rec.get("end"),
            "count": rec.get("count"),
            "prefix": prefix(rec),
            "boundary_named_callers": rec.get("boundary_named_callers", [])[:8],
            "boundary_named_callees": rec.get("boundary_named_callees", [])[:8],
            "boundary_prefixes": rec.get("boundary_prefixes", [])[:5],
        }
        for func in rec.get("top_functions") or []:
            merge(addr_int(func.get("addr")), "graph_component", ctx)
    return out


def main():
    ap = argparse.ArgumentParser(description="Prepare a binary-audit review batch using BN for HLIL and asm.")
    bncm.add_target_args(ap)
    ap.add_argument("batch", type=int, help="1-based batch number from $KAUDIT_ROOT/batches.json")
    ap.add_argument("--root", default=os.environ.get("KAUDIT_ROOT", "."))
    ap.add_argument("--db", default=None, help="kreview.db path; defaults to <root>/kreview.db")
    ap.add_argument("--profile", default=os.environ.get("KAUDIT_PROFILE"), help="profile JSON for review framing")
    ap.add_argument("--batches", default=None, help="batches JSON path; defaults to <root>/batches.json")
    ap.add_argument("--workflow-out", default=None, help="workflow path; defaults to <root>/review-wf-bN.js")
    ap.add_argument("--graph-context", default=None, help="optional graph-locality JSON to splice into FNS records")
    ap.add_argument("--max-hlil", type=int, default=70000)
    ap.add_argument("--max-asm", type=int, default=5000)
    args = ap.parse_args()

    root = Path(args.root)
    dbpath = Path(args.db or (root / "kreview.db")).resolve()
    batches_path = Path(args.batches or (root / "batches.json"))
    batches = json.loads(batches_path.read_text())
    if args.batch < 1 or args.batch > len(batches):
        raise SystemExit("batch %d out of range 1..%d" % (args.batch, len(batches)))
    names = batches[args.batch - 1]

    con = sqlite3.connect(str(dbpath))
    funcs = []
    addrs = []
    for nm in names:
        r = con.execute(
            "SELECT addr,name,size,cc,n_memidx,sink_calls,parse_off,n_insns FROM func WHERE name=?",
            (nm,)).fetchone()
        if not r:
            print("  MISSING %s" % nm)
            continue
        addr, name, size, cc, mi, sk, pa, ins = r
        funcs.append({"addr_int": addr, "name": name, "size": size, "cc": cc, "memidx": mi,
                      "sink": sk, "parse": pa, "insns": ins})
        addrs.append(addr)

    if addrs:
        bncm.run(BODY, _db=str(dbpath), _addrs_json=json.dumps(addrs),
                 _max_hlil=str(args.max_hlil), _max_asm=str(args.max_asm),
                 **bncm.target_params(args))

    (root / "hlil").mkdir(parents=True, exist_ok=True)
    (root / "asm").mkdir(parents=True, exist_ok=True)
    out_fns = []
    graph_context = _load_graph_context(args.graph_context) if args.graph_context else {}
    for f in funcs:
        row = con.execute("SELECT hlil, asm FROM audit_text WHERE addr=?", (f["addr_int"],)).fetchone()
        if not row:
            print("  TEXT-MISSING %s" % f["name"])
            continue
        stem = _safe_name(f["name"], f["addr_int"])
        hl_path = root / "hlil" / ("%s.hlil.c" % stem)
        asm_path = root / "asm" / ("%s.asm" % stem)
        hl_path.write_text(row[0] or "")
        asm_path.write_text(row[1] or "")
        rec = {
            "name": f["name"],
            "addr": "0x%x" % f["addr_int"],
            "cc": f["cc"],
            "memidx": f["memidx"],
            "sink": f["sink"],
            "parse": f["parse"],
            "insns": f["insns"],
            "hlil": str(hl_path),
            "asm": str(asm_path),
        }
        if graph_context.get(f["addr_int"]):
            rec["locality"] = graph_context[f["addr_int"]]
        out_fns.append(rec)

    tmpl = Path(_SD, "review-wf.js").read_text()
    repl = "const FNS = " + json.dumps(out_fns)
    tmpl = re.sub(r"^const FNS = .*$", lambda m: repl, tmpl, count=1, flags=re.M)
    if args.profile:
        prof = json.load(open(args.profile))
        for key, prefix in [
            ("review_target", "const TARGET = "),
            ("review_attacker", "const ATTACKER = "),
            ("review_context", "const CONTEXT = "),
        ]:
            if prof.get(key):
                line = prefix + json.dumps(prof[key]) + "   // (profile)"
                tmpl = re.sub(r"^" + re.escape(prefix) + r".*$", lambda m, line=line: line, tmpl, count=1, flags=re.M)
    outp = Path(args.workflow_out or (root / ("review-wf-b%d.js" % args.batch)))
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(tmpl)
    con.close()
    print("[prep-batch-bn] batch%d: %d/%d fns prepped -> %s" % (
        args.batch, len(out_fns), len(names), outp.resolve()))


if __name__ == "__main__":
    main()
