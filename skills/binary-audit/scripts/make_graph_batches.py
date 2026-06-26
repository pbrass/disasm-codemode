#!/usr/bin/env python3
"""make_graph_batches.py - create review batches from graph-locality output.

The normal make_batches.py worklist is score-only. This helper starts from
graph_report.py output and selects high-scoring auto-name functions that are
prefix-sandwiched or graph-boundary adjacent to relevant named families.

  bn-audit-make-graph-batches --db kaudit/kreview.db --graph kaudit/graph-locality.json \
      --out kaudit/graph-batches.json --keyword VMCI --keyword Vmxnet3
"""
import argparse
import json
import os
import re
import sqlite3
from pathlib import Path


DEFAULT_VMX_KEYWORDS = [
    "USB", "Usb", "Xhci", "Ehci", "Uhci",
    "SVGA", "MSVGADX", "MKS", "MVNC",
    "Vmxnet3", "E1000", "Ethernet",
    "VMCI", "VMCISock", "VSock", "Socket",
    "VRDMA", "PVRDMA", "Vrdma",
    "PVSCSI", "LSILogic", "BusLogic", "AHCI", "NVME",
    "Checkpoint", "Snapshot", "Migrate", "Dumper",
    "Vigor", "GuestOps", "GuestRpc", "Backdoor",
    "Serial", "HDAudio",
]


def _addr(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    return None


def _json_text(value):
    return json.dumps(value, sort_keys=True)


def _context_prefix(value):
    if not isinstance(value, dict):
        return ""
    return (
        value.get("boundary_common_prefix")
        or value.get("window_common_prefix")
        or ((value.get("dominant_neighbor_prefixes") or value.get("boundary_prefixes") or [[""]])[0][0])
        or ""
    )


def _collect_candidates(report):
    candidates = {}

    def add(addr, source, score, context):
        if addr is None:
            return
        cur = candidates.setdefault(addr, {"addr": addr, "sources": [], "graph_score": 0.0, "contexts": []})
        cur["sources"].append(source)
        cur["graph_score"] = max(cur["graph_score"], float(score or 0))
        if context:
            cur["contexts"].append(context)

    for rec in report.get("prefix_sandwiches") or []:
        add(_addr(rec.get("addr")), "prefix_sandwich", rec.get("score"), rec)

    for run in report.get("address_runs") or []:
        run_score = (run.get("max_score") or 0) + (8 if _context_prefix(run) else 0)
        for func in run.get("top_functions") or []:
            ctx = {
                "source": "address_run",
                "start": run.get("start"),
                "end": run.get("end"),
                "count": run.get("count"),
                "prefix": _context_prefix(run),
                "nearest_lower": run.get("nearest_lower"),
                "nearest_higher": run.get("nearest_higher"),
            }
            add(_addr(func.get("addr")), "address_run", run_score, ctx)

    for comp in report.get("graph_components") or []:
        comp_score = (comp.get("max_score") or 0) + (8 if _context_prefix(comp) else 0)
        for func in comp.get("top_functions") or []:
            ctx = {
                "source": "graph_component",
                "start": comp.get("start"),
                "end": comp.get("end"),
                "count": comp.get("count"),
                "prefix": _context_prefix(comp),
                "boundary_named_callers": comp.get("boundary_named_callers", [])[:8],
                "boundary_named_callees": comp.get("boundary_named_callees", [])[:8],
            }
            add(_addr(func.get("addr")), "graph_component", comp_score, ctx)

    return candidates


def main():
    ap = argparse.ArgumentParser(description="Create graph/locality-guided audit review batches.")
    ap.add_argument("--db", default=None, help="kreview.db path; defaults to $KAUDIT_ROOT/kreview.db")
    ap.add_argument("--graph", default=None, help="graph-locality JSON; defaults to $KAUDIT_ROOT/graph-locality.json")
    ap.add_argument("--out", default=None, help="batches JSON path; defaults to $KAUDIT_ROOT/graph-batches.json")
    ap.add_argument("--manifest", default=None, help="optional candidate manifest JSON")
    ap.add_argument("--batch-size", type=int, default=12)
    ap.add_argument("--limit", type=int, default=48)
    ap.add_argument("--min-score", type=float, default=1.0, help="minimum func.score")
    ap.add_argument("--min-graph-score", type=float, default=0.0)
    ap.add_argument("--skip-reviewed", action="store_true", default=True)
    ap.add_argument("--include-reviewed", action="store_false", dest="skip_reviewed")
    ap.add_argument("--keyword", action="append", default=[], help="case-insensitive family/context keyword; repeatable")
    ap.add_argument("--vmx-keywords", action="store_true", help="add default vmx attack-surface keywords")
    args = ap.parse_args()

    root = os.environ.get("KAUDIT_ROOT", ".")
    dbpath = args.db or os.path.join(root, "kreview.db")
    graph_path = args.graph or os.path.join(root, "graph-locality.json")
    outpath = Path(args.out or os.path.join(root, "graph-batches.json"))
    manifest_path = Path(args.manifest) if args.manifest else outpath.with_suffix(".manifest.json")
    keywords = list(args.keyword)
    if args.vmx_keywords:
        keywords.extend(DEFAULT_VMX_KEYWORDS)
    keyword_re = re.compile("|".join(re.escape(k) for k in keywords), re.I) if keywords else None

    report = json.load(open(graph_path))
    candidates = _collect_candidates(report)

    con = sqlite3.connect(dbpath)
    con.row_factory = sqlite3.Row
    reviewed = set()
    if args.skip_reviewed:
        con.execute("CREATE TABLE IF NOT EXISTS review(addr INTEGER PRIMARY KEY, name TEXT, reviewed_at TEXT, reviewer TEXT, verdict TEXT, notes TEXT)")
        reviewed = {int(r[0]) for r in con.execute("SELECT addr FROM review WHERE addr IS NOT NULL")}

    enriched = []
    for addr, cand in candidates.items():
        if args.skip_reviewed and addr in reviewed:
            continue
        row = con.execute(
            "SELECT addr,name,score,cc,sink_calls,parse_off,n_insns FROM func WHERE addr=?",
            (addr,),
        ).fetchone()
        if not row:
            continue
        score = float(row["score"] or 0)
        if score < args.min_score or cand["graph_score"] < args.min_graph_score:
            continue
        text = _json_text(cand)
        if keyword_re and not keyword_re.search(text):
            continue
        enriched.append({
            "addr": "0x%x" % addr,
            "name": row["name"],
            "score": score,
            "graph_score": cand["graph_score"],
            "cc": row["cc"],
            "sink_calls": row["sink_calls"],
            "parse_off": row["parse_off"],
            "n_insns": row["n_insns"],
            "sources": sorted(set(cand["sources"])),
            "prefix": _context_prefix(cand["contexts"][0]) if cand["contexts"] else "",
            "contexts": cand["contexts"][:4],
        })
    con.close()

    enriched.sort(key=lambda r: (r["score"], r["graph_score"], r["sink_calls"] or 0, r["parse_off"] or 0), reverse=True)
    chosen = enriched[:args.limit]
    batches = [[r["name"] for r in chosen[i:i + args.batch_size]] for i in range(0, len(chosen), args.batch_size)]

    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(json.dumps(batches, indent=2) + "\n")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(chosen, indent=2) + "\n")

    print("[make-graph-batches] wrote %s" % outpath)
    print("[make-graph-batches] wrote %s" % manifest_path)
    print("[make-graph-batches] selected=%d batches=%d candidates=%d min_score=%.2f keywords=%d" % (
        len(chosen), len(batches), len(enriched), args.min_score, len(keywords)))
    for rec in chosen[:12]:
        print("  {addr} {name} score={score:.2f} graph={graph_score:.2f} prefix={prefix}".format(**rec))


if __name__ == "__main__":
    main()
