#!/usr/bin/env python3
"""graph_report.py - summarize address and callgraph clusters in kreview.db.

This is an audit-steering helper for stripped/recovered-BNDB targets. It does
not decompile or mutate anything; it mines the extracted function table and
direct-edge graph for address-local unnamed runs, prefix-sandwiched functions,
and unnamed callgraph components with named boundary functions.

  bn-audit-graph-report --db kaudit/kreview.db --out kaudit/graph-locality.json \
      --md kaudit/graph-locality.md
"""
import argparse
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path


AUTO_RE = re.compile(r"^(?:sub|j_sub)_[0-9a-fA-F]+$|^nullsub_")


def _has(cur, table, col):
    try:
        return col in [r[1] for r in cur.execute("PRAGMA table_info(%s)" % table)]
    except sqlite3.Error:
        return False


def _is_auto_name(name):
    return not name or bool(AUTO_RE.match(name))


def _hex(addr):
    return "0x%x" % int(addr)


def _prefix_token(name):
    if not name:
        return ""
    if "_" in name:
        token = name.split("_", 1)[0]
        return token if len(token) >= 3 else ""
    # Keep acronym-heavy VMware-style families such as VMCISockStream together
    # when they are expressed in CamelCase without an underscore.
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z0-9]+", name)
    if not parts:
        return ""
    if len(parts) >= 3 and parts[0].isupper() and len(parts[0]) <= 5:
        token = "".join(parts[:3])
    elif len(parts) >= 2 and len(parts[0]) <= 5:
        token = "".join(parts[:2])
    else:
        token = parts[0]
    return token if len(token) >= 4 else ""


def _common_prefix(names):
    names = [n for n in names if n]
    if len(names) < 2:
        return ""
    pref = os.path.commonprefix(names)
    pref = re.sub(r"[^A-Za-z0-9_]+$", "", pref).strip("_")
    if "_" in pref:
        pref = pref[:pref.rfind("_")]
    else:
        pref = re.sub(r"([a-z0-9])([A-Z])[^A-Z]*$", r"\1", pref)
    pref = pref.strip("_")
    return pref if len(pref) >= 4 else ""


def _name_record(func, target=None):
    rec = {
        "addr": _hex(func["addr"]),
        "name": func["name"],
        "score": func.get("score"),
        "cc": func.get("cc"),
        "sink_calls": func.get("sink_calls"),
        "parse_off": func.get("parse_off"),
    }
    if target is not None:
        rec["distance"] = abs(func["addr"] - target)
    return rec


def _top_funcs(funcs, limit):
    return [
        _name_record(f)
        for f in sorted(funcs, key=lambda f: (f.get("score") or 0, f.get("sink_calls") or 0, f.get("cc") or 0), reverse=True)[:limit]
    ]


def _unique_limit(items, limit):
    out = []
    seen = set()
    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _load_funcs(cur):
    auto_col = _has(cur, "func_meta", "is_auto_name")
    has_user_col = _has(cur, "func_meta", "has_user_name")
    join = " LEFT JOIN func_meta m ON m.addr=f.addr" if auto_col or has_user_col else ""
    cols = [
        "f.addr", "f.name", "COALESCE(f.size,0)", "COALESCE(f.cc,0)",
        "COALESCE(f.sink_calls,0)", "COALESCE(f.parse_off,0)", "f.score",
    ]
    if auto_col:
        cols.append("m.is_auto_name")
    else:
        cols.append("NULL")
    if has_user_col:
        cols.append("m.has_user_name")
    else:
        cols.append("NULL")
    rows = cur.execute("SELECT %s FROM func f%s ORDER BY f.addr" % (",".join(cols), join)).fetchall()
    funcs = []
    for row in rows:
        addr, name, size, cc, sink, parse, score, is_auto, has_user = row
        auto = bool(is_auto) if is_auto is not None else _is_auto_name(name or "")
        if has_user:
            auto = False
        if _is_auto_name(name or ""):
            auto = True
        funcs.append({
            "addr": int(addr),
            "name": name or "",
            "size": int(size or 0),
            "cc": int(cc or 0),
            "sink_calls": int(sink or 0),
            "parse_off": int(parse or 0),
            "score": float(score) if score is not None else None,
            "is_auto": auto,
        })
    return funcs


def _neighbor_window(named, pos, target, side, count, max_distance):
    out = []
    if side < 0:
        indexes = range(pos - 1, -1, -1)
    else:
        indexes = range(pos, len(named))
    for idx in indexes:
        func = named[idx]
        if max_distance and abs(func["addr"] - target) > max_distance:
            break
        out.append(_name_record(func, target))
        if len(out) >= count:
            break
    return out


def _address_runs(funcs, neighbor_count, max_distance, top_funcs):
    named = [f for f in funcs if not f["is_auto"]]
    named_addrs = [f["addr"] for f in named]
    runs = []
    sandwiches = []
    i = 0
    while i < len(funcs):
        if not funcs[i]["is_auto"]:
            i += 1
            continue
        start = i
        while i < len(funcs) and funcs[i]["is_auto"]:
            i += 1
        members = funcs[start:i]
        lo_named = funcs[start - 1] if start > 0 and not funcs[start - 1]["is_auto"] else None
        hi_named = funcs[i] if i < len(funcs) and not funcs[i]["is_auto"] else None
        target = members[0]["addr"]
        pos = 0
        while pos < len(named_addrs) and named_addrs[pos] < target:
            pos += 1
        lower = _neighbor_window(named, pos, target, -1, neighbor_count, max_distance)
        higher = _neighbor_window(named, pos, members[-1]["addr"], 1, neighbor_count, max_distance)
        neighbor_names = [r["name"] for r in lower + higher]
        prefix_counts = Counter(_prefix_token(n) for n in neighbor_names)
        prefix_counts.pop("", None)
        boundary_names = []
        if lo_named:
            boundary_names.append(lo_named["name"])
        if hi_named:
            boundary_names.append(hi_named["name"])
        boundary_common = _common_prefix(boundary_names)
        window_common = _common_prefix(neighbor_names)
        score_values = [f.get("score") or 0 for f in members]
        run = {
            "start": _hex(members[0]["addr"]),
            "end": _hex(members[-1]["addr"]),
            "count": len(members),
            "span": members[-1]["addr"] - members[0]["addr"],
            "nearest_lower": _name_record(lo_named, members[0]["addr"]) if lo_named else None,
            "nearest_higher": _name_record(hi_named, members[-1]["addr"]) if hi_named else None,
            "boundary_common_prefix": boundary_common,
            "window_common_prefix": window_common,
            "dominant_neighbor_prefixes": prefix_counts.most_common(8),
            "max_score": max(score_values) if score_values else 0,
            "avg_score": sum(score_values) / len(score_values) if score_values else 0,
            "sink_count": sum(1 for f in members if f.get("sink_calls")),
            "parser_count": sum(1 for f in members if f.get("parse_off")),
            "top_functions": _top_funcs(members, top_funcs),
        }
        run["rank_score"] = (
            run["max_score"]
            + 0.1 * run["avg_score"]
            + 0.5 * run["sink_count"]
            + 0.25 * run["parser_count"]
            + (8 if boundary_common else 0)
            + (4 if window_common else 0)
            + (2 * prefix_counts.most_common(1)[0][1] if prefix_counts else 0)
        )
        runs.append(run)

        if boundary_common or window_common or prefix_counts:
            for idx, f in enumerate(members):
                sandwiches.append({
                    "addr": _hex(f["addr"]),
                    "name": f["name"],
                    "index_in_run": idx,
                    "run_count": len(members),
                    "score": f.get("score"),
                    "nearest_lower": run["nearest_lower"],
                    "nearest_higher": run["nearest_higher"],
                    "boundary_common_prefix": boundary_common,
                    "window_common_prefix": window_common,
                    "dominant_neighbor_prefixes": prefix_counts.most_common(5),
                })
    runs.sort(key=lambda r: (r["rank_score"], r["count"]), reverse=True)
    sandwiches.sort(key=lambda r: (r.get("score") or 0, r["run_count"]), reverse=True)
    return runs, sandwiches


def _graph_components(cur, funcs, top_funcs, max_component_context):
    func_by_addr = {f["addr"]: f for f in funcs}
    unnamed = {f["addr"] for f in funcs if f["is_auto"]}
    named = {f["addr"] for f in funcs if not f["is_auto"]}
    parent = {}
    rank = {}

    def find(x):
        parent.setdefault(x, x)
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(a, b):
        ra = find(a)
        rb = find(b)
        if ra == rb:
            return
        if rank.get(ra, 0) < rank.get(rb, 0):
            ra, rb = rb, ra
        parent[rb] = ra
        if rank.get(ra, 0) == rank.get(rb, 0):
            rank[ra] = rank.get(ra, 0) + 1

    boundary_callers = defaultdict(list)
    boundary_callees = defaultdict(list)
    edge_count = Counter()
    for caller, callee in cur.execute("SELECT caller, callee FROM edge"):
        caller = int(caller)
        callee = int(callee)
        if caller in unnamed:
            find(caller)
        if callee in unnamed:
            find(callee)
        if caller in unnamed and callee in unnamed:
            union(caller, callee)
            edge_count[caller] += 1
            edge_count[callee] += 1
        elif caller in named and callee in unnamed:
            boundary_callers[callee].append(func_by_addr[caller])
        elif caller in unnamed and callee in named:
            boundary_callees[caller].append(func_by_addr[callee])

    groups = defaultdict(list)
    for addr in unnamed:
        groups[find(addr)].append(addr)

    comps = []
    for members in groups.values():
        member_funcs = [func_by_addr[a] for a in sorted(members)]
        callers = []
        callees = []
        for a in members:
            callers.extend(boundary_callers.get(a, []))
            callees.extend(boundary_callees.get(a, []))
        boundary_names = [f["name"] for f in callers + callees]
        prefix_counts = Counter(_prefix_token(n) for n in boundary_names)
        prefix_counts.pop("", None)
        score_values = [f.get("score") or 0 for f in member_funcs]
        comp = {
            "start": _hex(member_funcs[0]["addr"]),
            "end": _hex(member_funcs[-1]["addr"]),
            "count": len(member_funcs),
            "span": member_funcs[-1]["addr"] - member_funcs[0]["addr"],
            "max_score": max(score_values) if score_values else 0,
            "avg_score": sum(score_values) / len(score_values) if score_values else 0,
            "internal_edge_degree": sum(edge_count[a] for a in members),
            "boundary_common_prefix": _common_prefix(boundary_names),
            "boundary_prefixes": prefix_counts.most_common(8),
            "boundary_named_callers": _unique_limit([_name_record(f) for f in callers], 24),
            "boundary_named_callees": _unique_limit([_name_record(f) for f in callees], 24),
            "top_functions": _top_funcs(member_funcs, top_funcs),
            "coarse": len(member_funcs) > max_component_context,
        }
        comp["rank_score"] = (
            comp["max_score"]
            + 0.05 * comp["avg_score"]
            + min(comp["count"], 80) * 0.1
            + min(comp["internal_edge_degree"], 200) * 0.05
            + (8 if comp["boundary_common_prefix"] else 0)
            + (2 * prefix_counts.most_common(1)[0][1] if prefix_counts else 0)
        )
        comps.append(comp)
    comps.sort(key=lambda c: (c["rank_score"], c["count"]), reverse=True)
    return comps


def _write_markdown(path, report, limit):
    lines = []
    meta = report["meta"]
    lines.append("# Graph/locality report")
    lines.append("")
    lines.append("- DB: `%s`" % meta["db"])
    lines.append("- Functions: %d total, %d named, %d auto/unnamed" % (
        meta["functions"], meta["named_functions"], meta["auto_functions"]))
    lines.append("- Address runs: %d; graph components: %d" % (
        len(report["address_runs"]), len(report["graph_components"])))
    lines.append("")

    lines.append("## Top Address-Local Unnamed Runs")
    for r in report["address_runs"][:limit]:
        lower = r["nearest_lower"]["name"] if r["nearest_lower"] else "-"
        higher = r["nearest_higher"]["name"] if r["nearest_higher"] else "-"
        pref = r["boundary_common_prefix"] or r["window_common_prefix"] or (
            r["dominant_neighbor_prefixes"][0][0] if r["dominant_neighbor_prefixes"] else "")
        lines.append("")
        lines.append("- `%s..%s` count=%d span=0x%x max_score=%.2f prefix=`%s`" % (
            r["start"], r["end"], r["count"], r["span"], r["max_score"], pref or "-"))
        lines.append("  lower=`%s` higher=`%s` sinks=%d parsers=%d" % (
            lower, higher, r["sink_count"], r["parser_count"]))
        if r["top_functions"]:
            tops = ", ".join("%s(%.1f)" % (f["addr"], f.get("score") or 0) for f in r["top_functions"][:5])
            lines.append("  top: %s" % tops)

    lines.append("")
    lines.append("## Top Unnamed Callgraph Components")
    for c in report["graph_components"][:limit]:
        pref = c["boundary_common_prefix"] or (c["boundary_prefixes"][0][0] if c["boundary_prefixes"] else "")
        lines.append("")
        lines.append("- `%s..%s` count=%d span=0x%x max_score=%.2f prefix=`%s` coarse=%s" % (
            c["start"], c["end"], c["count"], c["span"], c["max_score"], pref or "-", c["coarse"]))
        callers = ", ".join(r["name"] for r in c["boundary_named_callers"][:5]) or "-"
        callees = ", ".join(r["name"] for r in c["boundary_named_callees"][:5]) or "-"
        lines.append("  callers: %s" % callers)
        lines.append("  callees: %s" % callees)
        if c["top_functions"]:
            tops = ", ".join("%s(%.1f)" % (f["addr"], f.get("score") or 0) for f in c["top_functions"][:5])
            lines.append("  top: %s" % tops)

    lines.append("")
    lines.append("## Prefix-Sandwiched Function Examples")
    for s in report["prefix_sandwiches"][:limit]:
        pref = s["boundary_common_prefix"] or s["window_common_prefix"] or (
            s["dominant_neighbor_prefixes"][0][0] if s["dominant_neighbor_prefixes"] else "-")
        lines.append("- `%s` score=%.2f run=%d index=%d prefix=`%s`" % (
            s["addr"], s.get("score") or 0, s["run_count"], s["index_in_run"], pref))

    path.write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Summarize address/callgraph locality from a binary-audit DB.")
    ap.add_argument("--db", default=None, help="kreview.db path; defaults to $KAUDIT_ROOT/kreview.db")
    ap.add_argument("--out", default=None, help="JSON output path; defaults to $KAUDIT_ROOT/graph-locality.json")
    ap.add_argument("--md", default=None, help="optional Markdown report path")
    ap.add_argument("--neighbor-count", type=int, default=8)
    ap.add_argument("--max-neighbor-distance", type=lambda s: int(s, 0), default=0x40000)
    ap.add_argument("--top", type=int, default=80, help="records per output category")
    ap.add_argument("--top-functions", type=int, default=8)
    ap.add_argument("--max-component-context", type=int, default=120)
    args = ap.parse_args()

    root = os.environ.get("KAUDIT_ROOT", ".")
    dbpath = os.path.abspath(args.db or os.path.join(root, "kreview.db"))
    outpath = Path(args.out or os.path.join(root, "graph-locality.json"))
    outpath.parent.mkdir(parents=True, exist_ok=True)
    mdpath = Path(args.md) if args.md else None

    con = sqlite3.connect(dbpath)
    cur = con.cursor()
    funcs = _load_funcs(cur)
    runs, sandwiches = _address_runs(funcs, args.neighbor_count, args.max_neighbor_distance, args.top_functions)
    comps = _graph_components(cur, funcs, args.top_functions, args.max_component_context)
    con.close()

    named_count = sum(1 for f in funcs if not f["is_auto"])
    report = {
        "meta": {
            "db": dbpath,
            "functions": len(funcs),
            "named_functions": named_count,
            "auto_functions": len(funcs) - named_count,
            "neighbor_count": args.neighbor_count,
            "max_neighbor_distance": args.max_neighbor_distance,
        },
        "address_runs": runs[:args.top],
        "graph_components": comps[:args.top],
        "prefix_sandwiches": sandwiches[:args.top],
    }
    outpath.write_text(json.dumps(report, indent=2) + "\n")
    if mdpath:
        mdpath.parent.mkdir(parents=True, exist_ok=True)
        _write_markdown(mdpath, report, min(args.top, 40))

    print("[graph-report] wrote %s" % outpath)
    if mdpath:
        print("[graph-report] wrote %s" % mdpath)
    print("[graph-report] funcs=%d named=%d auto=%d runs=%d components=%d sandwiches=%d" % (
        len(funcs), named_count, len(funcs) - named_count, len(runs), len(comps), len(sandwiches)))
    if runs:
        r = runs[0]
        print("[graph-report] top-run %s..%s count=%d max_score=%.2f prefix=%s" % (
            r["start"], r["end"], r["count"], r["max_score"],
            r["boundary_common_prefix"] or r["window_common_prefix"] or (
                r["dominant_neighbor_prefixes"][0][0] if r["dominant_neighbor_prefixes"] else "-")))


if __name__ == "__main__":
    main()
