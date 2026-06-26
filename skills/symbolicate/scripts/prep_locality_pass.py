#!/usr/bin/env python3
"""prep_locality_pass.py - late-stage naming prep with address-local context.

This is a residue pass for stripped binaries where direct strings and
caller/callee names are thin, but address locality still carries signal. It
adds nearest named lower/higher functions, distance-to-boundary, neighboring
prefix counts, and unnamed-run size to each record so reviewers/agents can spot
families such as VMCISockStream_* or SVGA3D_* helpers clustered in address
space.

  bn-sym-prep-locality --bv-match i_vmx_full --db symdb.sqlite \
      --sidecar i_vmx_full.sidecar.json --out locality_pass1.json --n 1200
"""
import argparse
import bisect
import glob
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm

HLIL_BODY = r'''
import json as _j, sqlite3
_addrs = _j.loads(_addrs_json)
_limit = int(_hlil_dump_bytes)
_c = sqlite3.connect(_db, timeout=120)
_c.execute("CREATE TABLE IF NOT EXISTS hlil(addr INTEGER PRIMARY KEY, text TEXT)")
_rows = []
for _a in _addrs:
    _f = _bv.get_function_at(_a)
    if _f is None:
        continue
    try:
        _h = str(_f.hlil)
    except Exception:
        _h = ""
    _rows.append((_a, _h[:_limit]))
_c.executemany("INSERT OR REPLACE INTO hlil(addr,text) VALUES(?,?)", _rows)
_c.commit(); _c.close()
print("[prep-locality] hlil dumped: %d" % len(_rows))
'''


def _addr(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value)
        except Exception:
            return None
    return None


def _is_auto_name(name):
    return not name or re.match(r"^sub_[0-9a-fA-F]+$", name) or name.startswith("j_sub_")


def _load_sidecar_names(sidecar):
    names = {}
    if not sidecar or not os.path.exists(sidecar):
        return names
    side = json.load(open(sidecar))
    for key, rec in (side.get("functions") or {}).items():
        try:
            a = int(key, 16)
        except Exception:
            continue
        if isinstance(rec, dict) and rec.get("name"):
            names[a] = rec["name"]
    return names


def _default_attempt_globs(out_path):
    base = Path(out_path).resolve().parent
    return [
        str(base / "wave*.combined.json"),
        str(base / "codex_wave*" / "wave*.codex.combined.json"),
        str(base / "codex_second_pass*" / "second_pass*.codex.combined.json"),
        str(base / "codex_locality_pass*" / "locality_pass*.codex.combined.json"),
    ]


def _load_attempts(patterns):
    attempts = Counter()
    for pat in patterns:
        for path in glob.glob(pat):
            try:
                recs = json.load(open(path))
            except Exception:
                continue
            if not isinstance(recs, list):
                continue
            for rec in recs:
                if not isinstance(rec, dict):
                    continue
                a = _addr(rec.get("addr"))
                if a is not None:
                    attempts[a] += 1
    return attempts


def _prefix_token(name):
    if not name:
        return ""
    if "_" in name:
        token = name.split("_", 1)[0]
        return token if len(token) >= 3 else ""
    m = re.match(r"^([A-Z][A-Za-z0-9]{3,}?)(?:[A-Z][a-z]|$)", name)
    if m:
        return m.group(1)
    return ""


def _common_prefix(names):
    names = [n for n in names if n]
    if len(names) < 2:
        return ""
    pref = os.path.commonprefix(names)
    pref = re.sub(r"[^A-Za-z0-9_]+$", "", pref)
    if "_" in pref:
        pref = pref[:pref.rfind("_")]
    else:
        pref = re.sub(r"([a-z0-9])([A-Z])[^A-Z]*$", r"\1", pref)
    pref = pref.strip("_")
    if len(pref) < 4:
        return ""
    return pref


def _neighbor_record(addr, name, target):
    return {"addr": "0x%x" % addr, "name": name, "distance": abs(target - addr)}


def _window(named_addrs, named_names, pos, target, count, direction, max_distance):
    out = []
    if direction < 0:
        rng = range(pos - 1, -1, -1)
    else:
        rng = range(pos, len(named_addrs))
    for idx in rng:
        a = named_addrs[idx]
        dist = abs(target - a)
        if max_distance and dist > max_distance:
            break
        out.append(_neighbor_record(a, named_names[a], target))
        if len(out) >= count:
            break
    return out


def _edge_maps(db, effective_names):
    named_callees = defaultdict(list)
    named_callers = defaultdict(list)
    unnamed_callees = defaultdict(list)
    unnamed_callers = defaultdict(list)
    for caller, callee, callee_name in db.execute("SELECT caller, callee, callee_name FROM edge"):
        cn = effective_names.get(callee)
        rn = effective_names.get(caller)
        if cn:
            named_callees[caller].append(cn)
        else:
            unnamed_callees[caller].append(callee)
        if rn:
            named_callers[callee].append(rn)
        else:
            unnamed_callers[callee].append(caller)
    return named_callees, named_callers, unnamed_callees, unnamed_callers


def _graph_components(unnamed, unnamed_callees):
    parent = {}
    rank = {}

    def find(x):
        p = parent.setdefault(x, x)
        if p != x:
            parent[x] = find(p)
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

    unnamed_set = set(unnamed)
    for a in unnamed:
        find(a)
        for b in unnamed_callees.get(a, []):
            if b in unnamed_set:
                union(a, b)

    groups = defaultdict(list)
    for a in unnamed:
        groups[find(a)].append(a)

    comp_by_addr = {}
    comp_info = {}
    for idx, members in enumerate(sorted((sorted(v) for v in groups.values()), key=lambda xs: (xs[0], len(xs)))):
        cid = "c%05d" % idx
        for a in members:
            comp_by_addr[a] = cid
        comp_info[cid] = {
            "id": cid,
            "members": members,
            "size": len(members),
            "start": members[0],
            "end": members[-1],
            "span": members[-1] - members[0],
        }
    return comp_by_addr, comp_info


def _component_context(addr, comp_by_addr, comp_info, named_callers, named_callees, local_limit, max_context_size):
    cid = comp_by_addr.get(addr)
    if not cid:
        return {}
    info = comp_info[cid]
    members = info["members"]
    pos = bisect.bisect_left(members, addr)
    half = max(1, local_limit // 2)
    lo = max(0, pos - half)
    hi = min(len(members), pos + half + 1)
    if hi - lo < local_limit:
        lo = max(0, hi - local_limit)
        hi = min(len(members), lo + local_limit)

    base = {
        "id": cid,
        "size": info["size"],
        "start": "0x%x" % info["start"],
        "end": "0x%x" % info["end"],
        "span": info["span"],
        "index": pos,
        "nearby_members": ["0x%x" % x for x in members[lo:hi]],
    }
    if info["size"] > max_context_size:
        base.update({
            "coarse": True,
            "boundary_named_callers": [],
            "boundary_named_callees": [],
            "boundary_common_prefix": "",
            "boundary_prefixes": [],
        })
        return base

    boundary_callers = []
    boundary_callees = []
    for m in members:
        boundary_callers.extend(named_callers.get(m, []))
        boundary_callees.extend(named_callees.get(m, []))
    boundary_callers = _unique_limit(boundary_callers, 20)
    boundary_callees = _unique_limit(boundary_callees, 20)
    boundary_names = boundary_callers + boundary_callees
    prefix_counts = Counter(_prefix_token(n) for n in boundary_names)
    prefix_counts.pop("", None)

    base.update({
        "coarse": False,
        "boundary_named_callers": boundary_callers,
        "boundary_named_callees": boundary_callees,
        "boundary_common_prefix": _common_prefix(boundary_names),
        "boundary_prefixes": prefix_counts.most_common(8),
    })
    return base


def _unique_limit(items, limit):
    out = []
    seen = set()
    for item in items:
        key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else item
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def main():
    ap = argparse.ArgumentParser(description="Prepare a late naming batch with address-local family context.")
    bncm.add_target_args(ap)
    ap.add_argument("--db", required=True)
    ap.add_argument("--sidecar", required=True, help="sidecar whose named functions should be excluded")
    ap.add_argument("--profile", help="accepted for pipeline compatibility; locality prep reads extracted DB evidence")
    ap.add_argument("--out", required=True, help="batch JSON to write")
    ap.add_argument("--n", type=int, default=1200)
    ap.add_argument("--attempt-glob", action="append",
                    help="glob for prior workflow output JSON; repeatable. Defaults are relative to --out's directory")
    ap.add_argument("--neighbor-count", type=int, default=8,
                    help="named lower/higher neighbors to include on each side")
    ap.add_argument("--max-neighbor-distance", type=lambda s: int(s, 0), default=0x40000,
                    help="max byte distance for named-neighbor windows; 0 disables the cap")
    ap.add_argument("--callee-limit", type=int, default=28)
    ap.add_argument("--caller-limit", type=int, default=18)
    ap.add_argument("--local-edge-limit", type=int, default=12)
    ap.add_argument("--component-member-limit", type=int, default=16,
                    help="max nearby unnamed component members to include per record")
    ap.add_argument("--max-component-context-size", type=int, default=80,
                    help="do not summarize full graph boundary names for larger weak components")
    ap.add_argument("--string-limit", type=int, default=14)
    ap.add_argument("--hlil-bytes", type=int, default=3000)
    ap.add_argument("--hlil-dump-bytes", type=int, default=6000)
    ap.add_argument("--sort", choices=["address", "score"], default="address",
                    help="output ordering; address keeps families together in chunks")
    args = ap.parse_args()

    dbpath = os.path.abspath(args.db)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    side_names = _load_sidecar_names(args.sidecar)
    attempts = _load_attempts(args.attempt_glob or _default_attempt_globs(out_path))

    db = sqlite3.connect(dbpath)
    funcs = [(a, n or "", sz or 0) for a, n, sz in db.execute("SELECT addr, name, size FROM func ORDER BY addr")]
    all_addrs = [a for a, _, _ in funcs]
    effective_names = {}
    sizes = {}
    for a, n, sz in funcs:
        sizes[a] = sz
        side_name = side_names.get(a)
        if side_name:
            effective_names[a] = side_name
        elif not _is_auto_name(n):
            effective_names[a] = n

    unnamed = [a for a, _, _ in funcs if not effective_names.get(a)]
    named_addrs = sorted(effective_names)
    named_names = effective_names
    addr_to_index = {a: i for i, a in enumerate(all_addrs)}

    nstr = {a: c for a, c in db.execute("SELECT func_addr, COUNT(*) FROM strref GROUP BY func_addr")}
    haslog = set(a for (a,) in db.execute("SELECT DISTINCT func_addr FROM strref WHERE is_logpfx=1"))
    hasdom = set(a for (a,) in db.execute("SELECT DISTINCT func_addr FROM domain"))
    domains = defaultdict(list)
    for a, tag in db.execute("SELECT DISTINCT func_addr, tag FROM domain"):
        domains[a].append(tag)
    strrefs = defaultdict(list)
    for a, s in db.execute("SELECT func_addr, s FROM strref ORDER BY is_logpfx DESC"):
        if len(strrefs[a]) < args.string_limit:
            strrefs[a].append(s)
    named_callees, named_callers, unnamed_callees, unnamed_callers = _edge_maps(db, effective_names)
    comp_by_addr, comp_info = _graph_components(unnamed, unnamed_callees)

    scored = []
    locality_cache = {}
    for a in unnamed:
        pos = bisect.bisect_left(named_addrs, a)
        lower = _window(named_addrs, named_names, pos, a, args.neighbor_count, -1, args.max_neighbor_distance)
        higher = _window(named_addrs, named_names, pos, a, args.neighbor_count, 1, args.max_neighbor_distance)
        nearest_lower = lower[0] if lower else None
        nearest_higher = higher[0] if higher else None
        neighbor_names = [r["name"] for r in lower + higher]
        prefix_counts = Counter(_prefix_token(n) for n in neighbor_names)
        prefix_counts.pop("", None)
        dominant = prefix_counts.most_common(5)
        boundary_names = []
        if nearest_lower:
            boundary_names.append(nearest_lower["name"])
        if nearest_higher:
            boundary_names.append(nearest_higher["name"])
        boundary_common = _common_prefix(boundary_names)
        window_common = _common_prefix(neighbor_names[:])

        lower_named_idx = addr_to_index.get(int(nearest_lower["addr"], 16)) if nearest_lower else -1
        higher_named_idx = addr_to_index.get(int(nearest_higher["addr"], 16)) if nearest_higher else len(all_addrs)
        cur_idx = addr_to_index[a]
        run_start_idx = lower_named_idx + 1
        run_end_idx = higher_named_idx - 1
        run_count = max(0, run_end_idx - run_start_idx + 1)
        run_start = all_addrs[run_start_idx] if run_count else a
        run_end = all_addrs[run_end_idx] if run_count else a

        meta = {
            "nearest_lower": nearest_lower,
            "nearest_higher": nearest_higher,
            "named_neighbors_lower": lower,
            "named_neighbors_higher": higher,
            "boundary_common_prefix": boundary_common,
            "window_common_prefix": window_common,
            "dominant_neighbor_prefixes": dominant,
            "unnamed_run": {
                "start": "0x%x" % run_start,
                "end": "0x%x" % run_end,
                "count": run_count,
                "index_in_run": cur_idx - run_start_idx,
                "span": max(0, run_end - run_start),
            },
            "graph_component": _component_context(
                a, comp_by_addr, comp_info, named_callers, named_callees,
                args.component_member_limit, args.max_component_context_size),
        }
        locality_cache[a] = meta

        at = attempts.get(a, 0)
        nc = len(set(named_callees.get(a, [])))
        nr = len(set(named_callers.get(a, [])))
        score = (
            80 * (a in haslog)
            + 60 * (a in hasdom)
            + 5 * min(nstr.get(a, 0), 20)
            + 3 * min(nc, 30)
            + 2 * min(nr, 30)
            + (20 if at == 0 else 0)
            - 8 * min(at, 5)
        )
        if nearest_lower:
            score += 18 if nearest_lower["distance"] <= args.max_neighbor_distance else 4
        if nearest_higher:
            score += 18 if nearest_higher["distance"] <= args.max_neighbor_distance else 4
        if boundary_common:
            score += 70
        if window_common:
            score += 35
        if dominant:
            score += 20 + 6 * min(dominant[0][1], 8)
        graph_ctx = meta["graph_component"]
        if graph_ctx.get("size", 1) > 1:
            score += (8 if graph_ctx.get("coarse") else 25) + min(graph_ctx.get("size", 1), 30)
        if graph_ctx.get("boundary_common_prefix"):
            score += 45
        if graph_ctx.get("boundary_prefixes"):
            score += 15
        if 1 < run_count <= 40:
            score += 20
        elif run_count > 40:
            score += 8
        if at >= 4 and not (boundary_common or window_common or dominant or nc or nr or nstr.get(a, 0)):
            score -= 80
        if score > 0:
            scored.append((score, a))

    scored.sort(key=lambda item: (item[0], -attempts.get(item[1], 0), item[1]), reverse=True)
    chosen = scored[:args.n]
    if args.sort == "address":
        chosen.sort(key=lambda item: item[1])
    batch = [a for _, a in chosen]

    recs = {}
    for score, a in chosen:
        recs[a] = {
            "addr": "0x%x" % a,
            "tier": "sonnet",
            "strings": strrefs.get(a, []),
            "named_callees": _unique_limit(named_callees.get(a, []), args.callee_limit),
            "named_callers": _unique_limit(named_callers.get(a, []), args.caller_limit),
            "unnamed_callees": ["0x%x" % x for x in _unique_limit(unnamed_callees.get(a, []), args.local_edge_limit)],
            "unnamed_callers": ["0x%x" % x for x in _unique_limit(unnamed_callers.get(a, []), args.local_edge_limit)],
            "domain": domains.get(a, []),
            "locality": locality_cache[a],
            "second_pass_meta": {
                "score": score,
                "prior_attempts": attempts.get(a, 0),
                "n_strings": len(strrefs.get(a, [])),
                "n_named_callees": len(set(named_callees.get(a, []))),
                "n_named_callers": len(set(named_callers.get(a, []))),
                "n_unnamed_callees": len(set(unnamed_callees.get(a, []))),
                "n_unnamed_callers": len(set(unnamed_callers.get(a, []))),
            },
        }
    db.close()

    if batch:
        bncm.run(HLIL_BODY, _addrs_json=json.dumps(batch), _db=dbpath,
                 _hlil_dump_bytes=str(args.hlil_dump_bytes), **bncm.target_params(args))
        db = sqlite3.connect(dbpath)
        hlil = {a: t for a, t in db.execute("SELECT addr, text FROM hlil")}
        db.close()
        for a in batch:
            recs[a]["hlil"] = (hlil.get(a) or "")[:args.hlil_bytes]

    out = [recs[a] for a in batch]
    out_path.write_text(json.dumps(out, indent=2) + "\n")

    attempts_dist = Counter(attempts.get(a, 0) for a in batch)
    boundary_count = sum(1 for a in batch if locality_cache[a]["boundary_common_prefix"])
    window_count = sum(1 for a in batch if locality_cache[a]["window_common_prefix"])
    dominant_count = sum(1 for a in batch if locality_cache[a]["dominant_neighbor_prefixes"])
    graph_multi_count = sum(1 for a in batch if locality_cache[a]["graph_component"].get("size", 1) > 1)
    graph_boundary_count = sum(1 for a in batch if locality_cache[a]["graph_component"].get("boundary_common_prefix"))
    print("[prep-locality] wrote %s" % out_path)
    print("[prep-locality] selected %d from %d scored candidates; unnamed %d" % (len(batch), len(scored), len(unnamed)))
    print("[prep-locality] attempts: %s" % sorted(attempts_dist.items()))
    print("[prep-locality] locality: boundary_common=%d window_common=%d dominant_prefix=%d" % (
        boundary_count, window_count, dominant_count))
    print("[prep-locality] graph: multi_member=%d boundary_common=%d components=%d" % (
        graph_multi_count, graph_boundary_count, len(set(comp_by_addr.get(a) for a in batch))))
    print("[prep-locality] evidence: strings=%d callees=%d callers=%d log=%d domain=%d" % (
        sum(1 for a in batch if nstr.get(a, 0)),
        sum(1 for a in batch if named_callees.get(a)),
        sum(1 for a in batch if named_callers.get(a)),
        sum(1 for a in batch if a in haslog),
        sum(1 for a in batch if a in hasdom),
    ))


if __name__ == "__main__":
    main()
