#!/usr/bin/env python3
"""prep_second_pass.py - targeted residue prep after the first-pass yield drops.

Builds a naming batch from still-unnamed functions, using the sidecar plus prior
workflow outputs as an abstention/attempt ledger. This avoids repeatedly sending
the same all-abstain residue and prefers functions that now have named callers,
named callees, domain tags, or direct strings after propagation.

  bn-sym-prep-second --bv-match i_vmx_full --db symdb.sqlite \
      --sidecar i_vmx_full.sidecar.json --out second_pass1.json --n 1200
"""
import argparse
import glob
import json
import os
import sqlite3
import sys
from collections import Counter
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
print("[prep-second] hlil dumped: %d" % len(_rows))
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


def _load_named_addrs(sidecar):
    named = set()
    if not sidecar or not os.path.exists(sidecar):
        return named
    side = json.load(open(sidecar))
    for key, rec in (side.get("functions") or {}).items():
        try:
            if isinstance(rec, dict) and rec.get("name"):
                named.add(int(key, 16))
        except Exception:
            pass
    return named


def _default_attempt_globs(out_path):
    base = Path(out_path).resolve().parent
    return [
        str(base / "wave*.combined.json"),
        str(base / "codex_wave*" / "wave*.codex.combined.json"),
        str(base / "codex_second_pass*" / "second_pass*.codex.combined.json"),
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


def main():
    ap = argparse.ArgumentParser(description="Prepare a targeted second-pass naming batch.")
    bncm.add_target_args(ap)
    ap.add_argument("--db", required=True)
    ap.add_argument("--sidecar", required=True, help="sidecar whose named functions should be excluded")
    ap.add_argument("--profile", help="accepted for pipeline compatibility; second-pass prep reads extracted DB evidence")
    ap.add_argument("--out", required=True, help="batch JSON to write")
    ap.add_argument("--n", type=int, default=1200)
    ap.add_argument("--attempt-glob", action="append",
                    help="glob for prior workflow output JSON; repeatable. Defaults are relative to --out's directory")
    ap.add_argument("--cheap-string-threshold", type=int, default=3,
                    help="route to cheap tier when a function has this many direct strings (default 3)")
    ap.add_argument("--callee-limit", type=int, default=28)
    ap.add_argument("--caller-limit", type=int, default=18)
    ap.add_argument("--string-limit", type=int, default=14)
    ap.add_argument("--hlil-bytes", type=int, default=3000,
                    help="max HLIL bytes embedded per record")
    ap.add_argument("--hlil-dump-bytes", type=int, default=6000,
                    help="max HLIL bytes stored in sqlite by the BN-side helper")
    args = ap.parse_args()

    dbpath = os.path.abspath(args.db)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    attempt_globs = args.attempt_glob or _default_attempt_globs(out_path)
    attempts = _load_attempts(attempt_globs)
    named_addrs = _load_named_addrs(args.sidecar)

    db = sqlite3.connect(dbpath)
    nstr = {a: c for a, c in db.execute("SELECT func_addr, COUNT(*) FROM strref GROUP BY func_addr")}
    ncallee = {a: c for a, c in db.execute(
        "SELECT caller, COUNT(*) FROM edge WHERE callee_name NOT LIKE 'sub_%' GROUP BY caller")}
    ncaller = {a: c for a, c in db.execute(
        "SELECT e.callee, COUNT(DISTINCT e.caller) "
        "FROM edge e JOIN func f ON f.addr=e.caller "
        "WHERE f.name NOT LIKE 'sub_%' GROUP BY e.callee")}
    haslog = set(a for (a,) in db.execute("SELECT DISTINCT func_addr FROM strref WHERE is_logpfx=1"))
    hasdom = set(a for (a,) in db.execute("SELECT DISTINCT func_addr FROM domain"))
    unnamed = [a for (a,) in db.execute("SELECT addr FROM func WHERE name LIKE 'sub_%'") if a not in named_addrs]

    scored = []
    for a in unnamed:
        ns = nstr.get(a, 0)
        nc = ncallee.get(a, 0)
        nr = ncaller.get(a, 0)
        at = attempts.get(a, 0)
        score = (
            80 * (a in haslog)
            + 60 * (a in hasdom)
            + 5 * min(ns, 20)
            + 3 * min(nc, 30)
            + min(nr, 40)
            + (20 if at == 0 else 0)
            - 20 * min(at, 5)
        )
        if at >= 5 and not (ns or nc or nr or a in haslog or a in hasdom):
            score -= 100
        if score > 0:
            scored.append((score, a))
    scored.sort(key=lambda item: (item[0], -attempts.get(item[1], 0), item[1]), reverse=True)
    chosen = scored[:args.n]
    batch = [a for _, a in chosen]

    def tier_of(a):
        if a in hasdom or a in haslog or nstr.get(a, 0) >= args.cheap_string_threshold:
            return "haiku"
        return "sonnet"

    recs = {}
    for score, a in chosen:
        strings = [s for (s,) in db.execute(
            "SELECT s FROM strref WHERE func_addr=? ORDER BY is_logpfx DESC LIMIT ?", (a, args.string_limit))]
        callees = [n for (n,) in db.execute(
            "SELECT DISTINCT callee_name FROM edge "
            "WHERE caller=? AND callee_name NOT LIKE 'sub_%' LIMIT ?", (a, args.callee_limit))]
        callers = [n for (n,) in db.execute(
            "SELECT DISTINCT f.name FROM edge e JOIN func f ON f.addr=e.caller "
            "WHERE e.callee=? AND f.name NOT LIKE 'sub_%' LIMIT ?", (a, args.caller_limit))]
        domains = [t for (t,) in db.execute("SELECT DISTINCT tag FROM domain WHERE func_addr=?", (a,))]
        recs[a] = {
            "addr": "0x%x" % a,
            "tier": tier_of(a),
            "strings": strings,
            "named_callees": callees,
            "named_callers": callers,
            "domain": domains,
            "second_pass_meta": {
                "score": score,
                "prior_attempts": attempts.get(a, 0),
                "n_strings": len(strings),
                "n_named_callees": len(callees),
                "n_named_callers": len(callers),
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

    tiers = Counter(r["tier"] for r in out)
    attempts_dist = Counter(attempts.get(a, 0) for a in batch)
    print("[prep-second] wrote %s" % out_path)
    print("[prep-second] selected %d from %d candidates; unnamed %d" % (len(batch), len(scored), len(unnamed)))
    print("[prep-second] tiers: %s" % dict(tiers))
    print("[prep-second] attempts: %s" % sorted(attempts_dist.items()))
    print("[prep-second] evidence: strings=%d callees=%d callers=%d log=%d domain=%d" % (
        sum(1 for a in batch if nstr.get(a, 0)),
        sum(1 for a in batch if ncallee.get(a, 0)),
        sum(1 for a in batch if ncaller.get(a, 0)),
        sum(1 for a in batch if a in haslog),
        sum(1 for a in batch if a in hasdom),
    ))


if __name__ == "__main__":
    main()
