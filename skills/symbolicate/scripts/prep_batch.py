#!/usr/bin/env python3
"""prep_batch.py — Pass 3 prep: pull a batch of UNNAMED functions that have evidence, bundle each with its
HLIL + referenced strings + named call-neighborhood + domain, and write a batch.json the naming workflow fans
out over. (Pre-extracting HLIL once — BN-side, to a file — keeps N agents off the decompiler and dodges the
~100 KB output cap.)

  bn-sym-prep --bv-match i_vmx_full --db .../symdb.sqlite --out .../batch1.json --n 24 [--offset 0]

Selection: unnamed functions ranked by evidence richness (strings + named callees) so the agent has something
to go on. Use --offset to walk further down the ranked list for subsequent batches.
"""
import sys, os, json, argparse, sqlite3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm

HLIL_BODY = r'''
import json as _j, sqlite3
_addrs = _j.loads(_addrs_json)
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
    _rows.append((_a, _h[:6000]))
_c.executemany("INSERT OR REPLACE INTO hlil(addr,text) VALUES(?,?)", _rows)
_c.commit(); _c.close()
print("[prep] hlil dumped: %d" % len(_rows))
'''


def main():
    ap = argparse.ArgumentParser(description="Prepare a naming batch (evidence + HLIL) for the symbolicate workflow.")
    bncm.add_target_args(ap)
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True, help="batch JSON to write")
    ap.add_argument("--n", type=int, default=24)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--sidecar", help="exclude functions already named in this sidecar")
    ap.add_argument("--spread", action="store_true", help="select a tier MIX (half evidence-rich -> haiku, half thin -> sonnet) to trial both tiers")
    args = ap.parse_args()
    dbpath = os.path.abspath(args.db)
    db = sqlite3.connect(dbpath)

    # functions already named (skip them)
    named_addrs = set()
    if args.sidecar and os.path.exists(args.sidecar):
        for k in (json.load(open(args.sidecar)).get("functions") or {}):
            try:
                named_addrs.add(int(k, 16))
            except Exception:
                pass

    # evidence maps
    nstr = {a: c for a, c in db.execute("SELECT func_addr, COUNT(*) FROM strref GROUP BY func_addr")}
    ncallee = {a: c for a, c in db.execute("SELECT caller, COUNT(*) FROM edge WHERE callee_name NOT LIKE 'sub_%' GROUP BY caller")}
    haslog = set(a for (a,) in db.execute("SELECT DISTINCT func_addr FROM strref WHERE is_logpfx=1"))
    hasdom = set(a for (a,) in db.execute("SELECT DISTINCT func_addr FROM domain"))
    unnamed = [a for (a,) in db.execute("SELECT addr FROM func WHERE name LIKE 'sub_%'")]
    scored = []
    for a in unnamed:
        if a in named_addrs:
            continue
        sc = 2 * nstr.get(a, 0) + ncallee.get(a, 0)
        if sc > 0:
            scored.append((sc, a))
    scored.sort(reverse=True)

    def tier_of(a, sc):
        # evidence-rich/self-identifying -> Haiku is plenty; thin (needs HLIL reasoning) -> Sonnet
        if a in hasdom or a in haslog or sc >= 6:
            return "haiku"
        return "sonnet"

    if args.spread:
        rich = [(sc, a) for sc, a in scored if tier_of(a, sc) == "haiku"]
        thin = [(sc, a) for sc, a in scored if tier_of(a, sc) == "sonnet"]
        half = args.n // 2
        chosen = rich[args.offset: args.offset + half] + thin[args.offset: args.offset + (args.n - half)]
    else:
        chosen = scored[args.offset: args.offset + args.n]
    batch = [a for _, a in chosen]
    tiers = {a: tier_of(a, sc) for sc, a in chosen}
    if not batch:
        print("[prep] no functions left to batch (offset past end)"); return

    # per-function evidence from the DB
    recs = {}
    for a in batch:
        strings = [s for (s,) in db.execute("SELECT s FROM strref WHERE func_addr=? ORDER BY is_logpfx DESC LIMIT 14", (a,))]
        callees = [n for (n,) in db.execute("SELECT DISTINCT callee_name FROM edge WHERE caller=? AND callee_name NOT LIKE 'sub_%' LIMIT 24", (a,))]
        callers = [n for (n,) in db.execute("SELECT DISTINCT f.name FROM edge e JOIN func f ON f.addr=e.caller WHERE e.callee=? AND f.name NOT LIKE 'sub_%' LIMIT 12", (a,))]
        domains = [t for (t,) in db.execute("SELECT DISTINCT tag FROM domain WHERE func_addr=?", (a,))]
        recs["0x%x" % a] = {"addr": "0x%x" % a, "tier": tiers[a], "strings": strings, "named_callees": callees,
                            "named_callers": callers, "domain": domains}
    db.close()

    # pull HLIL for the batch (BN-side writes to a sqlite table -> read back; BN sandbox forbids open())
    bncm.run(HLIL_BODY, _addrs_json=json.dumps(batch), _db=dbpath, **bncm.target_params(args))
    db = sqlite3.connect(dbpath)
    hlil = {a: t for a, t in db.execute("SELECT addr, text FROM hlil")}
    db.close()
    for a in batch:
        # cap embedded HLIL: the naming signal is in the head + the strings/callees, and the whole batch must
        # fit a Workflow script (<512 KB). Big functions rarely need more than this to name.
        recs["0x%x" % a]["hlil"] = hlil.get(a, "")[:3000]

    out = list(recs.values())
    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=2)
    nh = sum(1 for r in out if r["tier"] == "haiku")
    ns = sum(1 for r in out if r["tier"] == "sonnet")
    print("[prep] wrote %s  (%d functions: %d haiku-tier, %d sonnet-tier; offset %d)" % (args.out, len(out), nh, ns, args.offset))


if __name__ == "__main__":
    main()
