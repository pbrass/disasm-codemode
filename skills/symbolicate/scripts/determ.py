#!/usr/bin/env python3
"""determ.py — Pass 1 of symbolicate: DETERMINISTIC names from the evidence DB (no LLM, high confidence).

The one rule that needs no judgement: a stripped function that references a log string whose prefix is an
EXACT function-name (CamelCase with '_', e.g. "OvhdMem_PowerOn: ...") — and is the SOLE referencer of that
prefix — is almost certainly that function (VMware logs __FUNCTION__). We also tag domains from shared
module prefixes (Vmxnet3, USB, ...). Output is written into the re_sync SIDECAR (merge), with provenance
(_source/_confidence) so later passes and review know what's proven vs. inferred.

  bn-sym-determ --db phil_notes/vmx-re/symdb.sqlite --sidecar phil_notes/vmx-re/i_vmx_full.sidecar.json \
                --profile <plugin>/skills/symbolicate/profiles/vmware.json

Then sync: bn-re-apply <sidecar> --bv-match i_vmx_full   (Ctrl+S to persist).
Idempotent: re-running recomputes proposals and merges; never clobbers a hand-authored or higher-confidence
entry already in the sidecar (a determ proposal only fills an empty slot or another determ slot).
"""
import sys, os, json, re, argparse, sqlite3


def main():
    ap = argparse.ArgumentParser(description="Deterministic Pass-1 naming from the evidence DB -> sidecar.")
    ap.add_argument("--db", required=True, help="evidence DB from extract.py")
    ap.add_argument("--sidecar", required=True, help="re_sync sidecar JSON to write/merge")
    ap.add_argument("--profile", required=True, help="symbolicate profile JSON")
    ap.add_argument("--max-shared", type=int, default=1, help="a name-prefix referenced by >this many functions is a DOMAIN tag, not a name (default 1 = sole referencer only)")
    args = ap.parse_args()
    prof = json.load(open(args.profile))
    exact_re = prof["exact_name_re"]
    db = sqlite3.connect(args.db)

    # current names already in the binary (reserve them; also gives the sub_ set)
    cur_name = {a: n for a, n in db.execute("SELECT addr, name FROM func")}
    reserved = set(n for n in cur_name.values() if not n.startswith("sub_"))

    # exact-name prefixes: prefix -> set of distinct referencing functions
    pfx_funcs = {}
    for fa, pfx in db.execute("SELECT DISTINCT func_addr, pfx FROM strref WHERE is_logpfx=1 AND pfx IS NOT NULL"):
        if not re.match(exact_re, pfx):
            continue
        pfx_funcs.setdefault(pfx, set()).add(fa)

    # propose: a prefix referenced by exactly N<=max_shared functions, applied to its UNNAMED referencers
    proposals = {}   # addr -> (name, n_refs_of_prefix)
    for pfx, fas in pfx_funcs.items():
        if len(fas) > args.max_shared:
            continue  # shared across many functions => a domain tag, not an exact name
        for fa in fas:
            if not cur_name.get(fa, "").startswith("sub_"):
                continue  # already named
            # if a function already has a proposal, keep the prefix with the tightest (smallest) ref-set
            prev = proposals.get(fa)
            if prev is None or len(fas) < prev[1]:
                proposals[fa] = (pfx, len(fas))

    # de-duplicate proposed names against reserved + each other (BN tolerates dups, but keep them unique)
    used = set(reserved)
    final = {}
    for fa in sorted(proposals):
        nm = proposals[fa][0]
        cand = nm
        i = 2
        while cand in used:
            cand = "%s_%d" % (nm, i); i += 1
        used.add(cand)
        final[fa] = cand

    # domain tags for context comments (Pass-2 lite): addr -> sorted set of tags
    dom = {}
    for fa, tag in db.execute("SELECT DISTINCT func_addr, tag FROM domain"):
        dom.setdefault(fa, set()).add(tag)
    db.close()

    # merge into the sidecar
    side = {}
    if os.path.exists(args.sidecar):
        side = json.load(open(args.sidecar))
    side.setdefault("binary", os.path.splitext(os.path.basename(args.sidecar))[0])
    side.setdefault("types_c", "")
    fns = side.get("functions") or {}

    n_new = n_skip = 0
    for fa, nm in final.items():
        key = "0x%x" % fa
        ex = fns.get(key) or {}
        # only fill an empty/determ slot — never clobber a hand-authored or LLM (higher) name
        if ex.get("name") and ex.get("_source") not in (None, "determ-logstring"):
            n_skip += 1
            continue
        tags = sorted(dom.get(fa, []))
        comment = "[symbolicate Pass-1 / logstring] name recovered from this function's own log-prefix (VMware __FUNCTION__ convention)."
        if tags:
            comment += " domain: " + ", ".join(tags) + "."
        ex.update({"name": nm, "comment": comment, "_source": "determ-logstring", "_confidence": "high"})
        fns[key] = ex
        n_new += 1
    side["functions"] = fns
    with open(args.sidecar, "w") as fh:
        json.dump(side, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("[determ] exact-name prefixes considered: %d  (<= %d referencers)" % (len(pfx_funcs), args.max_shared))
    print("[determ] named %d function(s) (high confidence); %d kept (already higher-confidence)" % (n_new, n_skip))
    print("[determ] sidecar -> %s  (%d functions total)" % (args.sidecar, len(fns)))
    ex = sorted(final.items())[:12]
    for fa, nm in ex:
        print("   0x%x  ->  %s" % (fa, nm))


if __name__ == "__main__":
    main()
