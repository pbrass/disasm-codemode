#!/usr/bin/env python3
"""ingest.py — fold the naming workflow's output ({addr,name,comment,confidence,proto}) into the re_sync
sidecar (merge). LLM names fill empty or determ slots and are marked _source=llm with their confidence; a
hand-authored or already-LLM-high entry is never clobbered by a lower-confidence proposal.

  bn-sym-ingest <workflow-output.json> --sidecar phil_notes/vmx-re/i_vmx_full.sidecar.json
Tolerant of wrapper formats: finds the first JSON array of records in the file.
Then sync: bn-re-apply <sidecar> --bv-match i_vmx_full   (Ctrl+S).
"""
import sys, os, json, re, argparse

RANK = {"high": 3, "medium": 2, "low": 1, None: 0, "": 0}


def main():
    ap = argparse.ArgumentParser(description="Ingest naming-workflow output into the re_sync sidecar.")
    ap.add_argument("output", help="workflow output JSON (array of {addr,name,comment,confidence,proto})")
    ap.add_argument("--sidecar", required=True)
    args = ap.parse_args()
    raw = open(args.output).read()
    recs = None
    try:
        recs = json.loads(raw)
    except Exception:
        m = re.search(r"\[\s*\{.*\}\s*\]", raw, re.S)
        if m:
            recs = json.loads(m.group(0))
    if not isinstance(recs, list):
        print("could not parse records array"); sys.exit(1)

    side = {}
    if os.path.exists(args.sidecar):
        side = json.load(open(args.sidecar))
    side.setdefault("binary", os.path.splitext(os.path.basename(args.sidecar))[0])
    side.setdefault("types_c", "")
    fns = side.get("functions") or {}

    n = skip = abstain = 0
    used = set(f.get("name") for f in fns.values() if isinstance(f, dict) and f.get("name"))
    for r in recs:
        if not isinstance(r, dict) or not r.get("addr"):
            continue
        # ABSTENTION: empty name or confidence 'none' -> leave unnamed (revisited in a later propagation pass)
        if not r.get("name") or (r.get("confidence") or "").lower() == "none":
            abstain += 1
            continue
        a = r["addr"] if isinstance(r["addr"], str) and r["addr"].startswith("0x") else ("0x%x" % int(r["addr"]))
        ex = fns.get(a) or {}
        conf = (r.get("confidence") or "low").lower()
        # don't downgrade a hand-authored or a higher/equal-confidence existing entry
        if ex.get("name") and ex.get("_source") in (None, "hand") :
            skip += 1; continue
        if ex.get("name") and RANK.get(ex.get("_confidence"), 0) >= RANK.get(conf, 0) and ex.get("_source") == "llm":
            skip += 1; continue
        nm = r["name"]
        cand = nm; i = 2
        while cand in used and cand != ex.get("name"):
            cand = "%s_%d" % (nm, i); i += 1
        used.add(cand)
        ex["name"] = cand
        if r.get("comment"):
            ex["comment"] = r["comment"]
        if r.get("proto"):
            ex["proto"] = r["proto"]
        ex["_source"] = "llm"; ex["_confidence"] = conf
        fns[a] = ex
        n += 1
    side["functions"] = fns
    with open(args.sidecar, "w") as fh:
        json.dump(side, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print("[ingest] merged %d name(s); %d abstained (revisit in a later pass); %d skipped (already >= confidence); sidecar has %d functions" % (n, abstain, skip, len(fns)))


if __name__ == "__main__":
    main()
