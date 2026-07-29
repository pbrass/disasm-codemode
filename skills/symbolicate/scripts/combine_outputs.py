#!/usr/bin/env python3
"""combine_outputs.py - validate and combine fanout symbolication outputs.

Validates each result file against its input chunk, normalizes addr/tier from
the chunk, clears fields for abstentions, optionally applies manual addr->name
renames, and reports duplicates/suspicious names/prototype counts before ingest.

  bn-sym-combine --chunks codex_second_pass1/chunks \
      --results codex_second_pass1/results --out second_pass1.codex.combined.json
"""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

KEYS = ["addr", "tier", "name", "confidence", "comment", "proto"]
VALID_CONF = {"high", "medium", "low", "none"}


def _load_renames(pairs, path):
    renames = {}
    if path:
        data = json.loads(Path(path).read_text())
        if not isinstance(data, dict):
            raise SystemExit("--rename-json must be an object mapping addr to name")
        renames.update({str(k): str(v) for k, v in data.items()})
    for item in pairs or []:
        if "=" not in item:
            raise SystemExit("--rename values must look like 0xADDR=Name")
        addr, name = item.split("=", 1)
        renames[addr.strip()] = name.strip()
    return renames


def _result_path(results_dir, chunk_path, suffix):
    return results_dir / (chunk_path.stem + suffix)


def main():
    ap = argparse.ArgumentParser(description="Validate/combine fanout symbolication outputs.")
    ap.add_argument("--chunks", required=True, help="directory containing input chunk JSON files")
    ap.add_argument("--results", required=True, help="directory containing result JSON files")
    ap.add_argument("--out", required=True, help="combined output JSON for bn-sym-ingest")
    ap.add_argument("--chunk-glob", default="*.json")
    ap.add_argument("--result-suffix", default=".out.json")
    ap.add_argument("--rename", action="append", help="manual addr->name override, e.g. 0x123=Module_Name")
    ap.add_argument("--rename-json", help="JSON object mapping addr strings to replacement names")
    ap.add_argument("--strict", action="store_true", help="exit nonzero on validation errors")
    args = ap.parse_args()

    chunks_dir = Path(args.chunks)
    results_dir = Path(args.results)
    renames = _load_renames(args.rename, args.rename_json)

    combined = []
    errors = []
    per_file = []
    normalized_tiers = 0

    for chunk_path in sorted(chunks_dir.glob(args.chunk_glob)):
        result_path = _result_path(results_dir, chunk_path, args.result_suffix)
        if not result_path.exists():
            errors.append("missing %s" % result_path)
            continue
        try:
            chunk = json.loads(chunk_path.read_text())
            result = json.loads(result_path.read_text())
        except Exception as exc:
            errors.append("%s: parse error: %s" % (result_path, exc))
            continue
        if not isinstance(chunk, list) or not isinstance(result, list):
            errors.append("%s: chunk/result must both be JSON arrays" % result_path)
            continue
        if len(chunk) != len(result):
            errors.append("%s: count %d != %d" % (result_path, len(result), len(chunk)))

        conf_count = Counter()
        named = 0
        for idx, (src, out) in enumerate(zip(chunk, result)):
            if not isinstance(src, dict) or not isinstance(out, dict):
                errors.append("%s[%d]: source/result records must be objects" % (result_path, idx))
                continue
            if out.get("addr") != src.get("addr"):
                errors.append("%s[%d]: addr %r != %r" % (result_path, idx, out.get("addr"), src.get("addr")))
            if out.get("tier") != src.get("tier"):
                normalized_tiers += 1

            rec = {key: out.get(key, "") for key in KEYS}
            rec["addr"] = src.get("addr", rec.get("addr", ""))
            rec["tier"] = src.get("tier", rec.get("tier", ""))

            conf = (rec.get("confidence") or "").lower()
            if conf not in VALID_CONF:
                errors.append("%s[%d]: bad confidence %r" % (result_path, idx, rec.get("confidence")))
                conf = "none"
            rec["confidence"] = conf

            if rec["confidence"] == "none" or not rec.get("name"):
                rec["confidence"] = "none"
                rec["name"] = ""
                rec["comment"] = ""
                rec["proto"] = ""
            elif rec["addr"] in renames:
                rec["name"] = renames[rec["addr"]]

            if rec.get("name"):
                named += 1
            conf_count[rec["confidence"]] += 1
            combined.append(rec)
        per_file.append((result_path.name, len(result), named, dict(conf_count)))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(combined, indent=2) + "\n")

    conf = Counter(rec.get("confidence") for rec in combined)
    named_total = sum(1 for rec in combined if rec.get("name"))
    dups = {name: count for name, count in Counter(rec["name"] for rec in combined if rec.get("name")).items() if count > 1}
    suspicious = []
    for rec in combined:
        name = rec.get("name") or ""
        if not name:
            continue
        if re.search(r"(?i)(maybe|possible|guess|sub_|nullsub|unnamed|wrapper_wrapper)", name):
            suspicious.append((rec["addr"], name, rec["confidence"]))
        elif re.search(r"(?i)(^|_)todo($|_)", name):
            suspicious.append((rec["addr"], name, rec["confidence"]))
        elif "unknown" in name.lower() and "unknownchunk" not in name.lower():
            suspicious.append((rec["addr"], name, rec["confidence"]))
        elif not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            suspicious.append((rec["addr"], name, rec["confidence"]))

    print("[combine] wrote %s" % out_path)
    print("[combine] total=%d named=%d abstained=%d confidence=%s" % (
        len(combined), named_total, conf.get("none", 0), dict(conf)))
    print("[combine] normalized_tiers=%d prototypes=%d" % (
        normalized_tiers, sum(1 for rec in combined if rec.get("proto"))))
    print("[combine] duplicate_groups=%d" % len(dups))
    for name, count in sorted(dups.items(), key=lambda item: (-item[1], item[0]))[:50]:
        print("DUP %d %s" % (count, name))
    print("[combine] suspicious=%d" % len(suspicious))
    for addr, name, confv in suspicious[:50]:
        print("SUSP %s %s %s" % (addr, name, confv))
    print("[combine] per_file")
    for row in per_file:
        print(row)
    print("[combine] errors=%d" % len(errors))
    for err in errors[:80]:
        print("ERR %s" % err)
    if args.strict and errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
