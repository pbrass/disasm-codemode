#!/usr/bin/env python3
"""split_batch.py - split a prepared symbolication batch into fanout shards.

The splitter is intentionally dumb: it preserves input record order within each
tier and writes files named <prefix>.<tier>.<NN>.json. Use it for Codex/agent
fanout when the Workflow-based per-function runner is not the right surface.

  bn-sym-split second_pass1.json --out-dir codex_second_pass1/chunks
"""
import argparse
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description="Split a prepared symbolication batch into tiered chunks.")
    ap.add_argument("batch", help="prepared batch JSON")
    ap.add_argument("--out-dir", required=True, help="directory for chunk JSON files")
    ap.add_argument("--prefix", help="chunk filename prefix; defaults to input stem")
    ap.add_argument("--sonnet-size", type=int, default=100)
    ap.add_argument("--haiku-size", type=int, default=100)
    ap.add_argument("--default-size", type=int, default=100)
    args = ap.parse_args()

    src = Path(args.batch)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = args.prefix or src.stem

    records = json.loads(src.read_text())
    if not isinstance(records, list):
        raise SystemExit("batch must be a JSON array")

    by_tier = {}
    for rec in records:
        if not isinstance(rec, dict):
            raise SystemExit("batch records must be JSON objects")
        tier = rec.get("tier") or "sonnet"
        by_tier.setdefault(tier, []).append(rec)

    written = 0
    for tier in sorted(by_tier):
        recs = by_tier[tier]
        size = args.haiku_size if tier == "haiku" else args.sonnet_size if tier == "sonnet" else args.default_size
        if size <= 0:
            raise SystemExit("chunk sizes must be positive")
        for idx in range(0, len(recs), size):
            chunk = recs[idx:idx + size]
            path = out_dir / ("%s.%s.%02d.json" % (prefix, tier, idx // size + 1))
            path.write_text(json.dumps(chunk, indent=2) + "\n")
            print("%s %d" % (path, len(chunk)))
            written += 1
    print("[split] wrote %d chunk(s) from %d record(s)" % (written, len(records)))


if __name__ == "__main__":
    main()
