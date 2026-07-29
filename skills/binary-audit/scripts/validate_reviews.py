#!/usr/bin/env python3
"""Validate and summarize Stage-2 review output before ingest.

This is intentionally read-only. It accepts either a clean JSON array or a
workflow/log wrapper containing the first JSON array of records.
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


ALLOWED_VERDICTS = {"clean", "needs-caller-analysis", "suspicious", "bug"}
ALLOWED_KINDS = {
    "len-bound",
    "no-overflow",
    "nonnull",
    "range",
    "signed",
    "lock",
    "lifetime",
    "state",
    "field-consistency",
}
ALLOWED_KLASSES = {"self", "caller", "unguaranteed"}
ALLOWED_CONFIDENCE = {"low", "med", "high"}
ALLOWED_BUG_CLASSES = {
    "oob",
    "int-overflow",
    "double-fetch",
    "uaf-lifetime",
    "uninit-disclosure",
    "race",
    "type-confusion",
    "other",
}


def load_records(path):
    raw = Path(path).read_text()
    try:
        value = json.loads(raw)
    except Exception:
        value = None
    if isinstance(value, list):
        return value
    m = re.search(r"\[\s*\{.*\}\s*\]", raw, re.S)
    if not m:
        raise ValueError("could not find a JSON record array")
    value = json.loads(m.group(0))
    if not isinstance(value, list):
        raise ValueError("parsed JSON is not an array")
    return value


def load_assigned(workflow_path):
    raw = Path(workflow_path).read_text()
    m = re.search(r"const\s+FNS\s*=\s*(\[[^\n]*\])", raw)
    if not m:
        raise ValueError("could not find single-line const FNS = [...] in workflow")
    fns = json.loads(m.group(1))
    return [f["name"] for f in fns if isinstance(f, dict) and f.get("name")]


def require_field(obj, field, owner, errors):
    if field not in obj or obj[field] in (None, ""):
        errors.append(f"{owner}: missing {field}")


def main():
    ap = argparse.ArgumentParser(description="Validate Stage-2 review JSON before ingest.")
    ap.add_argument("review_json", help="combined review JSON or workflow output")
    ap.add_argument("--workflow", help="review-wf-bN.js to check assigned-vs-returned")
    ap.add_argument("--strict-low", action="store_true",
                    help="treat low-confidence suspected bugs as errors")
    args = ap.parse_args()

    errors = []
    warnings = []
    records = load_records(args.review_json)

    names = []
    verdicts = Counter()
    bug_counts = Counter()
    preconditions = 0
    for idx, rec in enumerate(records):
        owner = f"record[{idx}]"
        if not isinstance(rec, dict):
            errors.append(f"{owner}: not an object")
            continue
        require_field(rec, "function", owner, errors)
        name = rec.get("function", f"<record {idx}>")
        names.append(name)
        verdict = rec.get("verdict")
        if verdict not in ALLOWED_VERDICTS:
            errors.append(f"{name}: invalid verdict {verdict!r}")
        else:
            verdicts[verdict] += 1
        require_field(rec, "summary", name, errors)
        if not isinstance(rec.get("preconditions", []), list):
            errors.append(f"{name}: preconditions is not an array")
        for pidx, pre in enumerate(rec.get("preconditions") or []):
            preconditions += 1
            if not isinstance(pre, dict):
                errors.append(f"{name}: precondition[{pidx}] not an object")
                continue
            for field in ("text", "kind", "klass"):
                require_field(pre, field, f"{name}: precondition[{pidx}]", errors)
            if pre.get("kind") not in ALLOWED_KINDS:
                errors.append(f"{name}: invalid precondition kind {pre.get('kind')!r}")
            if pre.get("klass") not in ALLOWED_KLASSES:
                errors.append(f"{name}: invalid precondition klass {pre.get('klass')!r}")
        if not isinstance(rec.get("suspected_bugs", []), list):
            errors.append(f"{name}: suspected_bugs is not an array")
        for bidx, bug in enumerate(rec.get("suspected_bugs") or []):
            if not isinstance(bug, dict):
                errors.append(f"{name}: bug[{bidx}] not an object")
                continue
            for field in ("desc", "location", "confidence", "bug_class"):
                require_field(bug, field, f"{name}: bug[{bidx}]", errors)
            if bug.get("confidence") not in ALLOWED_CONFIDENCE:
                errors.append(f"{name}: invalid bug confidence {bug.get('confidence')!r}")
            if bug.get("bug_class") not in ALLOWED_BUG_CLASSES:
                errors.append(f"{name}: invalid bug_class {bug.get('bug_class')!r}")
            bug_counts[(bug.get("confidence", ""), bug.get("bug_class", ""))] += 1
            if bug.get("confidence") == "low":
                msg = f"{name}: low-confidence suspected bug should usually be a precondition, not an open bug"
                (errors if args.strict_low else warnings).append(msg)
            if not (bug.get("why") or "").strip():
                warnings.append(f"{name}: suspected bug has no why/evidence text")
            loc = bug.get("location") or ""
            if "HLIL" not in loc and "ASM" not in loc and "0x" not in loc:
                warnings.append(f"{name}: suspected bug location is not anchored to HLIL/ASM")

    duplicates = [name for name, count in Counter(names).items() if count > 1]
    for name in duplicates:
        errors.append(f"duplicate review record for {name}")

    missing = []
    extra = []
    if args.workflow:
        assigned = load_assigned(args.workflow)
        assigned_set = set(assigned)
        returned_set = set(names)
        missing = [name for name in assigned if name not in returned_set]
        extra = [name for name in names if name not in assigned_set]
        for name in missing:
            errors.append(f"assigned function missing from review output: {name}")
        for name in extra:
            warnings.append(f"review output has function not present in workflow: {name}")

    print(f"records={len(records)} preconditions={preconditions} suspected_bugs={sum(bug_counts.values())}")
    if verdicts:
        print("verdicts=" + ", ".join(f"{k}:{verdicts[k]}" for k in sorted(verdicts)))
    if bug_counts:
        print("bugs=" + ", ".join(f"{conf}/{klass}:{count}" for (conf, klass), count in sorted(bug_counts.items())))
    if args.workflow:
        print(f"assigned_missing={len(missing)} extra={len(extra)}")
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
