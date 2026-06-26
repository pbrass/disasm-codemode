#!/usr/bin/env python3
"""review_protos.py - classify and parse-test recovered sidecar prototypes.

This is a review-only helper. It reads sidecar prototypes, applies conservative
text-quality filters, optionally parse-tests the survivors in Binary Ninja with
parse_type_string(), and writes JSON review queues. It never mutates the
sidecar and never assigns function types in BN.

  bn-sym-review-protos i_vmx_full.sidecar.json --bv-match i_vmx_full \
      --out proto_review/all.json --clean-out proto_review/clean_parse.json
"""
import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm


CONF_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
PROBLEM_KEYWORD_PARAMS = {"namespace", "class", "private"}


PARSE_BODY = r'''
import json, collections
_rows = json.loads(_rows_json)
_errs = []
_counts = collections.Counter()
for _row in _rows:
    _addr = _row.get("addr")
    _proto = _row.get("proto") or ""
    try:
        _bv.parse_type_string(_proto)
        _counts["parse_ok"] += 1
    except Exception as _e:
        _msg = str(_e)
        if "unknown type name" in _msg or "Reference to unknown type" in _msg or "Referencing unknown structure type" in _msg:
            _st = "unknown_type"
        else:
            _st = "parse_error"
        _counts[_st] += 1
        _errs.append({"addr": _addr, "parse_status": _st, "parse_error": _msg[:800]})
print("[proto-review-parse] " + json.dumps({"counts": dict(_counts), "errors": _errs}, sort_keys=True))
'''


def _confidence_at_least(value, minimum):
    return CONF_ORDER.get((value or "").lower(), 0) >= CONF_ORDER.get(minimum, 3)


def _proto_function_name(proto):
    matches = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", proto or "")
    return matches[-1] if matches else ""


def _base_name(name):
    return re.sub(r"_\d+$", "", name or "")


def _param_names(proto):
    m = re.search(r"\((.*)\)", proto or "")
    if not m:
        return []
    params = m.group(1)
    if params.strip() in ("", "void"):
        return []
    names = []
    for part in params.split(","):
        part = part.strip()
        if not part or part == "...":
            continue
        part = re.sub(r"\[[^\]]*\]", "", part)
        tokens = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", part)
        if tokens:
            names.append(tokens[-1])
    return names


def _text_flags(proto, max_void_ptrs):
    p = proto or ""
    flags = []
    checks = [
        ("placeholder_qmark", r"\?"),
        ("varargs_ellipsis", r"\.\.\."),
        ("function_pointer", r"\(\*"),
        ("callback_guess", r"\b(callback|Callback|callback_fn|callback_t|VigorCallback)\b"),
        ("vague_param_name", r"\b(unused\d*|reserved|unknown|mystery)\b"),
        ("nonstandard_int_alias", r"\b(int32|uint32|int64|uint64)\b"),
        ("embedded_comment", r"/\*|//"),
        ("non_ascii", r"[^\x00-\x7f]"),
    ]
    for name, rx in checks:
        if re.search(rx, p, re.I):
            flags.append(name)
    param_names = _param_names(p)
    if any(re.search(r"(^arg$)|(^arg\d+($|_))|(_arg\d+($|_))|(^param\d+$)|(_param\d+($|_))|^(unused\d*|reserved|unknown|mystery)$", n, re.I)
           for n in param_names):
        if "vague_param_name" not in flags:
            flags.append("vague_param_name")
    if not p.rstrip().endswith(";"):
        flags.append("missing_semicolon")
    if p.count("void *") + p.count("void*") >= max_void_ptrs:
        flags.append("many_void_ptrs")
    bad_keywords = sorted({name for name in param_names if name in PROBLEM_KEYWORD_PARAMS})
    if bad_keywords:
        flags.append("keyword_param:" + ",".join(bad_keywords[:5]))
    return flags


def _review_flags(addr, name, proto):
    flags = []
    pname = _proto_function_name(proto)
    if pname and pname not in {name, _base_name(name)}:
        flags.append("prototype_name_mismatch:%s" % pname)
    if re.search(r"\bstruct\s+[A-Za-z_][A-Za-z0-9_]*\s*\*", proto or ""):
        flags.append("custom_struct_pointer")
    return flags


def _load_records(sidecar, min_conf, max_void_ptrs):
    side = json.loads(Path(sidecar).read_text())
    rows = []
    for addr, rec in sorted((side.get("functions") or {}).items(), key=lambda item: int(item[0], 16)):
        proto = (rec.get("proto") or "").strip()
        if not proto:
            continue
        confidence = (rec.get("_confidence") or "").lower()
        text_flags = _text_flags(proto, max_void_ptrs)
        review_flags = _review_flags(addr, rec.get("name") or "", proto)
        rows.append({
            "addr": addr,
            "name": rec.get("name") or "",
            "confidence": confidence,
            "source": rec.get("_source") or "",
            "proto": proto,
            "text_flags": text_flags,
            "review_flags": review_flags,
            "parse_status": "not_tested",
            "parse_error": "",
            "queue": "text_rejected" if text_flags or not _confidence_at_least(confidence, min_conf) else "needs_parse",
        })
    return rows


def _parse_test(rows, args):
    candidates = [r for r in rows if r["queue"] == "needs_parse"]
    if not candidates:
        return
    if not args.bv_match and not args.file:
        return
    payload = json.dumps([{"addr": r["addr"], "proto": r["proto"]} for r in candidates])
    output = _bn_capture(PARSE_BODY, _rows_json=payload, **bncm.target_params(args))
    marker = "[proto-review-parse] "
    parsed = None
    for line in output.splitlines():
        if marker in line:
            parsed = json.loads(line.split(marker, 1)[1])
    if parsed is None:
        raise SystemExit("BN parse-test did not return parse results")
    by_addr = {item["addr"]: item for item in parsed.get("errors") or []}
    for row in rows:
        if row["queue"] != "needs_parse":
            continue
        item = by_addr.get(row["addr"])
        if not item:
            row["parse_status"] = "parse_ok"
            row["parse_error"] = ""
            row["queue"] = "clean_parse"
            continue
        row["parse_status"] = item.get("parse_status") or "parse_error"
        row["parse_error"] = item.get("parse_error") or ""
        if row["parse_status"] == "unknown_type":
            row["queue"] = "needs_type_stub_review"
        else:
            row["queue"] = "parse_rejected"


def _bn_capture(body, **params):
    prologue = "".join("%s = %s\n" % (k, bncm.pylit(v)) for k, v in params.items())
    inner = bncm.SELECT_BV + body
    indented = "\n".join(("    " + ln) if ln.strip() else ln for ln in inner.split("\n"))
    res = bncm.execute(prologue + "try:\n" + indented + "\nexcept SystemExit:\n    pass\n")
    out = bncm.scrub(res.get("output") or "")
    if res.get("error"):
        sys.stderr.write("[BN ERROR]\n" + bncm.scrub(res["error"]) + "\n")
        sys.exit(1)
    if res.get("timed_out"):
        sys.stderr.write("[BN TIMED OUT] (large binary? raise BINJA_HTTP_TIMEOUT or use --bv-match)\n")
        sys.exit(1)
    return out


def _write_json(path, data):
    if not path:
        return
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n")


def _write_summary(path, rows, clean):
    if not path:
        return
    queue_counts = collections.Counter(r["queue"] for r in rows)
    conf_counts = collections.Counter(r["confidence"] for r in rows)
    flag_counts = collections.Counter(flag.split(":", 1)[0] for r in rows for flag in r["text_flags"])
    parse_counts = collections.Counter(r["parse_status"] for r in rows)
    lines = [
        "# Prototype Review Summary",
        "",
        "## Counts",
        "",
        "- Total prototypes: %d" % len(rows),
        "- Confidence: %s" % dict(sorted(conf_counts.items())),
        "- Queues: %s" % dict(sorted(queue_counts.items())),
        "- Parse status: %s" % dict(sorted(parse_counts.items())),
        "- Clean parsed prototypes: %d" % len(clean),
        "",
        "## Text Rejection Flags",
        "",
    ]
    for flag, count in flag_counts.most_common():
        lines.append("- %s: %d" % (flag, count))
    lines += ["", "## Clean Parse Samples", ""]
    for row in clean[:50]:
        lines.append("- `%s` `%s`: `%s`" % (row["addr"], row["name"], row["proto"]))
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Review recovered sidecar prototypes without applying them.")
    ap.add_argument("sidecar", help="sidecar JSON containing recovered prototypes")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--file", help="path to a binary to load for BN parse_type_string checks")
    g.add_argument("--bv-match", help="open BN tab substring to use for BN parse_type_string checks")
    ap.add_argument("--out", required=True, help="write full classified review JSON")
    ap.add_argument("--clean-out", help="write clean parse queue JSON")
    ap.add_argument("--summary-out", help="write a Markdown summary")
    ap.add_argument("--min-confidence", default="high", choices=["low", "medium", "high"],
                    help="minimum confidence to consider for clean queue (default high)")
    ap.add_argument("--max-void-ptrs", type=int, default=4,
                    help="reject prototypes with this many or more void* parameters/fragments (default 4)")
    args = ap.parse_args()

    rows = _load_records(args.sidecar, args.min_confidence, args.max_void_ptrs)
    _parse_test(rows, args)
    clean = [r for r in rows if r["queue"] == "clean_parse"]
    _write_json(args.out, rows)
    _write_json(args.clean_out, clean)
    _write_summary(args.summary_out, rows, clean)

    queue_counts = collections.Counter(r["queue"] for r in rows)
    conf_counts = collections.Counter(r["confidence"] for r in rows)
    parse_counts = collections.Counter(r["parse_status"] for r in rows)
    flag_counts = collections.Counter(flag.split(":", 1)[0] for r in rows for flag in r["text_flags"])
    print("[proto-review] wrote %s" % args.out)
    if args.clean_out:
        print("[proto-review] clean_out %s" % args.clean_out)
    if args.summary_out:
        print("[proto-review] summary_out %s" % args.summary_out)
    print("[proto-review] total=%d confidence=%s" % (len(rows), dict(sorted(conf_counts.items()))))
    print("[proto-review] queues=%s" % dict(sorted(queue_counts.items())))
    print("[proto-review] parse=%s" % dict(sorted(parse_counts.items())))
    print("[proto-review] text_flags=%s" % dict(flag_counts.most_common()))


if __name__ == "__main__":
    main()
