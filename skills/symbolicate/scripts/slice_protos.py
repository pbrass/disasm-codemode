#!/usr/bin/env python3
"""slice_protos.py - build small reviewed prototype sidecars from a review queue.

Consumes bn-sym-review-protos JSON output, classifies clean parsed prototypes
into a conservative "boring_safe" tier, and writes a tiny sidecar containing
only the selected prototypes. This helper does not apply anything to Binary
Ninja.

  bn-sym-slice-protos i_vmx_full.sidecar.json proto_review.clean_parse.json \
      --queue-out proto_slices/boring_safe.queue.json \
      --sidecar-out proto_slices/boring_safe.001.sidecar.json --limit 50

  bn-sym-slice-protos i_vmx_full.sidecar.json proto_review.clean_parse.json \
      --queue-out proto_slices/boring_safe.queue.json \
      --sidecar-out proto_slices/manual_review.001.sidecar.json \
      --select-tier needs_manual --allow-reasons too_many_void_ptrs,too_many_pointers,pointer_to_pointer,too_many_params \
      --addr-list 0x1234,0x5678
"""
import argparse
import json
import re
from pathlib import Path


ALLOWED_TYPE_TOKENS = {
    "bool", "char", "const", "double", "float", "int", "int8_t", "int16_t",
    "int32_t", "int64_t", "intptr_t", "long", "restrict", "short",
    "signed", "size_t", "ssize_t", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "uintptr_t", "unsigned", "void", "volatile",
}


def _load_json(path):
    return json.loads(Path(path).read_text())


def _write_json(path, data):
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n")


def _split_csv(value):
    if not value:
        return []
    return [p for p in re.split(r"[\s,]+", value.strip()) if p]


def _load_addr_list(value):
    if not value:
        return None
    if re.search(r"[\s,]", value) or len(value) > 240:
        text = value
    else:
        path = Path(value)
        text = path.read_text() if path.exists() else value
    addrs = []
    for item in _split_csv(text):
        try:
            addrs.append("0x%x" % int(item, 16))
        except Exception as exc:
            raise SystemExit("bad address in --addr-list: %r (%s)" % (item, exc))
    return set(addrs)


def _base_name(name):
    return re.sub(r"_\d+$", "", name or "")


def _func_name(proto):
    matches = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", proto or "")
    return matches[-1] if matches else ""


def _signature_parts(proto):
    m = re.match(r"\s*(.*?)\b([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*;?\s*$", proto or "")
    if not m:
        return "", "", []
    ret = m.group(1).strip()
    name = m.group(2)
    params = m.group(3).strip()
    if not params or params == "void":
        return ret, name, []
    return ret, name, [p.strip() for p in params.split(",")]


def _strip_param_name(param):
    p = re.sub(r"\[[^\]]*\]", "", param or "").strip()
    tokens = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", p)
    if not tokens:
        return p
    last = tokens[-1]
    if last not in ALLOWED_TYPE_TOKENS:
        # Drop the final identifier as the parameter name.
        return re.sub(r"\b%s\b\s*$" % re.escape(last), "", p).strip()
    return p


def _type_tokens(ret, params):
    chunks = [ret] + [_strip_param_name(p) for p in params]
    toks = []
    for chunk in chunks:
        toks.extend(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", chunk))
    return toks


def _classify(row, args):
    proto = row.get("proto") or ""
    name = row.get("name") or ""
    reasons = []

    if row.get("queue") and row.get("queue") != "clean_parse":
        reasons.append("not_clean_parse")
    if row.get("parse_status") and row.get("parse_status") != "parse_ok":
        reasons.append("not_parse_ok")
    if row.get("text_flags"):
        reasons.append("text_flags")

    ret, pname, params = _signature_parts(proto)
    if not ret or not pname:
        reasons.append("unparsed_signature")
    if pname and pname not in {name, _base_name(name)}:
        reasons.append("prototype_name_mismatch")
    if len(params) > args.max_params:
        reasons.append("too_many_params")
    if "**" in proto:
        reasons.append("pointer_to_pointer")

    ptr_count = proto.count("*")
    void_ptr_count = len(re.findall(r"\bvoid\s*\*", proto))
    if ptr_count > args.max_pointers:
        reasons.append("too_many_pointers")
    if void_ptr_count > args.max_void_ptrs:
        reasons.append("too_many_void_ptrs")
    if re.search(r"\bstruct\b|\benum\b|\bunion\b", proto):
        reasons.append("custom_type")

    bad_tokens = sorted({t for t in _type_tokens(ret, params) if t not in ALLOWED_TYPE_TOKENS})
    if bad_tokens:
        reasons.append("custom_type:" + ",".join(bad_tokens[:6]))

    return "boring_safe" if not reasons else "needs_manual", reasons


def main():
    ap = argparse.ArgumentParser(description="Slice reviewed prototypes into conservative application batches.")
    ap.add_argument("sidecar", help="original symbolication sidecar JSON")
    ap.add_argument("review_queue", help="clean_parse JSON from bn-sym-review-protos")
    ap.add_argument("--queue-out", required=True, help="write classified queue JSON")
    ap.add_argument("--sidecar-out", required=True, help="write filtered sidecar for selected boring_safe prototypes")
    ap.add_argument("--limit", type=int, default=50, help="max prototypes to include in sidecar batch")
    ap.add_argument("--offset", type=int, default=0, help="offset within boring_safe queue")
    ap.add_argument("--max-params", type=int, default=5)
    ap.add_argument("--max-pointers", type=int, default=2)
    ap.add_argument("--max-void-ptrs", type=int, default=1)
    ap.add_argument("--select-tier", default="boring_safe", choices=["boring_safe", "needs_manual", "all"],
                    help="classified tier to select from when --addr-list is not used (default boring_safe)")
    ap.add_argument("--allow-reasons", default="",
                    help="comma/space list; for manual tiers, require reject reasons to be a subset of these")
    ap.add_argument("--exclude-reasons", default="",
                    help="comma/space list; reject rows containing any listed reason")
    ap.add_argument("--addr-list",
                    help="comma/space separated addresses, or a file containing them; selected in queue order")
    args = ap.parse_args()

    side = _load_json(args.sidecar)
    review = _load_json(args.review_queue)
    funcs = side.get("functions") or {}

    classified = []
    for row in review:
        rec = dict(row)
        tier, reasons = _classify(row, args)
        rec["proto_tier"] = tier
        rec["proto_reject_reasons"] = reasons
        classified.append(rec)

    allow_reasons = set(_split_csv(args.allow_reasons))
    exclude_reasons = set(_split_csv(args.exclude_reasons))
    addr_filter = _load_addr_list(args.addr_list)

    def selected_by_filters(row):
        if addr_filter is not None:
            return row["addr"].lower() in addr_filter
        if args.select_tier != "all" and row["proto_tier"] != args.select_tier:
            return False
        reasons = set(row["proto_reject_reasons"])
        if allow_reasons and not reasons <= allow_reasons:
            return False
        if exclude_reasons and reasons & exclude_reasons:
            return False
        return True

    boring = [r for r in classified if r["proto_tier"] == "boring_safe"]
    queue = [r for r in classified if selected_by_filters(r)]
    selected = queue[args.offset:args.offset + args.limit]

    out_sidecar = {
        "binary": side.get("binary", ""),
        "functions": {},
        "_meta": {
            "source_sidecar": str(args.sidecar),
            "source_review_queue": str(args.review_queue),
            "proto_filter": {
                "tier": args.select_tier,
                "offset": args.offset,
                "limit": args.limit,
                "max_params": args.max_params,
                "max_pointers": args.max_pointers,
                "max_void_ptrs": args.max_void_ptrs,
                "allow_reasons": sorted(allow_reasons),
                "exclude_reasons": sorted(exclude_reasons),
                "addr_list_count": len(addr_filter) if addr_filter is not None else 0,
            },
        },
    }
    for row in selected:
        addr = row["addr"]
        src = funcs.get(addr) or {}
        out_sidecar["functions"][addr] = {
            "name": src.get("name") or row.get("name", ""),
            "proto": src.get("proto") or row.get("proto", ""),
        }

    _write_json(args.queue_out, classified)
    _write_json(args.sidecar_out, out_sidecar)

    print("[proto-slice] wrote queue %s" % args.queue_out)
    print("[proto-slice] wrote sidecar %s" % args.sidecar_out)
    print("[proto-slice] clean=%d boring_safe=%d needs_manual=%d queue=%d selected=%d offset=%d limit=%d" % (
        len(review), len(boring), len(classified) - len(boring), len(queue), len(selected), args.offset, args.limit))
    reasons = {}
    for row in classified:
        for reason in row["proto_reject_reasons"]:
            reasons[reason] = reasons.get(reason, 0) + 1
    print("[proto-slice] reject_reasons=%s" % dict(sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:40]))


if __name__ == "__main__":
    main()
