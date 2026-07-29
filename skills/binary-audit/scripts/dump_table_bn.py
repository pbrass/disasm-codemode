#!/usr/bin/env python3
"""dump_table_bn.py - dump a BNDB pointer/dispatch table with resolved names.

Use this when a stripped/recovered binary reaches handlers through a data table
instead of direct call edges. It reads fixed-stride entries from an open BN view,
resolves pointer fields to function/symbol names, and optionally writes JSON.
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm


BODY = r'''
import json as _json
_addr = int(_addr)
_count = int(_count)
_stride = int(_stride)
_ptr_off = int(_ptr_off)
_flag_off = int(_flag_off)
_entries = []
for _i in range(_count):
    _slot = _addr + (_i * _stride)
    _raw = _bv.read(_slot, _stride)
    if _raw is None or len(_raw) < _stride:
        _entries.append({"index": _i, "addr": "0x%x" % _slot, "error": "short-read"})
        continue
    _entry = {"index": _i, "addr": "0x%x" % _slot}
    if _ptr_off >= 0 and _ptr_off + 8 <= len(_raw):
        _val = int.from_bytes(_raw[_ptr_off:_ptr_off+8], "little")
        _entry["ptr"] = "0x%x" % _val
        _fn = _bv.get_function_at(_val)
        if _fn is not None:
            _entry["name"] = _fn.name
        else:
            _sym = _bv.get_symbol_at(_val)
            if _sym is not None:
                _entry["name"] = _sym.full_name
    if _flag_off >= 0 and _flag_off + 8 <= len(_raw):
        _entry["flag64"] = int.from_bytes(_raw[_flag_off:_flag_off+8], "little")
    _crefs = []
    try:
        for _r in _bv.get_code_refs(_slot):
            _crefs.append({
                "addr": "0x%x" % _r.address,
                "function": _r.function.name if _r.function is not None else None,
            })
    except Exception:
        pass
    if _crefs:
        _entry["code_refs"] = _crefs[:16]
    _entries.append(_entry)
print(_json.dumps(_entries, indent=2))
'''


def main():
    ap = argparse.ArgumentParser(description="Dump a fixed-stride pointer table from an open BNDB.")
    bncm.add_target_args(ap)
    ap.add_argument("--addr", required=True, help="table start address")
    ap.add_argument("--count", type=int, default=64)
    ap.add_argument("--stride", type=int, default=16)
    ap.add_argument("--ptr-off", type=int, default=0, help="pointer field offset in each entry; -1 disables")
    ap.add_argument("--flag-off", type=int, default=8, help="64-bit flag/value field offset in each entry; -1 disables")
    ap.add_argument("--out", help="optional JSON output path")
    args = ap.parse_args()
    if args.count <= 0 or args.stride <= 0:
        raise SystemExit("--count and --stride must be positive")
    if args.count > 10000:
        raise SystemExit("--count too large")
    params = bncm.target_params(args)
    params.update({
        "_addr": bncm.vaddr(args.addr),
        "_count": args.count,
        "_stride": args.stride,
        "_ptr_off": args.ptr_off,
        "_flag_off": args.flag_off,
    })
    code = "".join("%s = %s\n" % (k, bncm.pylit(v)) for k, v in params.items())
    code += bncm.SELECT_BV + "\n" + BODY
    res = bncm.execute(code)
    out = bncm.scrub(res.get("output") or "")
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out)
    print(out, end="" if out.endswith("\n") else "\n")
    if res.get("error"):
        print("\n[ERROR]\n" + bncm.scrub(res["error"]), file=sys.stderr)
        sys.exit(1)
    if res.get("timed_out"):
        print("[TIMED OUT]", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
