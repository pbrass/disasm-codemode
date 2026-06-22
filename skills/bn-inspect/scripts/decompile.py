#!/usr/bin/env python3
"""decompile.py - decompile ONE function to HLIL pseudo-C (the #1 BN code-mode task).

Resolve a function by name or address, print its HLIL (with caller list), optionally filter
to just the lines matching a regex (+context), and optionally append disassembly.

  decompile.py --file /tmp/vmdird VmDirMLBind
  decompile.py --file /tmp/vmdird --addr 0x532324 --grep 'sasl|SASLSession' --context 2
  decompile.py --bv-match wcpsvc 'main.handleLogin' --asm

Injection-safe: name/addr/regex are validated and embedded only as escaped literals (see bncm.py).
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bncm

BODY = r'''
fn = None
if _name:
    for f in _bv.functions:
        if f.name == _name:
            fn = f; break
    if fn is None:
        _near = []
        for f in _bv.functions:
            if _name in f.name:
                _near.append(f.name)
        _near = sorted(set(_near))[:12]
        print("[no function named %r]" % _name + ((" -- near: " + ", ".join(_near)) if _near else ""))
        raise SystemExit
else:
    fn = _bv.get_function_at(_addr)
    if fn is None:
        _cf = _bv.get_functions_containing(_addr) or []
        fn = _cf[0] if _cf else None
    if fn is None:
        print("[no function at 0x%x]" % _addr); raise SystemExit
_callers = sorted({c.name for c in fn.callers})
print("// %s @ 0x%x   bytes=%d   callers(%d): %s" % (fn.name, fn.start, fn.total_bytes, len(_callers), ", ".join(_callers[:24])))
_h = str(fn.hlil)
if _grep:
    _lines = _h.split("\n")
    _keep = set()
    _i = 0
    for _ln in _lines:
        if re.search(_grep, _ln):
            _lo = _i - _ctx
            if _lo < 0:
                _lo = 0
            _hi = _i + _ctx + 1
            if _hi > len(_lines):
                _hi = len(_lines)
            _k = _lo
            while _k < _hi:
                _keep.add(_k); _k += 1
        _i += 1
    if not _keep:
        print("[grep: no HLIL line matched %r]" % _grep)
    else:
        for _i in sorted(_keep):
            print("%5d| %s" % (_i, _lines[_i]))
else:
    print(_h[:_maxlen])
    if len(_h) > _maxlen:
        print("...[HLIL truncated: %d more bytes -- use --grep, raise --maxlen, or the bulk-decompile skill]" % (len(_h) - _maxlen))
if _asm:
    print("\n; ---- disassembly ----")
    _na = 0
    _stop = False
    for _bb in fn.basic_blocks:
        for _dt in _bb.get_disassembly_text():
            if _na >= _maxasm:
                print("; ...[asm truncated at %d lines]" % _maxasm); _stop = True; break
            print("%08x  %s" % (_dt.address, _dt)); _na += 1
        if _stop:
            break
'''


def main():
    ap = argparse.ArgumentParser(description="Decompile one function to HLIL via BN code-mode.")
    bncm.add_target_args(ap)
    ap.add_argument("name", nargs="?", help="exact function/symbol name")
    ap.add_argument("--addr", help="resolve by address instead (hex 0x.. or decimal)")
    ap.add_argument("--grep", help="show only HLIL lines matching this regex")
    ap.add_argument("--context", type=int, default=0, help="lines of context around --grep hits")
    ap.add_argument("--asm", action="store_true", help="also print disassembly")
    ap.add_argument("--maxlen", type=int, default=60000, help="max HLIL bytes to print (default 60000)")
    ap.add_argument("--maxasm", type=int, default=4000, help="max disassembly lines (default 4000)")
    a = ap.parse_args()
    if bool(a.name) == bool(a.addr):
        bncm.die("give exactly one of: a function name, or --addr")
    p = bncm.target_params(a)
    p["_name"] = bncm.vsym(a.name) if a.name else None
    p["_addr"] = bncm.vaddr(a.addr) if a.addr else None
    p["_grep"] = bncm.vregex(a.grep) if a.grep else None
    p["_ctx"] = max(0, min(a.context, 50))
    p["_asm"] = bool(a.asm)
    p["_maxlen"] = max(1000, min(a.maxlen, 95000))
    p["_maxasm"] = max(1, min(a.maxasm, 100000))
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
