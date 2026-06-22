#!/usr/bin/env python3
"""xrefs.py - callers, callees, and call-sites of a function/address (BN xref task).

  xrefs.py --file /tmp/vmdird VmDirSASLSessionStart       # who calls it / what it calls / call-sites
  xrefs.py --file /tmp/libsrp_live.so --addr 0x405e50 --callers

Injection-safe: name/addr are validated and embedded only as escaped literals (see bncm.py).
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
else:
    fn = _bv.get_function_at(_addr)
    if fn is None:
        _cf = _bv.get_functions_containing(_addr) or []
        fn = _cf[0] if _cf else None
if fn is None:
    print("[target function not found]"); raise SystemExit
print("# %s @ 0x%x" % (fn.name, fn.start))
if _want_callers:
    _cs = sorted({c.name for c in fn.callers})
    print("callers (%d): %s" % (len(_cs), ", ".join(_cs[:_limit])))
    print("call-sites to 0x%x:" % fn.start)
    _n = 0
    for _ref in _bv.get_code_refs(fn.start):
        if _n >= _limit:
            print("  ...more call-sites"); break
        _rf = _ref.function
        print("  0x%-12x  in %s" % (_ref.address, _rf.name if _rf else "?")); _n += 1
if _want_callees:
    _ce = sorted({c.name for c in fn.callees})
    print("callees (%d): %s" % (len(_ce), ", ".join(_ce[:_limit])))
'''


def main():
    ap = argparse.ArgumentParser(description="Show callers/callees/call-sites of a function via BN code-mode.")
    bncm.add_target_args(ap)
    ap.add_argument("name", nargs="?", help="exact function name")
    ap.add_argument("--addr", help="resolve by address instead (hex 0x.. or decimal)")
    ap.add_argument("--callers", action="store_true", help="only callers + call-sites")
    ap.add_argument("--callees", action="store_true", help="only callees")
    ap.add_argument("--limit", type=int, default=200, help="max entries per list (default 200)")
    a = ap.parse_args()
    if bool(a.name) == bool(a.addr):
        bncm.die("give exactly one of: a function name, or --addr")
    p = bncm.target_params(a)
    p["_name"] = bncm.vsym(a.name) if a.name else None
    p["_addr"] = bncm.vaddr(a.addr) if a.addr else None
    # default: show both
    both = not (a.callers or a.callees)
    p["_want_callers"] = bool(a.callers or both)
    p["_want_callees"] = bool(a.callees or both)
    p["_limit"] = max(1, min(a.limit, 100000))
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
