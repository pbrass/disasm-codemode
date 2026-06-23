#!/usr/bin/env python3
"""gh-xrefs — callers, callees, and call-sites of a function/address (xref task).

  gh-xrefs --file /tmp/vmdird VmDirSASLSessionStart
  gh-xrefs --file /tmp/libsrp.so --addr 0x101379 --callers

Ghidra sibling of bn-inspect's xrefs.py. Injection-safe (see ghcm.py)."""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm

BODY = r'''
_mon = pyghidra.task_monitor()
fm = program.getFunctionManager()
_rm = program.getReferenceManager()
fn = None
if _name:
    for f in fm.getFunctions(True):
        if f.getName() == _name:
            fn = f; break
else:
    fn = fm.getFunctionContaining(_toaddr(_addr))
if fn is None:
    print("[target function not found]"); raise SystemExit
_st = fn.getEntryPoint().getOffset()
print("# %s @ 0x%x" % (fn.getName(), _st))
if _want_callers:
    _cs = sorted({c.getName() for c in fn.getCallingFunctions(_mon)})
    print("callers (%d): %s" % (len(_cs), ", ".join(_cs[:_limit])))
    print("call-sites to 0x%x:" % _st)
    _n = 0
    for _ref in _rm.getReferencesTo(fn.getEntryPoint()):
        if not _ref.getReferenceType().isCall():
            continue
        if _n >= _limit:
            print("  ...more call-sites"); break
        _frm = _ref.getFromAddress()
        _rf = fm.getFunctionContaining(_frm)
        print("  0x%-12x  in %s" % (_frm.getOffset(), _rf.getName() if _rf else "?")); _n += 1
if _want_callees:
    _ce = sorted({c.getName() for c in fn.getCalledFunctions(_mon)})
    print("callees (%d): %s" % (len(_ce), ", ".join(_ce[:_limit])))
'''


def main():
    ap = argparse.ArgumentParser(description="Show callers/callees/call-sites of a function (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    ap.add_argument("name", nargs="?", help="exact function name")
    ap.add_argument("--addr", help="resolve by address instead (hex 0x.. or decimal)")
    ap.add_argument("--callers", action="store_true", help="only callers + call-sites")
    ap.add_argument("--callees", action="store_true", help="only callees")
    ap.add_argument("--limit", type=int, default=200, help="max entries per list (default 200)")
    a = ap.parse_args()
    if bool(a.name) == bool(a.addr):
        ghcm.die("give exactly one of: a function name, or --addr")
    p = {}
    p["_name"] = ghcm.vsym(a.name) if a.name else None
    p["_addr"] = ghcm.vaddr(a.addr) if a.addr else None
    both = not (a.callers or a.callees)
    p["_want_callers"] = bool(a.callers or both)
    p["_want_callees"] = bool(a.callees or both)
    p["_limit"] = max(1, min(a.limit, 100000))
    ghcm.run(BODY, a, **p)


if __name__ == "__main__":
    main()
