#!/usr/bin/env python3
"""gh-frame — stack-frame size, self-recursion, and signature/vars of a function.

  gh-frame --file /tmp/libsrp.so --func srp_server_mech_step
  gh-frame --file /tmp/apiForwarder --top 15      # N largest stack frames (stack-DoS hunt)

Ghidra reads the frame size from the recovered StackFrame (getFrameSize) rather than parsing the
prologue. Injection-safe (see ghcm.py)."""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm

BODY = r'''
_mon = pyghidra.task_monitor()
fm = program.getFunctionManager()
_targets = []
if _all:
    for f in fm.getFunctions(True):
        _targets.append(f)
else:
    _fn = None
    if _name:
        for f in fm.getFunctions(True):
            if f.getName() == _name:
                _fn = f; break
    else:
        _fn = fm.getFunctionContaining(_toaddr(_addr))
    if _fn is None:
        print("[function not found]"); raise SystemExit
    _targets = [_fn]
_rows = []
for _f in _targets:
    try:
        _frame = int(_f.getStackFrame().getFrameSize())
    except Exception:
        _frame = 0
    _rec = False
    _eo = _f.getEntryPoint().getOffset()
    for _c in _f.getCalledFunctions(_mon):
        if _c.getEntryPoint().getOffset() == _eo:
            _rec = True; break
    _rows.append((_frame, _f.getName(), _eo, _rec))
if _all:
    _rows.sort(reverse=True)
    print("top %d of %d functions by stack-frame size (* = self-recursive):" % (
        min(_top, len(_rows)), len(_rows)))
    _i = 0
    for _fr, _nm, _st, _rc in _rows:
        if _i >= _top:
            break
        print("  0x%-10x %9d B  %s %s" % (_st, _fr, "*" if _rc else " ", _nm)); _i += 1
else:
    _f = _targets[0]
    _fr, _nm, _st, _rc = _rows[0]
    print("# %s @ 0x%x" % (_nm, _st))
    print("stack frame : %d bytes (0x%x)   local size: %d" % (
        _fr, _fr, int(_f.getStackFrame().getLocalSize())))
    print("self-recursive: %s   code bytes: %d" % (_rc, _f.getBody().getNumAddresses()))
    _params = _f.getParameters()
    print("parameters (%d):" % len(_params))
    for _p in _params:
        _dt = _p.getDataType()
        print("   %-28s %s" % (_dt.getName() if _dt is not None else "?", _p.getName()))
    _rt = _f.getReturnType()
    print("returns     : %s" % (_rt.getName() if _rt is not None else "?"))
    print("prototype   : %s" % _f.getPrototypeString(False, False))
    print("local vars  : %d" % len(_f.getLocalVariables()))
'''


def main():
    ap = argparse.ArgumentParser(description="Stack-frame / recursion / signature of a function (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--func", help="function name (single-function report)")
    g.add_argument("--addr", help="function address (single-function report)")
    g.add_argument("--top", type=int, help="scan ALL functions; show the N largest stack frames")
    a = ap.parse_args()
    p = {}
    p["_all"] = a.top is not None
    p["_top"] = max(1, min(a.top, 100000)) if a.top is not None else 0
    p["_name"] = ghcm.vsym(a.func) if a.func else None
    p["_addr"] = ghcm.vaddr(a.addr) if a.addr else None
    ghcm.run(BODY, a, **p)


if __name__ == "__main__":
    main()
