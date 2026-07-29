#!/usr/bin/env python3
"""frame.py - stack-frame size, self-recursion, and signature/vars of a function.

Two modes:
  * single function -> frame size, params (+types), return type, #locals, recursion, xref counts
  * --top N         -> the N functions with the LARGEST stack frames, flagging self-recursive
                       ones (the stack-exhaustion / unbounded-recursion DoS hunt, e.g. the
                       apiForwarder nested-JSON finding).

  frame.py --file /tmp/libsrp.so --func srp_server_mech_step
  frame.py --file /tmp/apiForwarder --top 15

Frame size is read from the prologue (`sub rsp/esp, imm`). Injection-safe (see bncm.py).
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bncm

BODY = r'''
_targets = []
if _all:
    for f in _bv.functions:
        _targets.append(f)
else:
    _fn = None
    if _name:
        for f in _bv.functions:
            if f.name == _name:
                _fn = f; break
    else:
        _fn = _bv.get_function_at(_addr)
        if _fn is None:
            _cf = _bv.get_functions_containing(_addr) or []
            _fn = _cf[0] if _cf else None
    if _fn is None:
        print("[function not found]"); raise SystemExit
    _targets = [_fn]

_rows = []
for _f in _targets:
    _frame = 0
    _bbs = _f.basic_blocks
    if _bbs:
        _cnt = 0
        for _dt in _bbs[0].get_disassembly_text():
            _s = str(_dt)
            if "sub" in _s and ("rsp" in _s or "esp" in _s):
                _m = re.search(r"(0x[0-9a-fA-F]+|[0-9]+)\s*$", _s)
                if _m:
                    try:
                        _frame = int(_m.group(1), 0)
                    except Exception:
                        _frame = 0
                    break
            _cnt += 1
            if _cnt > 24:
                break
    _rec = False
    for _c in _f.callees:
        if _c.start == _f.start:
            _rec = True; break
    _rows.append((_frame, _f.name, _f.start, _rec, len(_f.callers), len(_f.callees)))

if _all:
    _rows.sort(reverse=True)
    print("top %d of %d functions by stack-frame size (* = self-recursive):" % (min(_top, len(_rows)), len(_rows)))
    _i = 0
    for _fr, _nm, _st, _rc, _ncr, _nce in _rows:
        if _i >= _top:
            break
        print("  0x%-10x %9d B  %s %s" % (_st, _fr, "*" if _rc else " ", _nm))
        _i += 1
else:
    _fr, _nm, _st, _rc, _ncr, _nce = _rows[0]
    _fn = _targets[0]
    print("# %s @ 0x%x" % (_nm, _st))
    print("stack frame : %d bytes (0x%x)" % (_fr, _fr))
    print("self-recursive: %s   callers: %d   callees: %d   code bytes: %d" % (_rc, _ncr, _nce, _fn.total_bytes))
    _pv = _fn.parameter_vars
    print("parameters (%d):" % len(_pv))
    for _p in _pv:
        _t = str(_p.type) if _p.type is not None else "?"
        print("   %-28s %s" % (_t, _p.name))
    _rt = _fn.return_type
    print("returns     : %s" % (str(_rt) if _rt is not None else "?"))
    print("local vars  : %d" % len(_fn.vars))
'''


def main():
    ap = argparse.ArgumentParser(description="Stack-frame / recursion / signature of a function via BN code-mode.")
    bncm.add_target_args(ap)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--func", help="function name (single-function report)")
    g.add_argument("--addr", help="function address (single-function report)")
    g.add_argument("--top", type=int, help="scan ALL functions; show the N largest stack frames")
    a = ap.parse_args()
    p = bncm.target_params(a)
    p["_all"] = a.top is not None
    p["_top"] = max(1, min(a.top, 100000)) if a.top is not None else 0
    p["_name"] = bncm.vsym(a.func) if a.func else None
    p["_addr"] = bncm.vaddr(a.addr) if a.addr else None
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
