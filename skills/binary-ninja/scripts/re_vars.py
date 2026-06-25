#!/usr/bin/env python3
"""re_vars.py — list one function's variables (stable IDENTIFIER, current name, type) + its prototype,
so you can author the `vars` section of an re_sync sidecar (which keys variables by identifier).

  bn-re-vars --bv-match i_vmx_full Vmx_HandleFoo
  bn-re-vars --file /abs/x.bndb --addr 0x140001000

Prints the function's address (the sidecar's function key), its current prototype, and one line per
variable:  <identifier>  <storage>  <name> : <type>   — paste the identifiers into the sidecar.
Injection-safe: name/addr validated, embedded only as escaped literals (see bncm.py).
"""
import sys, os, argparse
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
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

print("// function key (sidecar): \"0x%x\"   name=%s" % (fn.start, fn.name))
print("// prototype: %s" % fn.type)
_params = set()
for _pv in fn.parameter_vars:
    _params.add(_pv.identifier)
print("// variables (identifier  storage  name : type)  [* = parameter]")
for _v in fn.vars:
    _star = "*" if _v.identifier in _params else " "
    try:
        _store = _v.source_type.name
    except Exception:
        _store = "?"
    print("%s %d  %-10s  %s : %s" % (_star, _v.identifier, _store, _v.name, _v.type))
'''


def main():
    ap = argparse.ArgumentParser(description="List a function's variables (identifier/name/type) for re_sync sidecar authoring.")
    bncm.add_target_args(ap)
    ap.add_argument("name", nargs="?", help="exact function/symbol name")
    ap.add_argument("--addr", help="resolve by address instead (hex 0x.. or decimal)")
    a = ap.parse_args()
    if bool(a.name) == bool(a.addr):
        bncm.die("give exactly one of: a function name, or --addr")
    p = bncm.target_params(a)
    p["_name"] = bncm.vsym(a.name) if a.name else None
    p["_addr"] = bncm.vaddr(a.addr) if a.addr else None
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
