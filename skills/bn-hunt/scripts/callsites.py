#!/usr/bin/env python3
"""callsites.py - find every call to a SINK and show its argument expressions (HLIL).

The bug-hunt move behind format-string / heap-copy / alloc findings: resolve a sink
(memcpy/strcpy/sprintf/printf-family/malloc/a log helper/...), then look at each call site's
HLIL to read the argument expressions (e.g. "is arg[2] (the length) attacker-controlled?").

  callsites.py --file /tmp/libsrp.so --sink MakeBuffer
  callsites.py --file /tmp/vmdird --sink memcpy --arg 2        # show just the length arg
  callsites.py --file /tmp/vmknvme --sink-addr 0x429df7 --in NVMFAuthDoAuthentication

Resolves the sink as a function OR an imported symbol (so PLT/import sinks like memcpy work).
Injection-safe: sink/addr/scope are validated and embedded only as escaped literals (bncm.py).
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bncm

BODY = r'''
_SINK = None
if _sinkaddr is not None:
    _SINK = _sinkaddr
else:
    for f in _bv.functions:
        if f.name == _sink:
            _SINK = f.start; break
    if _SINK is None:
        _sym = _bv.get_symbol_by_raw_name(_sink)
        if _sym is not None:
            _SINK = _sym.address
if _SINK is None:
    print("[sink %r not found as a function or symbol]" % (_sink if _sink else _sinkaddr)); raise SystemExit
_label = _sink if _sink else ("0x%x" % _sinkaddr)
print("# call sites to %s (target 0x%x)%s" % (_label, _SINK, ((" within *%s*" % _infn) if _infn else "")))
_grp = {}
for _ref in _bv.get_code_refs(_SINK):
    _rf = _ref.function
    if _rf is None:
        continue
    if _infn and _infn not in _rf.name:
        continue
    _e = _grp.get(_rf.start)
    if _e is None:
        _e = [_rf, []]; _grp[_rf.start] = _e
    _e[1].append(_ref.address)
_n = 0
_stop = False
for _k in _grp:
    _cf, _addrs = _grp[_k]
    for _a in sorted(set(_addrs)):
        if _n >= _limit:
            _stop = True; break
        _il = _cf.get_low_level_il_at(_a)
        _hi = None
        if _il is not None:
            try:
                _hi = _il.hlil
            except Exception:
                _hi = None
        if _hi is None:
            print("  0x%-10x %-32s %s" % (_a, _cf.name, _bv.get_disassembly(_a) or "<no IL>")); _n += 1; continue
        _params = None
        try:
            _params = _hi.params
        except Exception:
            try:
                _params = _hi.src.params
            except Exception:
                _params = None
        if _argidx is not None and _params is not None and 0 <= _argidx < len(_params):
            print("  0x%-10x %-32s arg[%d] = %s" % (_a, _cf.name, _argidx, str(_params[_argidx])))
        else:
            print("  0x%-10x %-32s %s" % (_a, _cf.name, str(_hi)))
        _n += 1
    if _stop:
        break
print("[%d call site(s)]" % _n)
'''


def main():
    ap = argparse.ArgumentParser(description="Find calls to a sink and show arg expressions via BN code-mode.")
    bncm.add_target_args(ap)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--sink", help="callee/sink name (function or imported symbol, e.g. memcpy)")
    g.add_argument("--sink-addr", help="callee/sink address (hex/decimal)")
    ap.add_argument("--in", dest="infn", help="only call sites inside callers whose name contains this")
    ap.add_argument("--arg", type=int, help="show only this 0-based argument expression (e.g. 2 = memcpy length)")
    ap.add_argument("--limit", type=int, default=400, help="max call sites (default 400)")
    a = ap.parse_args()
    p = bncm.target_params(a)
    p["_sink"] = bncm.vsym(a.sink, "sink") if a.sink else None
    p["_sinkaddr"] = bncm.vaddr(a.sink_addr) if a.sink_addr else None
    p["_infn"] = bncm.vsym(a.infn, "in") if a.infn else None
    p["_argidx"] = a.arg if a.arg is not None else None
    if p["_argidx"] is not None and not (0 <= p["_argidx"] < 64):
        bncm.die("--arg out of range 0..63")
    p["_limit"] = max(1, min(a.limit, 100000))
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
