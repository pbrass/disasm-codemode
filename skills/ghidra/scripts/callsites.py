#!/usr/bin/env python3
"""gh-callsites — find every call to a SINK and show its argument expressions (decompiled C).

The bug-hunt move behind format-string / heap-copy / alloc findings: resolve a sink
(memcpy/strcpy/sprintf/malloc/a log helper/...), then read each call site's decompiled C to see
the argument expressions ("is the length attacker-controlled?").

  gh-callsites --file /tmp/libsrp.so --sink MakeBuffer
  gh-callsites --file /tmp/target --sink memcpy --in heap_copy

Resolves the sink as a function OR a global symbol (so PLT/import sinks like memcpy work). Unlike
BN's HLIL params, Ghidra shows the full decompiled call expression(s) per caller (all args).
Injection-safe: sink/addr/scope validated and embedded only as escaped literals (ghcm.py)."""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm

BODY = r'''
fm = program.getFunctionManager()
_rm = program.getReferenceManager()
_sink_addr = None
if _sinkaddr is not None:
    _sink_addr = _toaddr(_sinkaddr)
    _label = "0x%x" % _sinkaddr
else:
    for f in fm.getFunctions(True):
        if f.getName() == _sink:
            _sink_addr = f.getEntryPoint(); break
    if _sink_addr is None:
        for _s in symbol_table.getGlobalSymbols(_sink):
            _sink_addr = _s.getAddress(); break
    _label = _sink
if _sink_addr is None:
    print("[sink %r not found as a function or symbol]" % _label); raise SystemExit
print("# call sites to %s (target 0x%x)%s" % (
    _label, _sink_addr.getOffset(), ((" within *%s*" % _infn) if _infn else "")))
_grp = {}
for _ref in _rm.getReferencesTo(_sink_addr):
    if not _ref.getReferenceType().isCall():
        continue
    _frm = _ref.getFromAddress()
    _rf = fm.getFunctionContaining(_frm)
    if _rf is None:
        continue
    if _infn and _infn not in _rf.getName():
        continue
    _k = _rf.getEntryPoint().getOffset()
    _e = _grp.get(_k)
    if _e is None:
        _e = [_rf, []]; _grp[_k] = _e
    _e[1].append(_frm.getOffset())
_ncallers = 0
_nsites = 0
for _k in sorted(_grp):
    _rf, _sites = _grp[_k]
    _usites = sorted(set(_sites))
    _nsites += len(_usites)
    if _ncallers >= _limit:
        print("  ...[more callers; raise --limit]"); break
    print("  %s  (%d site(s): %s)" % (
        _rf.getName(), len(_usites), ", ".join("0x%x" % _s for _s in _usites[:8])))
    _r = decompiler.decompileFunction(_rf, _timeout, pyghidra.task_monitor())
    if _r.decompileCompleted():
        _hits = []
        for _ln in _r.getDecompiledFunction().getC().split("\n"):
            if _label in _ln:
                _hits.append(_ln.strip())
        for _h in _hits[:_linelimit]:
            print("        %s" % _h)
        if not _hits:
            print("        <call present; sink name not in decompiled text (inlined/renamed?)>")
    else:
        print("        <decompile failed: %s>" % _r.getErrorMessage())
    _ncallers += 1
print("[%d caller(s), %d call site(s) to %s]" % (_ncallers, _nsites, _label))
'''


def main():
    ap = argparse.ArgumentParser(description="Find calls to a sink and show arg expressions (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--sink", help="callee/sink name (function or global symbol, e.g. memcpy)")
    g.add_argument("--sink-addr", help="callee/sink address (hex/decimal)")
    ap.add_argument("--in", dest="infn", help="only call sites inside callers whose name contains this")
    ap.add_argument("--arg", type=int, help="(accepted for CLI parity; Ghidra shows the full call expression)")
    ap.add_argument("--limit", type=int, default=200, help="max callers to report (default 200)")
    ap.add_argument("--linelimit", type=int, default=12, help="max matching C lines per caller (default 12)")
    ap.add_argument("--timeout", type=int, default=30, help="decompiler timeout seconds")
    a = ap.parse_args()
    p = {}
    p["_sink"] = ghcm.vsym(a.sink, "sink") if a.sink else None
    p["_sinkaddr"] = ghcm.vaddr(a.sink_addr) if a.sink_addr else None
    p["_infn"] = ghcm.vsym(a.infn, "in") if a.infn else None
    if a.arg is not None and not (0 <= a.arg < 64):
        ghcm.die("--arg out of range 0..63")
    p["_limit"] = max(1, min(a.limit, 100000))
    p["_linelimit"] = max(1, min(a.linelimit, 200))
    p["_timeout"] = max(1, min(a.timeout, 300))
    ghcm.run(BODY, a, **p)


if __name__ == "__main__":
    main()
