#!/usr/bin/env python3
"""gh-strxref — find a string and the functions that reference it (stripped-binary recipe).

  gh-strxref --file /tmp/libsrp.so '%m%-o%s%-o'
  gh-strxref --file /tmp/vmdird 'SASL start failed' --decompile
  gh-strxref --file /tmp/wcpsvc --regex 'ctxClaims|/wcp/login'

Follows one data-ref hop so a string reached via a global pointer (const char *P = "...")
still maps back to the using function. The needle is NOT char-restricted (a string may contain
quotes); it is embedded only as a json.dumps-escaped literal, so it cannot inject code (ghcm.py)."""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm

BODY = r'''
_rm = program.getReferenceManager()
fm = program.getFunctionManager()
_matches = []
_ASD = ghidra.program.model.data.AbstractStringDataType
for _d in listing.getDefinedData(True):
    if not isinstance(_d.getDataType(), _ASD):
        continue
    _v = _d.getValue()
    _val = str(_v) if _v is not None else ""
    if _regex:
        _hit = re.search(_needle, _val) is not None
    elif _exact:
        _hit = (_val == _needle)
    else:
        _hit = (_needle in _val)
    if _hit:
        _matches.append((_d.getAddress(), _val))
print("%d string match(es) for %r%s:" % (
    len(_matches), _needle, " [regex]" if _regex else (" [exact]" if _exact else " [substr]")))
_fns = []
_seen = set()
_n = 0
for _saddr, _val in _matches:
    if _n >= _limit:
        print("  ...[%d more strings]" % (len(_matches) - _limit)); break
    _disp = _val if len(_val) <= 100 else _val[:100] + "..."
    print("  0x%-12x %r" % (_saddr.getOffset(), _disp))
    for _ref in _rm.getReferencesTo(_saddr):
        _frm = _ref.getFromAddress()
        _rf = fm.getFunctionContaining(_frm)
        if _rf is not None:
            print("      <- 0x%-12x %s" % (_frm.getOffset(), _rf.getName()))
            if _rf.getName() not in _seen:
                _seen.add(_rf.getName()); _fns.append(_rf.getName())
        else:
            for _ref2 in _rm.getReferencesTo(_frm):
                _f2 = fm.getFunctionContaining(_ref2.getFromAddress())
                if _f2 is not None:
                    print("      <- 0x%-12x %s  (via ptr 0x%x)" % (
                        _ref2.getFromAddress().getOffset(), _f2.getName(), _frm.getOffset()))
                    if _f2.getName() not in _seen:
                        _seen.add(_f2.getName()); _fns.append(_f2.getName())
    _n += 1
print("referencing functions (%d): %s" % (len(_fns), ", ".join(sorted(_fns)[:60])))
if _decompile:
    _dn = 0
    for _fname in sorted(_fns):
        if _dn >= _declimit:
            print("\n// ...[%d more functions; raise --declimit]" % (len(_fns) - _declimit)); break
        _fn = None
        for f in fm.getFunctions(True):
            if f.getName() == _fname:
                _fn = f; break
        if _fn is not None:
            print("\n// ===== %s @ 0x%x =====" % (_fn.getName(), _fn.getEntryPoint().getOffset()))
            _r = decompiler.decompileFunction(_fn, 30, pyghidra.task_monitor())
            _hh = _r.getDecompiledFunction().getC() if _r.decompileCompleted() else (
                "[decompile failed: %s]" % _r.getErrorMessage())
            print(_hh[:_maxlen])
            if len(_hh) > _maxlen:
                print("...[truncated %d bytes]" % (len(_hh) - _maxlen))
        _dn += 1
'''


def main():
    ap = argparse.ArgumentParser(description="Find a string and its referencing functions (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    ap.add_argument("needle", help="string to search for (substring by default)")
    ap.add_argument("--regex", action="store_true", help="treat needle as a regex")
    ap.add_argument("--exact", action="store_true", help="require an exact full-string match")
    ap.add_argument("--decompile", action="store_true", help="also decompile the referencing functions")
    ap.add_argument("--limit", type=int, default=100, help="max strings to report (default 100)")
    ap.add_argument("--declimit", type=int, default=10, help="max functions to decompile (default 10)")
    ap.add_argument("--maxlen", type=int, default=20000, help="max C bytes per decompiled fn")
    a = ap.parse_args()
    if a.regex and a.exact:
        ghcm.die("--regex and --exact are mutually exclusive")
    p = {}
    p["_needle"] = ghcm.vregex(a.needle) if a.regex else ghcm.vneedle(a.needle)
    p["_regex"] = bool(a.regex)
    p["_exact"] = bool(a.exact)
    p["_decompile"] = bool(a.decompile)
    p["_limit"] = max(1, min(a.limit, 100000))
    p["_declimit"] = max(1, min(a.declimit, 200))
    p["_maxlen"] = max(1000, min(a.maxlen, 95000))
    ghcm.run(BODY, a, **p)


if __name__ == "__main__":
    main()
