#!/usr/bin/env python3
"""strxref.py - find a string and the functions that reference it (stripped-binary recipe).

Locating a handler in a stripped binary by an error/format/log string it uses, then pivoting
to the referencing function, is a core code-mode move. This finds matching strings, lists the
code references (address + containing function), and can decompile those functions.

  strxref.py --file /tmp/libsrp_live.so '%m%-o%s%-o'              # exact-ish substring search
  strxref.py --file /tmp/vmdird 'SASL start failed' --decompile
  strxref.py --file /tmp/wcpsvc --regex 'ctxClaims|/wcp/login'

The needle is NOT character-restricted (a string may contain quotes); it is embedded only as a
json.dumps-escaped literal, so it cannot inject code (see bncm.py).
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bncm

BODY = r'''
_matches = []
for _s in _bv.get_strings():
    _val = _s.value
    _hit = False
    if _regex:
        if re.search(_needle, _val):
            _hit = True
    elif _exact:
        if _val == _needle:
            _hit = True
    else:
        if _needle in _val:
            _hit = True
    if _hit:
        _matches.append((_s.start, _val))
print("%d string match(es) for %r%s:" % (len(_matches), _needle, " [regex]" if _regex else (" [exact]" if _exact else " [substr]")))
_fns = []
_fnseen = set()
_n = 0
for _saddr, _val in _matches:
    if _n >= _limit:
        print("  ...[%d more strings]" % (len(_matches) - _limit)); break
    _disp = _val if len(_val) <= 100 else _val[:100] + "..."
    print("  0x%-12x %r" % (_saddr, _disp))
    for _ref in _bv.get_code_refs(_saddr):
        _rf = _ref.function
        _rn = _rf.name if _rf else "?"
        print("      <- 0x%-12x %s" % (_ref.address, _rn))
        if _rf is not None and _rf.name not in _fnseen:
            _fnseen.add(_rf.name); _fns.append(_rf.name)
    # also follow one data-ref hop: a string reached via a global pointer
    # (e.g. `const char *P = "..."; use(P);`) has no direct code ref to the string.
    for _dref in _bv.get_data_refs(_saddr):
        for _ref in _bv.get_code_refs(_dref):
            _rf = _ref.function
            if _rf is not None:
                print("      <- 0x%-12x %s  (via ptr 0x%x)" % (_ref.address, _rf.name, _dref))
                if _rf.name not in _fnseen:
                    _fnseen.add(_rf.name); _fns.append(_rf.name)
    _n += 1
print("referencing functions (%d): %s" % (len(_fns), ", ".join(sorted(_fns)[:60])))
if _decompile:
    _dn = 0
    for _fname in sorted(_fns):
        if _dn >= _declimit:
            print("\n// ...[%d more functions; raise --declimit]" % (len(_fns) - _declimit)); break
        _fn = None
        for f in _bv.functions:
            if f.name == _fname:
                _fn = f; break
        if _fn is not None:
            print("\n// ===== %s @ 0x%x =====" % (_fn.name, _fn.start))
            _hh = str(_fn.hlil)
            print(_hh[:_maxlen])
            if len(_hh) > _maxlen:
                print("...[truncated %d bytes]" % (len(_hh) - _maxlen))
        _dn += 1
'''


def main():
    ap = argparse.ArgumentParser(description="Find a string and its referencing functions via BN code-mode.")
    bncm.add_target_args(ap)
    ap.add_argument("needle", help="string to search for (substring by default)")
    ap.add_argument("--regex", action="store_true", help="treat needle as a regex")
    ap.add_argument("--exact", action="store_true", help="require an exact full-string match")
    ap.add_argument("--decompile", action="store_true", help="also decompile the referencing functions")
    ap.add_argument("--limit", type=int, default=100, help="max strings to report (default 100)")
    ap.add_argument("--declimit", type=int, default=10, help="max functions to decompile (default 10)")
    ap.add_argument("--maxlen", type=int, default=20000, help="max HLIL bytes per decompiled fn")
    a = ap.parse_args()
    if a.regex and a.exact:
        bncm.die("--regex and --exact are mutually exclusive")
    p = bncm.target_params(a)
    p["_needle"] = bncm.vregex(a.needle) if a.regex else bncm.vneedle(a.needle)
    p["_regex"] = bool(a.regex)
    p["_exact"] = bool(a.exact)
    p["_decompile"] = bool(a.decompile)
    p["_limit"] = max(1, min(a.limit, 100000))
    p["_declimit"] = max(1, min(a.declimit, 200))
    p["_maxlen"] = max(1000, min(a.maxlen, 95000))
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
