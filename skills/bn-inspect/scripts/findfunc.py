#!/usr/bin/env python3
"""findfunc.py - locate functions / resolve symbols (BN "where is ..." task).

  findfunc.py --file /tmp/vmdird sasl              # functions whose name contains 'sasl'
  findfunc.py --file /tmp/vmdird --regex '^Srv_.*[Ss]rp'
  findfunc.py --file /tmp/vmdird --addr 0x532324   # what function/symbol is at this address

Injection-safe: query/regex/addr are validated and embedded only as escaped literals (see bncm.py).
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bncm

BODY = r'''
if _addr is not None:
    fn = _bv.get_function_at(_addr)
    if fn is None:
        _cf = _bv.get_functions_containing(_addr) or []
        fn = _cf[0] if _cf else None
    if fn is not None:
        _off = _addr - fn.start
        print("function @ 0x%x  %s  (start 0x%x +0x%x, bytes %d)" % (_addr, fn.name, fn.start, _off, fn.total_bytes))
    _sym = _bv.get_symbol_at(_addr)
    if _sym is not None:
        print("symbol   @ 0x%x  %s  (%s)" % (_addr, _sym.full_name, _sym.type.name if _sym.type else "?"))
    if fn is None and _sym is None:
        print("[nothing defined at 0x%x]" % _addr)
else:
    _hits = []
    for f in _bv.functions:
        _ok = False
        if _regex:
            if re.search(_query, f.name):
                _ok = True
        else:
            if _query in f.name:
                _ok = True
        if _ok and _noimports:
            _sym = f.symbol
            if _sym is not None and _sym.type is not None and _sym.type.name == "ImportedFunctionSymbol":
                _ok = False
        if _ok:
            _hits.append((f.name, f.start))
    _hits.sort()
    print("%d function(s) match %r%s (of %d total):" % (len(_hits), _query, " [regex]" if _regex else "", len(_bv.functions)))
    _n = 0
    for _nm, _st in _hits:
        if _n >= _limit:
            print("  ...[%d more; raise --limit]" % (len(_hits) - _limit)); break
        print("  0x%-12x %s" % (_st, _nm)); _n += 1
'''


def main():
    ap = argparse.ArgumentParser(description="Find functions by name / resolve an address via BN code-mode.")
    bncm.add_target_args(ap)
    ap.add_argument("query", nargs="?", help="substring to match against function names")
    ap.add_argument("--regex", action="store_true", help="treat query as a regex")
    ap.add_argument("--addr", help="instead, report what function/symbol is at this address")
    ap.add_argument("--no-imports", action="store_true", help="drop ImportedFunctionSymbol (PLT/import) duplicates")
    ap.add_argument("--limit", type=int, default=200, help="max matches to list (default 200)")
    a = ap.parse_args()
    if bool(a.query) == bool(a.addr):
        bncm.die("give exactly one of: a name query, or --addr")
    p = bncm.target_params(a)
    p["_addr"] = bncm.vaddr(a.addr) if a.addr else None
    p["_query"] = (bncm.vregex(a.query) if a.regex else bncm.vsym(a.query, "query")) if a.query else None
    p["_regex"] = bool(a.regex)
    p["_noimports"] = bool(a.no_imports)
    p["_limit"] = max(1, min(a.limit, 100000))
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
