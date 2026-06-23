#!/usr/bin/env python3
"""gh-find — locate functions / resolve symbols ("where is ..." task).

  gh-find --file /tmp/vmdird sasl              # functions whose name contains 'sasl'
  gh-find --file /tmp/vmdird --regex '^Srv_.*[Ss]rp'
  gh-find --file /tmp/vmdird --addr 0x102240   # what function/symbol is at this address
  gh-find --file /tmp/vmdird memcpy --no-imports

Ghidra sibling of bn-inspect's findfunc.py. Injection-safe: query/regex/addr validated and
embedded only as escaped literals (see ghcm.py)."""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm

BODY = r'''
fm = program.getFunctionManager()
if _addr is not None:
    _a = _toaddr(_addr)
    fn = fm.getFunctionContaining(_a)
    if fn is not None:
        _st = fn.getEntryPoint().getOffset()
        print("function @ 0x%x  %s  (start 0x%x +0x%x, %d bytes)" % (
            _addr, fn.getName(), _st, _addr - _st, fn.getBody().getNumAddresses()))
    _sym = symbol_table.getPrimarySymbol(_a)
    if _sym is not None:
        print("symbol   @ 0x%x  %s  (%s)" % (_addr, _sym.getName(True), _sym.getSymbolType()))
    if fn is None and _sym is None:
        print("[nothing defined at 0x%x]" % _addr)
else:
    _hits = []
    _total = 0
    for f in fm.getFunctions(True):
        _total += 1
        _nm = f.getName()
        if _regex:
            _ok = re.search(_query, _nm) is not None
        else:
            _ok = _query in _nm
        if _ok and _noimports and (f.isThunk() or f.isExternal()):
            _ok = False
        if _ok:
            _hits.append((f.getEntryPoint().getOffset(), _nm))
    _hits.sort()
    print("%d function(s) match %r%s (of %d total):" % (
        len(_hits), _query, " [regex]" if _regex else "", _total))
    _n = 0
    for _st, _nm in _hits:
        if _n >= _limit:
            print("  ...[%d more; raise --limit]" % (len(_hits) - _limit)); break
        print("  0x%-12x %s" % (_st, _nm)); _n += 1
'''


def main():
    ap = argparse.ArgumentParser(description="Find functions by name / resolve an address (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    ap.add_argument("query", nargs="?", help="substring to match against function names")
    ap.add_argument("--regex", action="store_true", help="treat query as a regex")
    ap.add_argument("--addr", help="instead, report what function/symbol is at this address")
    ap.add_argument("--no-imports", action="store_true", help="drop thunk/external (PLT/import) functions")
    ap.add_argument("--limit", type=int, default=200, help="max matches to list (default 200)")
    a = ap.parse_args()
    if bool(a.query) == bool(a.addr):
        ghcm.die("give exactly one of: a name query, or --addr")
    p = {}
    p["_addr"] = ghcm.vaddr(a.addr) if a.addr else None
    p["_query"] = (ghcm.vregex(a.query) if a.regex else ghcm.vsym(a.query, "query")) if a.query else None
    p["_regex"] = bool(a.regex)
    p["_noimports"] = bool(a.no_imports)
    p["_limit"] = max(1, min(a.limit, 100000))
    ghcm.run(BODY, a, **p)


if __name__ == "__main__":
    main()
