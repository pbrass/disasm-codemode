#!/usr/bin/env python3
"""gh-scan — HEURISTIC bug-class candidate finder over decompiled C (Ghidra analog of bn_scan_*).

Decompiles each function and flags lines matching a bug-class pattern. This is a CANDIDATE
finder, not a prover: confirm every hit with gh-decompile / gh-callsites.

  gh-scan --file /tmp/target --class all
  gh-scan --file /tmp/target --class intof
  gh-scan --file /tmp/libfoo.so --class copylen --regex '^Srv_'   # only functions matching a name regex

Classes:
  intof     - malloc/realloc/alloca with a '*' in the size  (integer-overflow allocation)
  alloccopy - a function that BOTH allocates AND copies      (heap alloc/copy-size mismatch)
  copylen   - mem/str copy whose length is a cast/variable   (attacker-influenced length)
  fmt       - printf-family whose FORMAT arg is a variable   (format-string)

The class name is checked against a fixed allowlist; the patterns are CONSTANTS in the body.
The optional --regex name filter is the only user regex and is embedded as an escaped literal
(see ghcm.py). Output is scrubbed (tainted)."""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm

CLASSES = ("intof", "alloccopy", "copylen", "fmt")

BODY = r'''
_ALLOC = re.compile(r"(?:^|[^A-Za-z0-9_])(?:malloc|realloc|alloca|kmalloc|valloc|pvalloc)\s*\(")
_COPY = re.compile(r"(?:^|[^A-Za-z0-9_])(?:memcpy|memmove|strcpy|strcat|strncpy|strncat|sprintf|bcopy)\s*\(")
_TABLE = {
    "intof": re.compile(r"(?:^|[^A-Za-z0-9_])(?:malloc|realloc|alloca|kmalloc|valloc)\s*\([^;]*\*"),
    "copylen": re.compile(r"(?:^|[^A-Za-z0-9_])(?:memcpy|memmove|strncpy|strncat|memset)\s*\([^;]*,\s*\(?(?:long|ulong|uint|int|size_t|ushort|short)\)?\s*[A-Za-z_(*]"),
    "fmt": re.compile(r"(?:^|[^A-Za-z0-9_])(?:printf|sprintf|fprintf|snprintf|vsprintf|vsnprintf|syslog)\s*\(\s*[A-Za-z_]\w*\s*[,)]"),
}
_classes = list(CLASSES_LIT) if _cls == "all" else [_cls]
fm = program.getFunctionManager()
_count = 0
_scanned = 0
_capped = False
for f in fm.getFunctions(True):
    if f.isThunk() or f.isExternal():
        continue
    if _namerx is not None and re.search(_namerx, f.getName()) is None:
        continue
    if _scanned >= _maxfns:
        _capped = True; break
    _scanned += 1
    _r = decompiler.decompileFunction(f, _timeout, pyghidra.task_monitor())
    if not _r.decompileCompleted():
        continue
    _c = _r.getDecompiledFunction().getC()
    _lines = _c.split("\n")
    for _cl in _classes:
        _hits = []
        if _cl == "alloccopy":
            if _ALLOC.search(_c) and _COPY.search(_c):
                for _ln in _lines:
                    if _ALLOC.search(_ln) or _COPY.search(_ln):
                        _hits.append(_ln.strip())
        else:
            _pat = _TABLE[_cl]
            for _ln in _lines:
                if _pat.search(_ln):
                    _hits.append(_ln.strip())
        if _hits:
            print("  [%s] %s @ 0x%x" % (_cl, f.getName(), f.getEntryPoint().getOffset()))
            _seen = set()
            _shown = 0
            for _h in _hits:
                if _h in _seen:
                    continue
                _seen.add(_h)
                if _shown >= _linelimit:
                    break
                print("        %s" % _h); _shown += 1
            _count += 1
if _capped:
    print("  ...[stopped after --maxfns=%d functions]" % _maxfns)
print("[%d candidate(s) across %d function(s); HEURISTIC - verify with gh-decompile/gh-callsites]" % (_count, _scanned))
'''


def main():
    ap = argparse.ArgumentParser(description="Heuristic bug-class scan over decompiled C (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    ap.add_argument("--class", dest="cls", default="all",
                    help="bug class: %s, or 'all' (default)" % ", ".join(CLASSES))
    ap.add_argument("--regex", help="only scan functions whose name matches this regex")
    ap.add_argument("--maxfns", type=int, default=4000, help="max functions to decompile (default 4000)")
    ap.add_argument("--linelimit", type=int, default=12, help="max lines shown per hit (default 12)")
    ap.add_argument("--timeout", type=int, default=20, help="decompiler timeout seconds")
    a = ap.parse_args()
    if a.cls != "all" and a.cls not in CLASSES:
        ghcm.die("--class must be one of: %s, all" % ", ".join(CLASSES))
    p = {}
    p["_cls"] = a.cls
    p["CLASSES_LIT"] = list(CLASSES)
    p["_namerx"] = ghcm.vregex(a.regex) if a.regex else None
    p["_maxfns"] = max(1, min(a.maxfns, 1000000))
    p["_linelimit"] = max(1, min(a.linelimit, 200))
    p["_timeout"] = max(1, min(a.timeout, 300))
    ghcm.run(BODY, a, **p)


if __name__ == "__main__":
    main()
