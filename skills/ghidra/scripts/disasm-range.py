#!/usr/bin/env python3
"""gh-disasm-range — disassemble a WINDOW of instructions at an address (not a whole function).

  gh-disasm-range --file /tmp/target --addr 0x1011ee --count 24
  gh-disasm-range --file /tmp/target --addr 0x1011ee --end 0x101230

Injection-safe: addresses validated and embedded only as escaped literals (see ghcm.py)."""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm

BODY = r'''
_a = _toaddr(_start)
_endaddr = _toaddr(_end) if _end is not None else None
_n = 0
while _n < _count:
    if _endaddr is not None and _a.getOffset() >= _endaddr.getOffset():
        break
    _inst = listing.getInstructionAt(_a)
    if _inst is None:
        print("  0x%012x  <no instruction (not disassembled / not code here)>" % _a.getOffset()); break
    print("  0x%012x  %s" % (_a.getOffset(), _inst.toString()))
    _a = _a.add(_inst.getLength())
    _n += 1
print("[%d instruction(s) from 0x%x]" % (_n, _start))
'''


def main():
    ap = argparse.ArgumentParser(description="Disassemble an instruction window at an address (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    ap.add_argument("--addr", required=True, help="start address (hex/decimal)")
    ap.add_argument("--count", type=int, default=32, help="max instructions (default 32)")
    ap.add_argument("--end", help="stop at this address (optional)")
    a = ap.parse_args()
    p = {}
    p["_start"] = ghcm.vaddr(a.addr)
    p["_end"] = ghcm.vaddr(a.end) if a.end else None
    p["_count"] = max(1, min(a.count, 100000))
    ghcm.run(BODY, a, **p)


if __name__ == "__main__":
    main()
