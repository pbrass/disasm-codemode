#!/usr/bin/env python3
"""disasm-range.py - disassemble a WINDOW of instructions at an address (not a whole function).

For checking the exact instructions/lengths/compares at a specific site - e.g. the memcpy whose
length you want to read, or a patch point - without dumping a whole function's disassembly.

  disasm-range.py --file /tmp/vmknvme --addr 0x429dc0 --count 24
  disasm-range.py --file /tmp/vmknvme --addr 0x429dc0 --end 0x429e40

Injection-safe: addresses are validated and embedded only as escaped literals (see bncm.py).
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bncm

BODY = r'''
_a = _start
_n = 0
while _n < _count:
    if _end is not None and _a >= _end:
        break
    _txt = _bv.get_disassembly(_a)
    _ln = _bv.get_instruction_length(_a)
    if not _ln:
        print("  0x%012x  <no instruction (not in a code section, or undefined)>" % _a); break
    print("  0x%012x  %s" % (_a, _txt if _txt else "?"))
    _a += _ln
    _n += 1
print("[%d instruction(s) from 0x%x]" % (_n, _start))
'''


def main():
    ap = argparse.ArgumentParser(description="Disassemble an instruction window at an address via BN code-mode.")
    bncm.add_target_args(ap)
    ap.add_argument("--addr", required=True, help="start address (hex/decimal)")
    ap.add_argument("--count", type=int, default=32, help="max instructions (default 32)")
    ap.add_argument("--end", help="stop at this address (optional)")
    a = ap.parse_args()
    p = bncm.target_params(a)
    p["_start"] = bncm.vaddr(a.addr)
    p["_end"] = bncm.vaddr(a.end) if a.end else None
    p["_count"] = max(1, min(a.count, 100000))
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
