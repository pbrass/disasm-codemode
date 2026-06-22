#!/usr/bin/env python3
"""scansec.py - inspect sections / read bytes / scan data (stripped-daemon data recipe).

  scansec.py --file /tmp/vmdird                              # list sections
  scansec.py --file /tmp/vmdird --read 0x4af39a --len 64     # hexdump bytes at an address
  scansec.py --file /tmp/vmdird --section .data --ptrs       # code-pointer arrays (EPV/ifspec hunt)
  scansec.py --file /tmp/vmdird --section .rodata --strings --minstr 6

Injection-safe: addr/section are validated and embedded only as escaped literals (see bncm.py).
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bncm

BODY = r'''
if _mode == "read":
    _data = _bv.read(_read, _len) or b""
    if not _data:
        print("[no data readable at 0x%x]" % _read); raise SystemExit
    _o = 0
    while _o < len(_data):
        _chunk = _data[_o:_o + 16]
        _hx = ""
        _asc = ""
        for _b in _chunk:
            _hx += "%02x " % _b
            _asc += chr(_b) if 32 <= _b < 127 else "."
        print("%012x  %-48s %s" % (_read + _o, _hx, _asc))
        _o += 16
elif _mode == "list":
    print("sections (%d):" % len(_bv.sections))
    for _nm in _bv.sections:
        _sec = _bv.sections[_nm]
        _sem = _sec.semantics.name if _sec.semantics is not None else ""
        print("  %-22s 0x%-12x - 0x%-12x  len=0x%-9x %s" % (_nm, _sec.start, _sec.end, _sec.length, _sem))
else:
    _sec = _bv.sections.get(_section)
    if _sec is None:
        print("[no section %r -- have: %s]" % (_section, ", ".join(_bv.sections.keys()))); raise SystemExit
    _n = _sec.length
    if _n > _cap:
        _n = _cap
        print("[scanning first 0x%x of 0x%x bytes; raise --cap]" % (_n, _sec.length))
    _data = _bv.read(_sec.start, _n) or b""
    if _mode == "strings":
        _run = []
        _rstart = 0
        _i = 0
        _count = 0
        for _b in _data:
            if 32 <= _b < 127:
                if not _run:
                    _rstart = _i
                _run.append(_b)
            else:
                if len(_run) >= _minstr:
                    print("  0x%-12x %r" % (_sec.start + _rstart, bytes(_run).decode("ascii", "replace")))
                    _count += 1
                _run = []
            if _count >= _limit:
                break
            _i += 1
        print("[%d printable run(s) >= %d chars in %s]" % (_count, _minstr, _section))
    elif _mode == "ptrs":
        _execr = []
        for _nm in _bv.sections:
            _s2 = _bv.sections[_nm]
            if _s2.semantics is not None and "Code" in _s2.semantics.name:
                _execr.append((_s2.start, _s2.end))
        _o = 0
        _count = 0
        while _o + 8 <= len(_data):
            _v = int.from_bytes(_data[_o:_o + 8], "little")
            if _v:
                _inx = False
                for _lo, _hi in _execr:
                    if _lo <= _v < _hi:
                        _inx = True; break
                if _inx:
                    _fn = _bv.get_function_at(_v)
                    print("  0x%-12x -> 0x%-12x %s" % (_sec.start + _o, _v, (_fn.name if _fn else "")))
                    _count += 1
                    if _count >= _limit:
                        break
            _o += 8
        print("[%d code-pointer-like value(s) in %s (8-byte LE, aligned)]" % (_count, _section))
'''


def main():
    ap = argparse.ArgumentParser(description="Inspect sections / read bytes / scan data via BN code-mode.")
    bncm.add_target_args(ap)
    ap.add_argument("--read", help="hexdump bytes starting at this address (hex/decimal)")
    ap.add_argument("--len", type=int, default=256, help="bytes to hexdump for --read (default 256)")
    ap.add_argument("--section", help="section to scan (with --strings or --ptrs)")
    ap.add_argument("--strings", action="store_true", help="print printable ASCII runs in --section")
    ap.add_argument("--ptrs", action="store_true", help="print code-pointer-like values in --section")
    ap.add_argument("--minstr", type=int, default=4, help="min run length for --strings (default 4)")
    ap.add_argument("--limit", type=int, default=500, help="max items to print (default 500)")
    ap.add_argument("--cap", type=int, default=2 * 1024 * 1024, help="max section bytes to scan (default 2MiB)")
    a = ap.parse_args()
    p = bncm.target_params(a)
    if a.read:
        if a.section:
            bncm.die("use either --read or --section, not both")
        p["_mode"] = "read"
        p["_read"] = bncm.vaddr(a.read)
        p["_len"] = max(1, min(a.len, 1024 * 1024))
        p["_section"] = None
    elif a.section:
        if a.strings and a.ptrs:
            bncm.die("--strings and --ptrs are mutually exclusive")
        if not (a.strings or a.ptrs):
            bncm.die("--section requires --strings or --ptrs")
        p["_mode"] = "strings" if a.strings else "ptrs"
        p["_section"] = bncm.vsection(a.section)
        p["_read"] = None
        p["_len"] = 0
    else:
        p["_mode"] = "list"
        p["_section"] = None
        p["_read"] = None
        p["_len"] = 0
    p["_minstr"] = max(2, min(a.minstr, 256))
    p["_limit"] = max(1, min(a.limit, 1000000))
    p["_cap"] = max(4096, min(a.cap, 64 * 1024 * 1024))
    bncm.run(BODY, **p)


if __name__ == "__main__":
    main()
