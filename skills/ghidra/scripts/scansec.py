#!/usr/bin/env python3
"""gh-scansec — inspect memory blocks / read bytes / scan data.

  gh-scansec --file /tmp/vmdird                              # list blocks (sections)
  gh-scansec --file /tmp/vmdird --read 0x102004 --len 64     # hexdump bytes at an address
  gh-scansec --file /tmp/vmdird --section .data --ptrs       # code-pointer arrays
  gh-scansec --file /tmp/vmdird --section .rodata --strings --minstr 6

Ghidra sibling of bn-inspect's scansec.py. Injection-safe (see ghcm.py)."""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm

BODY = r'''
if _mode == "read":
    try:
        _raw = flat_api.getBytes(_toaddr(_read), _len)
    except Exception as _e:
        print("[no data readable at 0x%x: %s]" % (_read, _e)); raise SystemExit
    _data = bytes((_x & 0xff) for _x in _raw)
    _o = 0
    while _o < len(_data):
        _chunk = _data[_o:_o + 16]
        _hx = "".join("%02x " % _c for _c in _chunk)
        _asc = "".join(chr(_c) if 32 <= _c < 127 else "." for _c in _chunk)
        print("%012x  %-48s %s" % (_read + _o, _hx, _asc))
        _o += 16
elif _mode == "list":
    _blocks = list(memory.getBlocks())
    print("memory blocks / sections (%d):" % len(_blocks))
    for _blk in _blocks:
        _perm = "%s%s%s" % ("r" if _blk.isRead() else "-", "w" if _blk.isWrite() else "-",
                            "x" if _blk.isExecute() else "-")
        print("  %-22s 0x%-12x - 0x%-12x  len=0x%-9x %s%s" % (
            _blk.getName(), _blk.getStart().getOffset(), _blk.getEnd().getOffset(),
            int(_blk.getSize()), _perm, "" if _blk.isInitialized() else " (uninit)"))
else:
    _blk = None
    for _b in memory.getBlocks():
        if _b.getName() == _section:
            _blk = _b; break
    if _blk is None:
        _have = ", ".join(_b.getName() for _b in memory.getBlocks())
        print("[no section %r -- have: %s]" % (_section, _have)); raise SystemExit
    _n = int(_blk.getSize())
    if _n > _cap:
        _n = _cap
        print("[scanning first 0x%x of 0x%x bytes; raise --cap]" % (_n, int(_blk.getSize())))
    if not _blk.isInitialized():
        print("[section %s is uninitialized (.bss-like) -- no bytes to scan]" % _section); raise SystemExit
    try:
        _raw = flat_api.getBytes(_blk.getStart(), _n)
    except Exception as _e:
        print("[cannot read section %s: %s]" % (_section, _e)); raise SystemExit
    _data = bytes((_x & 0xff) for _x in _raw)
    _base = _blk.getStart().getOffset()
    if _mode == "strings":
        _run = []; _rstart = 0; _i = 0; _count = 0
        for _c in _data:
            if 32 <= _c < 127:
                if not _run:
                    _rstart = _i
                _run.append(_c)
            else:
                if len(_run) >= _minstr:
                    print("  0x%-12x %r" % (_base + _rstart, bytes(_run).decode("ascii", "replace")))
                    _count += 1
                _run = []
            if _count >= _limit:
                break
            _i += 1
        print("[%d printable run(s) >= %d chars in %s]" % (_count, _minstr, _section))
    elif _mode == "ptrs":
        _execr = []
        for _b in memory.getBlocks():
            if _b.isExecute():
                _execr.append((_b.getStart().getOffset(), _b.getEnd().getOffset()))
        _o = 0; _count = 0
        while _o + 8 <= len(_data):
            _v = int.from_bytes(_data[_o:_o + 8], "little")
            if _v:
                _inx = False
                for _lo, _hi in _execr:
                    if _lo <= _v <= _hi:
                        _inx = True; break
                if _inx:
                    _f2 = flat_api.getFunctionAt(_toaddr(_v))
                    print("  0x%-12x -> 0x%-12x %s" % (_base + _o, _v, (_f2.getName() if _f2 else "")))
                    _count += 1
                    if _count >= _limit:
                        break
            _o += 8
        print("[%d code-pointer-like value(s) in %s (8-byte LE, aligned)]" % (_count, _section))
'''


def main():
    ap = argparse.ArgumentParser(description="Inspect blocks / read bytes / scan data (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    ap.add_argument("--read", help="hexdump bytes starting at this address (hex/decimal)")
    ap.add_argument("--len", type=int, default=256, help="bytes to hexdump for --read (default 256)")
    ap.add_argument("--section", help="block/section to scan (with --strings or --ptrs)")
    ap.add_argument("--strings", action="store_true", help="print printable ASCII runs in --section")
    ap.add_argument("--ptrs", action="store_true", help="print code-pointer-like values in --section")
    ap.add_argument("--minstr", type=int, default=4, help="min run length for --strings (default 4)")
    ap.add_argument("--limit", type=int, default=500, help="max items to print (default 500)")
    ap.add_argument("--cap", type=int, default=2 * 1024 * 1024, help="max section bytes to scan (default 2MiB)")
    a = ap.parse_args()
    p = {}
    if a.read:
        if a.section:
            ghcm.die("use either --read or --section, not both")
        p["_mode"] = "read"
        p["_read"] = ghcm.vaddr(a.read)
        p["_len"] = max(1, min(a.len, 1024 * 1024))
        p["_section"] = None
    elif a.section:
        if a.strings and a.ptrs:
            ghcm.die("--strings and --ptrs are mutually exclusive")
        if not (a.strings or a.ptrs):
            ghcm.die("--section requires --strings or --ptrs")
        p["_mode"] = "strings" if a.strings else "ptrs"
        p["_section"] = ghcm.vsection(a.section)
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
    ghcm.run(BODY, a, **p)


if __name__ == "__main__":
    main()
