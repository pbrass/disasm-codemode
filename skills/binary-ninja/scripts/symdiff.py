#!/usr/bin/env python3
# Fast symbol-matched code differ for NON-stripped ELFs (e.g. hostd: 6183 FUNC symbols).
# Disassembles each named function with capstone, normalizes away layout noise (branch targets +
# RIP-relative displacements masked; registers + struct offsets + immediates kept), hashes it, and
# diffs by symbol name across two builds. Far faster than ghidriff (no decompilation).
#
# Usage: python3 symdiff.py <old.elf> <new.elf> [--filter REGEX] [--demangle] [--list]
import sys, hashlib, re, argparse, subprocess
from elftools.elf.elffile import ELFFile
import capstone
from capstone import x86

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def norm_insn(insn):
    m = insn.mnemonic
    if m == 'call' or m.startswith('j') or m.startswith('loop'):
        return m + ' @'                      # mask branch/call target (shifts with layout)
    if m == 'push' and insn.operands and insn.operands[0].type == x86.X86_OP_IMM:
        return 'push #'                      # mask push-immediates = __LINE__ constants (shift w/ unrelated edits)
    ops = []
    for op in insn.operands:
        if op.type == x86.X86_OP_REG:
            ops.append(insn.reg_name(op.reg))
        elif op.type == x86.X86_OP_IMM:
            ops.append('#%x' % (op.imm & 0xffffffffffffffff))   # PIE: genuine constant -> keep
        elif op.type == x86.X86_OP_MEM:
            mem = op.mem
            base = insn.reg_name(mem.base) if mem.base else ''
            if base == 'rip':
                ops.append('[rip+@]')        # rip-relative data ref -> mask (address)
            else:
                idx = insn.reg_name(mem.index) if mem.index else ''
                ops.append('[%s+%s*%d+%x]' % (base, idx, mem.scale, mem.disp & 0xffffffff))  # struct offset -> keep
        else:
            ops.append('?')
    return m + ' ' + ','.join(ops)

def load_funcs(path):
    funcs = {}      # name -> (normhash, size)
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        # build a vaddr -> (section data, sh_addr) map for executable sections
        secs = []
        for s in elf.iter_sections():
            if s['sh_flags'] & 0x4 and s['sh_type'] == 'SHT_PROGBITS':   # SHF_EXECINSTR
                secs.append((s['sh_addr'], s['sh_addr'] + s['sh_size'], s.data()))
        # functions may live in .symtab and/or .dynsym (hostd: 6183 FUNC are in .dynsym, but st_size=0).
        # Collect FUNC (name, addr) in exec sections, then derive each extent from the gap to the next addr.
        def sec_of(va):
            for lo, hi, sd in secs:
                if lo <= va < hi:
                    return lo, hi, sd
            return None
        byaddr = {}   # addr -> [names]
        tables = [t for t in (elf.get_section_by_name('.symtab'), elf.get_section_by_name('.dynsym')) if t]
        for t in tables:
            for sym in t.iter_symbols():
                if sym['st_info']['type'] != 'STT_FUNC' or not sym.name:
                    continue
                va = sym['st_value']
                if sec_of(va):
                    byaddr.setdefault(va, [])
                    if sym.name not in byaddr[va]:
                        byaddr[va].append(sym.name)
        addrs = sorted(byaddr)
        for i, va in enumerate(addrs):
            lo, hi, sd = sec_of(va)
            end = addrs[i+1] if i+1 < len(addrs) and addrs[i+1] <= hi else hi   # gap to next func (or section end)
            sz = end - va
            if sz <= 0 or sz > 0x40000:   # skip absurd gaps (func->data boundary)
                continue
            data = sd[va - lo: va - lo + sz]
            h = hashlib.sha1()
            for insn in md.disasm(data, va):
                h.update(norm_insn(insn).encode())
            dig = h.hexdigest()
            for nm in byaddr[va]:
                funcs[nm] = (dig, sz)
    return funcs

def demangle(names):
    if not names:
        return {}
    try:
        out = subprocess.run(['c++filt'], input='\n'.join(names), capture_output=True, text=True, timeout=30)
        return dict(zip(names, out.stdout.splitlines()))
    except Exception:
        return {n: n for n in names}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('old'); ap.add_argument('new')
    ap.add_argument('--filter', default=None, help='regex on (demangled) name to highlight')
    ap.add_argument('--demangle', action='store_true')
    ap.add_argument('--list', action='store_true', help='print every changed function')
    a = ap.parse_args()
    print(f"[*] loading {a.old} ..."); fo = load_funcs(a.old)
    print(f"[*] loading {a.new} ..."); fn = load_funcs(a.new)
    co, cn = set(fo), set(fn)
    common = co & cn
    changed = sorted(n for n in common if fo[n][0] != fn[n][0])
    added = sorted(cn - co); removed = sorted(co - cn)
    print(f"\n[*] {a.old} funcs={len(fo)}  {a.new} funcs={len(fn)}  common={len(common)}")
    print(f"[*] CHANGED={len(changed)}  added={len(added)}  removed={len(removed)}")
    dm = demangle(changed + added + removed) if (a.demangle or a.filter) else {n: n for n in changed+added+removed}
    if a.filter:
        rx = re.compile(a.filter, re.I)
        hits = [n for n in changed if rx.search(dm.get(n, n))]
        print(f"\n=== CHANGED matching /{a.filter}/  ({len(hits)}) ===")
        for n in hits:
            print(f"  [chg] {dm.get(n,n)}")
        ah = [n for n in added if rx.search(dm.get(n,n))]
        if ah:
            print(f"--- ADDED matching ---")
            for n in ah: print(f"  [add] {dm.get(n,n)}")
    if a.list:
        print(f"\n=== ALL CHANGED ({len(changed)}) ===")
        for n in changed:
            print(f"  {dm.get(n,n)}")

if __name__ == '__main__':
    main()
