#!/usr/bin/env python3
# BN-INDEPENDENT bug-class scanner for ET_REL relocatable objects (e.g. non-stripped kernel modules:
# .symtab names every func; .rela.text names every imported callee exactly). Resolves calls to allocator/
# memcpy imports, then does a LOCAL backward register-provenance scan on the size operand to classify:
#   MUL/SHIFT   -> size = count*K or count<<K  (integer-overflow -> undersized alloc / oversized copy)
#   SIGNEXT     -> size via movsx (negative 32b len -> huge 64b copy)  [e.g. a signed packet-length field]
#   MEMLOAD     -> size loaded from memory (often an attacker length field) feeding a copy
#   CONST/REG   -> constant or plain reg (lower interest)
# Fast + parallelizable: scans EVERY reachable module without a bndb. Verify hits in BN/HLIL.
#
# Usage: python3 cap_scan.py <module.elf> [--all]   (default: only MUL/SHIFT/SIGNEXT + MEMLOAD-into-copy)
import sys, argparse
from elftools.elf.elffile import ELFFile
import capstone
from capstone import x86

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# canonical 64-bit register name for any sub-register
_SUB = {}
for full, subs in {
    'rax':['eax','ax','al','ah'], 'rbx':['ebx','bx','bl','bh'], 'rcx':['ecx','cx','cl','ch'],
    'rdx':['edx','dx','dl','dh'], 'rsi':['esi','si','sil'], 'rdi':['edi','di','dil'],
    'rbp':['ebp','bp','bpl'], 'rsp':['esp','sp','spl'],
    'r8':['r8d','r8w','r8b'],'r9':['r9d','r9w','r9b'],'r10':['r10d','r10w','r10b'],
    'r11':['r11d','r11w','r11b'],'r12':['r12d','r12w','r12b'],'r13':['r13d','r13w','r13b'],
    'r14':['r14d','r14w','r14b'],'r15':['r15d','r15w','r15b'],
}.items():
    _SUB[full] = full
    for s in subs: _SUB[s] = full
def canon(rn): return _SUB.get(rn, rn)

# callee name -> which arg register holds the SIZE (System V: rdi,rsi,rdx,rcx,r8,r9)
def size_reg_for(name):
    n = name
    low = n.lower()
    if ('memcpy' in low) or ('memmove' in low) or ('bcopy' in low) or n.endswith('Memcpy') or n.endswith('Memmove'):
        return 'rdx', 'rdi'   # (size=arg2, dst=arg0)
    if 'realloc' in low:
        return 'rsi', None
    if ('heap_alloc' in low) or ('heapalloc' in low) or ('slaballoc' in low) or ('heap_allocwithra' in low) \
       or n.startswith('vmk_Heap') or ('_HeapAlloc' in n) or ('HeapAllocWithRA' in n):
        return 'rsi', None    # (heap=arg0, size=arg1)
    if low == 'malloc' or n.endswith('_Alloc') and 'Heap' not in n and 'Slab' not in n:
        return 'rdi', None    # bare malloc-style(size)
    return None, None

def reloc_map(elf, text_idx):
    # .text offset of a rel32 operand -> target symbol name (for call/jmp imports)
    rmap = {}
    symtab = elf.get_section_by_name('.symtab')
    rela = elf.get_section_by_name('.rela.text')
    if rela is None or symtab is None:
        return rmap
    for r in rela.iter_relocations():
        sym = symtab.get_symbol(r['r_info_sym'])
        if sym and sym.name:
            rmap[r['r_offset']] = sym.name
    return rmap

def classify(prov):
    if prov is None: return None
    m = prov.mnemonic
    if m in ('shl','sal','shld'): return 'SHIFT'
    if m in ('imul','mul'): return 'MUL'
    if m == 'lea':
        for op in prov.operands:
            if op.type == x86.X86_OP_MEM and op.mem.scale > 1: return 'LEA_SCALE'
        return None
    if m in ('movsx','movsxd'):
        # refine: the FreeBSD `int m_len` idiom is movsxd from [reg+0x18] (mbuf length) — benign/noisy.
        for op in prov.operands:
            if op.type == x86.X86_OP_MEM and op.mem.disp == 0x18 and canon(prov.reg_name(op.mem.base) if op.mem.base else '') not in ('rsp','rbp'):
                return 'MBUF_LEN'
        return 'SIGNEXT'
    if m in ('mov','movzx'):
        for op in prov.operands:
            if op.type == x86.X86_OP_MEM:
                base = prov.reg_name(op.mem.base) if op.mem.base else ''
                # load from memory; flag if not a pure stack/frame constant slot
                return 'MEMLOAD' if canon(base) not in ('rsp','rbp','') else 'STACKLOAD'
            if op.type == x86.X86_OP_IMM: return 'CONST'
        return 'REG'
    return None

def dest_class(prov, uses_fp):
    # classify a copy DESTINATION register's provenance: STACK buffer vs pointer.
    # [rsp+off] is ALWAYS stack. [rbp+off] is stack ONLY when the function established rbp as the frame
    # pointer (mov rbp,rsp in the prologue); otherwise (FPO / -fomit-frame-pointer) rbp is a general
    # register holding a pointer, and [rbp+off] is a heap/context deref (the vmknvme NVMFAuth FP class).
    if prov is None: return None, None
    if prov.mnemonic == 'lea':
        for op in prov.operands:
            if op.type == x86.X86_OP_MEM:
                base = canon(prov.reg_name(op.mem.base) if op.mem.base else '')
                if base == 'rsp':
                    return 'STACK', op.mem.disp
                if base == 'rbp' and uses_fp:
                    return 'STACK', op.mem.disp
                return 'PTR', None
    if prov.mnemonic in ('mov', 'movzx'):
        for op in prov.operands:
            if op.type == x86.X86_OP_MEM:
                return 'HEAPLOAD', None
    return None, None

def scan(path, show_all=False):
    with open(path,'rb') as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name('.text')
        if text is None: return []
        text_idx = list(elf.iter_sections()).index(text)
        data = text.data()
        rmap = reloc_map(elf, text_idx)
        symtab = elf.get_section_by_name('.symtab')
        funcs = []
        for s in symtab.iter_symbols():
            if s['st_info']['type']=='STT_FUNC' and s['st_size']>0 and s['st_shndx']==text_idx:
                funcs.append((s['st_value'], s['st_size'], s.name))
        hits = []
        for addr, size, name in funcs:
            try:
                code = data[addr:addr+size]
                hist = []   # list of insns in order
                lastwrite = {}  # canon reg -> index in hist
                uses_fp = False  # does this function establish rbp as the frame pointer?
                for insn in md.disasm(code, addr):
                    if insn.mnemonic == 'mov' and insn.op_str.replace(' ', '') == 'rbp,rsp':
                        uses_fp = True
                    # resolve a call/jmp import target via the rel32 reloc at insn.address+1
                    callee = None
                    if insn.mnemonic in ('call','jmp'):
                        callee = rmap.get(insn.address+1)
                    if callee:
                        szr, dstr = size_reg_for(callee)
                        if szr:
                            prov = hist[lastwrite[szr]] if szr in lastwrite else None
                            cls = classify(prov)
                            # destination classification (copies have dstr=rdi); STACK = lea rsp/rbp+off
                            dcls, doff = (None, None)
                            if dstr:
                                dprov = hist[lastwrite[dstr]] if dstr in lastwrite else None
                                dcls, doff = dest_class(dprov, uses_fp)
                            provtxt = ('%s %s' % (prov.mnemonic, prov.op_str)) if prov else '?'
                            # STACKCOPY: copy into a stack buffer with a NON-constant length = stack-overflow class
                            stackcopy = (dstr is not None and dcls == 'STACK' and cls != 'CONST')
                            interesting = cls in ('MUL','SHIFT','LEA_SCALE','SIGNEXT','MEMLOAD')
                            if stackcopy:
                                dtag = 'STACK[len=%s,off=%s]' % (cls or 'UNK', hex(doff) if doff is not None else '?')
                                hits.append((name, addr+(insn.address-addr), insn.address, callee, 'STACKCOPY', provtxt[:46], dtag))
                            elif interesting or show_all:
                                dtag = ('STACKDST' if dcls == 'STACK' else (dcls or ''))
                                hits.append((name, addr+(insn.address-addr), insn.address, callee, cls or '?', provtxt[:46], dtag))
                    # record writes
                    try:
                        _, wregs = insn.regs_access()
                    except Exception:
                        wregs = []
                    for w in wregs:
                        lastwrite[canon(insn.reg_name(w))] = len(hist)
                    hist.append(insn)
            except Exception:
                continue
        return hits

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('path'); ap.add_argument('--all', action='store_true')
    a = ap.parse_args()
    hits = scan(a.path, a.all)
    # rank: STACKCOPY (stack-overflow) first, then SIGNEXT/MUL/SHIFT, then MEMLOAD-into-copy
    order = {'STACKCOPY':0,'SIGNEXT':1,'MUL':2,'SHIFT':2,'LEA_SCALE':3,'MEMLOAD':4}
    hits.sort(key=lambda h: order.get(h[4], 9))
    print("%s: %d candidates" % (a.path.split('/')[-1], len(hits)))
    for name, _o, ad, callee, cls, prov, dst in hits[:200]:
        print("  %-40s 0x%-6x %-18s %-9s %-46s %s" % (name[:40], ad, callee[:18], cls, prov, dst))
