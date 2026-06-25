#!/usr/bin/env python3
"""kernel-review metric extractor: per-function structural + memory-safety features
+ resolved call graph, over a symbol-rich ELF. Emits kreview.db (sqlite).

Features (cheap pass, capstone): size, cc (CFG E-N+2), loops (back-edges),
n_mem, n_memidx (computed addressing), n_arith, calls (direct/indirect),
sink_calls (memcpy/alloc-class), state_calls (free/lock/refcount),
parse_off (distinct [reg+disp] read offsets = parser signature).
"""
import sys, re, sqlite3, subprocess
import os
from collections import defaultdict
import capstone

BIN = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("KAUDIT_BIN","target.elf")
DB  = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("KAUDIT_ROOT",".")+"/kreview.db"
PROFILE = sys.argv[3] if len(sys.argv) > 3 else None

# defaults = ESXi vmkernel; override with a profile JSON (sink_regex / state_regex). See profiles/.
_DEF_SINK  = r'(_?vmk_)?(Memcpy|Memmove|memcpy|memmove|memset|bcopy|strcpy|strncpy|strcat|strlcpy|sprintf|CopyIn|CopyOut|CopyFromMachine|Heap_?Alloc|Mem_?Alloc|Pkt_?Alloc|World_?Alloc|MemAlloc)'
_DEF_STATE = r'(_?vmk_)?(Free|Release|Put|RefCount|Ref_|_Lock|_Unlock|SpinLock|SP_Lock|SP_Unlock|Mutex|Sema)'
_prof = __import__('json').load(open(PROFILE)) if PROFILE else {}
SINK_RE  = re.compile(_prof.get('sink_regex',  _DEF_SINK),  re.I)
STATE_RE = re.compile(_prof.get('state_regex', _DEF_STATE), re.I)

def sh_exec_sections(binp):
    secs = []
    for ln in subprocess.run(['readelf','-SW',binp],capture_output=True,text=True).stdout.splitlines():
        # [Nr] Name Type Addr Off Size ES Flg Lk Inf Al
        m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+\S+\s+(\S*)', ln)
        if m and 'X' in m.group(6):
            secs.append((m.group(1), int(m.group(3),16), int(m.group(4),16), int(m.group(5),16)))
    return secs

def funcs(binp):
    out = {}
    for ln in subprocess.run(['readelf','-sW',binp],capture_output=True,text=True).stdout.splitlines():
        f = ln.split()
        if len(f) >= 8 and f[3] == 'FUNC':
            try:
                addr = int(f[1],16); size = int(f[2]); name = f[7]
            except: continue
            if size == 0 or addr == 0: continue
            if addr not in out: out[addr] = (name, size)
    return out

def file_off(secs, vaddr):
    for nm,a,o,s in secs:
        if a <= vaddr < a+s: return o + (vaddr-a)
    return None

def main():
    secs = sh_exec_sections(BIN)
    fmap = funcs(BIN)
    addrs = sorted(fmap)
    data = open(BIN,'rb').read()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    X86 = capstone.x86
    JCC = set(range(X86.X86_INS_JAE, X86.X86_INS_JS+1))  # conditional jumps cluster
    rows = []; edges = []
    name2addr = {n:a for a,(n,s) in fmap.items()}
    for i,addr in enumerate(addrs):
        name,size = fmap[addr]
        off = file_off(secs, addr)
        if off is None: continue
        code = data[off:off+size]
        insns = list(md.disasm(code, addr))
        if not insns: continue
        n = len(insns)
        ins_addrs = {ins.address for ins in insns}
        leaders = {addr}; succ = defaultdict(set)
        n_arith=n_mem=n_memidx=n_call=n_callind=sink=state=loops=0
        parse_off=set()
        ARITH = {'add','sub','imul','mul','shl','sal','shr','sar','and','or','xor','lea','inc','dec','adc','sbb'}
        for idx,ins in enumerate(insns):
            mn = ins.mnemonic
            nxt = insns[idx+1].address if idx+1 < n else None
            if mn in ARITH: n_arith += 1
            # memory operands
            has_mem=False; idxreg=False
            for op in ins.operands:
                if op.type == X86.X86_OP_MEM:
                    has_mem=True
                    if op.mem.index != 0: idxreg=True
                    # parser signature: read off a base reg w/ displacement
                    if op.mem.base != 0 and op.mem.disp != 0 and 0 < op.mem.disp < 0x4000:
                        parse_off.add(op.mem.disp)
            if has_mem: n_mem += 1
            if idxreg: n_memidx += 1
            # control flow
            if mn == 'call':
                n_call += 1
                op0 = ins.operands[0] if ins.operands else None
                if op0 and op0.type == X86.X86_OP_IMM:
                    tgt = op0.imm
                    edges.append((addr, tgt))
                    tn = fmap.get(tgt,(None,))[0]
                    if tn and SINK_RE.search(tn): sink += 1
                    if tn and STATE_RE.search(tn): state += 1
                else:
                    n_callind += 1
            elif ins.id in JCC:
                op0 = ins.operands[0]
                if op0.type == X86.X86_OP_IMM:
                    tgt = op0.imm
                    if tgt < ins.address: loops += 1
                    if tgt in ins_addrs: leaders.add(tgt); succ[ins.address].add(tgt)
                if nxt: leaders.add(nxt); succ[ins.address].add(nxt)
            elif mn == 'jmp':
                op0 = ins.operands[0]
                if op0.type == X86.X86_OP_IMM:
                    tgt = op0.imm
                    if tgt < ins.address and tgt in ins_addrs: loops += 1
                    if tgt in ins_addrs: leaders.add(tgt); succ[ins.address].add(tgt)
                if nxt: leaders.add(nxt)  # leader, but no fallthrough edge from jmp
            elif mn.startswith('ret') or mn == 'ud2':
                pass
            else:
                if nxt and nxt in leaders: succ[ins.address].add(nxt)
        # CFG: count BBs (leaders within func) and edges between BBs
        leaders = {l for l in leaders if l in ins_addrs}
        N = len(leaders)
        # edges: for each insn that is a terminator with succ, those are BB edges; also fallthrough into a leader
        E = 0
        for idx,ins in enumerate(insns):
            s = succ.get(ins.address)
            nxt = insns[idx+1].address if idx+1 < n else None
            if s: E += len(s)
            elif nxt and nxt in leaders and not ins.mnemonic.startswith('ret') and ins.mnemonic!='jmp':
                E += 1  # fallthrough edge into next BB
        cc = max(1, E - N + 2)
        rows.append((addr,name,size,n,cc,loops,n_mem,n_memidx,n_arith,n_call,n_callind,sink,state,len(parse_off)))
        if i % 3000 == 0: print(f"  {i}/{len(addrs)}", file=sys.stderr)
    # write db
    con = sqlite3.connect(DB); cur = con.cursor()
    cur.executescript("""DROP TABLE IF EXISTS func; DROP TABLE IF EXISTS edge;
      CREATE TABLE func(addr INTEGER PRIMARY KEY,name TEXT,size INT,n_insns INT,cc INT,loops INT,
        n_mem INT,n_memidx INT,n_arith INT,n_call INT,n_callind INT,sink_calls INT,state_calls INT,parse_off INT);
      CREATE TABLE edge(caller INTEGER,callee INTEGER);""")
    cur.executemany("INSERT OR REPLACE INTO func VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    cur.executemany("INSERT INTO edge VALUES(?,?)", [(c,t) for c,t in edges if t in fmap])
    cur.execute("CREATE INDEX ix_edge_callee ON edge(callee)")
    cur.execute("CREATE INDEX ix_edge_caller ON edge(caller)")
    cur.execute("CREATE INDEX ix_func_name ON func(name)")
    con.commit()
    print(f"functions={len(rows)} edges={cur.execute('SELECT COUNT(*) FROM edge').fetchone()[0]}")
    con.close()

if __name__ == "__main__":
    main()
