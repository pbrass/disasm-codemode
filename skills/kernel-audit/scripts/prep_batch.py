#!/usr/bin/env python3
"""prep_batch.py N  -> extract HLIL+asm for batch N's 25 funcs (skip existing),
emit <root>/review-wf-bN.js (workflow script w/ embedded FNS)."""
import sys, json, sqlite3, subprocess, re, os
import os
_SD=os.path.dirname(os.path.abspath(__file__))
N=int(sys.argv[1])
ROOT=os.environ.get("KAUDIT_ROOT",".")
batches=json.load(open(f"{ROOT}/batches.json"))
names=batches[N-1]
con=sqlite3.connect(f"{ROOT}/kreview.db")
DC=os.path.expanduser('~/projects/disasm-codemode/bin/bn-decompile')
os.makedirs(f"{ROOT}/hlil",exist_ok=True); os.makedirs(f"{ROOT}/asm",exist_ok=True)
fns=[]
for nm in names:
    r=con.execute("SELECT printf('0x%x',addr),printf('0x%x',addr+size),cc,n_memidx,sink_calls,parse_off,n_insns FROM func WHERE name=?", (nm,)).fetchone()
    if not r: print("  MISSING",nm); continue
    start,stop,cc,mi,sk,pa,ins=r
    hl=f"{ROOT}/hlil/{nm}.hlil.c"; am=f"{ROOT}/asm/{nm}.asm"
    if not os.path.exists(hl) or os.path.getsize(hl)<80:
        try: open(hl,'w').write(subprocess.run([DC,'--bv-match',os.environ.get('KAUDIT_BVMATCH',os.path.basename(os.environ.get('KAUDIT_BIN','target.elf'))),nm],capture_output=True,text=True,timeout=150).stdout)
        except Exception as e: print("  HLIL-fail",nm,e)
    if not os.path.exists(am) or os.path.getsize(am)<80:
        d=subprocess.run(['objdump','-d','--no-show-raw-insn',f'--start-address={start}',f'--stop-address={stop}',os.environ.get("KAUDIT_BIN","target.elf")],capture_output=True,text=True).stdout
        open(am,'w').write("\n".join(l for l in d.splitlines() if l.strip() and 'file format' not in l and 'Disassembly' not in l))
    fns.append(dict(name=nm,addr=start,cc=cc,memidx=mi,sink=sk,parse=pa,insns=ins,hlil=hl,asm=am))
tmpl=open(os.path.join(_SD,"review-wf.js")).read()
_repl="const FNS = "+json.dumps(fns)
tmpl=re.sub(r'^const FNS = .*$', lambda m: _repl, tmpl, count=1, flags=re.M)
outp=f"{ROOT}/review-wf-b{N}.js"
open(outp,'w').write(tmpl)
print(f"batch{N}: {len(fns)}/{len(names)} fns prepped -> {os.path.abspath(outp)}")
