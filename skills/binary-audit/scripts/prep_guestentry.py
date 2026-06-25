#!/usr/bin/env python3
"""prep_guestentry.py -> emit guestentry-wf.js: one unbounded deep-dive task per exhausted-guest-entry
consumer, bundling the consumer + its chain + the residual functions its audit named (extracted), to drive
it to confirmed-violable / refuted / needs-live-poc / still-blocked-external."""
import sys, json, sqlite3, subprocess, re, os
import os
_SD=os.path.dirname(os.path.abspath(__file__))
ROOT=os.environ.get("KAUDIT_ROOT",".")
con=sqlite3.connect(f"{ROOT}/kreview.db"); DC=os.path.expanduser('~/projects/disasm-codemode/bin/bn-decompile')
SYMS=set(r[0] for r in con.execute("SELECT name FROM func") if r[0])
def ensure(fn):
    r=con.execute("SELECT printf('0x%x',addr),printf('0x%x',addr+size) FROM func WHERE name=?", (fn,)).fetchone()
    if not r: return None
    hl=f"{ROOT}/hlil/{fn}.hlil.c"; am=f"{ROOT}/asm/{fn}.asm"
    if not os.path.exists(hl) or os.path.getsize(hl)<80:
        try: open(hl,'w').write(subprocess.run([DC,'--bv-match',os.environ.get('KAUDIT_BVMATCH',os.path.basename(os.environ.get('KAUDIT_BIN','target.elf'))),fn],capture_output=True,text=True,timeout=150).stdout)
        except Exception as e: print("  hlil-fail",fn,e)
    if not os.path.exists(am) or os.path.getsize(am)<80:
        d=subprocess.run(['objdump','-d','--no-show-raw-insn',f'--start-address={r[0]}',f'--stop-address={r[1]}',os.environ.get("KAUDIT_BIN","target.elf")],capture_output=True,text=True).stdout
        open(am,'w').write("\n".join(l for l in d.splitlines() if l.strip() and 'file format' not in l and 'Disassembly' not in l))
    return dict(name=fn,hlil=hl,asm=am)
TOK=re.compile(r'\b([A-Za-z_][A-Za-z0-9_]{6,})\b')
consumers=[r[0] for r in con.execute("SELECT DISTINCT func_name FROM bug WHERE status='exhausted-guest-entry'")]
tasks=[]
for c in consumers:
    rows=con.execute("SELECT residual,guest_path,evidence,next FROM audit WHERE verdict='guest-entry' AND (func_name=? OR evidence LIKE ?)", (c, f'%decides {c}%')).fetchall()
    residual=" | ".join(r[0] for r in rows if r[0])[:600]
    guest_path=" | ".join(r[1] for r in rows if r[1])[:600]
    blob=" ".join((r[0] or '')+' '+(r[2] or '')+' '+(r[3] or '') for r in rows)
    cand=[]
    for m in TOK.findall(blob):
        if m in SYMS and m!=c and m not in cand: cand.append(m)
    # consumer first, then up to 6 residual/chain functions
    funcs=[ensure(c)]; external=[]
    for fn in cand[:6]:
        e=ensure(fn)
        if e: funcs.append(e)
    funcs=[f for f in funcs if f]
    # external = symbol-ish tokens NOT in func table (vmk_*, *_RA, etc.)
    for m in set(TOK.findall(blob)):
        if m not in SYMS and ('_' in m or m[:3].lower()=='vmk') and len(m)>8 and m not in external:
            external.append(m)
    tasks.append(dict(id=c, consumer=funcs[0], residual=residual or '(see guest_path)', guest_path=guest_path,
                      funcs=funcs, external=external[:6]))
tmpl=open(os.path.join(_SD,"guestentry-template.js")).read()
_repl="const TASKS = "+json.dumps(tasks)
tmpl=re.sub(r'^const TASKS = .*$', lambda m:_repl, tmpl, count=1, flags=re.M)
outp=f"{ROOT}/guestentry-wf.js"; open(outp,'w').write(tmpl)
print(f"guest-entry deep-dive: {len(tasks)} tasks -> {os.path.abspath(outp)}")
for t in tasks: print(f"  {t['id']}: +{len(t['funcs'])-1} residual fns, {len(t['external'])} external-flagged")
