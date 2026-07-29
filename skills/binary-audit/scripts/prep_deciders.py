#!/usr/bin/env python3
"""prep_deciders.py N  -> emit decider-wf-bN.js for the next <=8 pending (bug,decider) pairs.
Bootstraps decider-worklist.json from the audit table on first run. Iterative-deepening to a fixpoint:
each round audits the current frontier of named deciders; ingest_deciders.py resolves or extends it."""
import sys, json, sqlite3, subprocess, re, os
import os
_SD=os.path.dirname(os.path.abspath(__file__))
N=int(sys.argv[1]); ROOT=os.environ.get("KAUDIT_ROOT","."); WL=f"{ROOT}/decider-worklist.json"
con=sqlite3.connect(f"{ROOT}/kreview.db"); DC=os.path.expanduser('~/projects/disasm-codemode/bin/bn-decompile')
SYMS=sorted((r[0] for r in con.execute("SELECT name FROM func") if r[0]), key=len, reverse=True)
def find_sym(text):
    if not text: return None
    m=re.search(r'[Pp]ull\s+([A-Za-z_][\w.]+)', text)              # "Pull <Symbol>"
    if m and m.group(1) in SYMS: return m.group(1)
    for s in SYMS:                                                  # else longest known symbol present
        if len(s)>6 and s in text: return s
    return None
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

if os.path.exists(WL):
    wl=json.load(open(WL))
else:   # bootstrap frontier from audit-table uncertain/partial verdicts
    wl={"frontier":[], "audited":{}, "round":0}; seen=set()
    for fn,nxt in con.execute("SELECT a.func_name,a.next FROM audit a JOIN bug b ON b.func_name=a.func_name WHERE a.verdict IN ('uncertain','partial') AND b.status IN ('uncertain','partial') GROUP BY a.func_name"):
        dec=find_sym(nxt)
        if dec and dec!=fn and (fn,dec) not in seen:
            seen.add((fn,dec))
            b=con.execute("SELECT desc FROM bug WHERE func_name=? LIMIT 1",(fn,)).fetchone()
            wl["frontier"].append({"consumer":fn,"decider":dec,"bug_desc":(b[0] if b else fn)[:600],
                "precondition":(nxt or '')[:300],"status":"pending"})
    print(f"bootstrapped frontier: {len(wl['frontier'])} (bug,decider) pairs")

wl["round"]=N
pending=[p for p in wl["frontier"] if p["status"]=="pending"][:8]
tasks=[]
for p in pending:
    dec=ensure(p["decider"]); cons=ensure(p["consumer"])
    if not dec or not cons: p["status"]="exhausted-extsym"; continue
    p["status"]="inflight"
    tasks.append(dict(id=f"{p['consumer']}__via__{p['decider']}", consumer=cons, decider=dec,
                      bug_desc=p["bug_desc"], precondition=p["precondition"]))
json.dump(wl, open(WL,'w'), indent=0)
if not tasks:
    print("NO PENDING TASKS — frontier exhausted (fixpoint). Run the final summary."); sys.exit(0)
tmpl=open(os.path.join(_SD,"decider-template.js")).read()
_repl="const TASKS = "+json.dumps(tasks)
tmpl=re.sub(r'^const TASKS = .*$', lambda m:_repl, tmpl, count=1, flags=re.M)
outp=f"{ROOT}/decider-wf-b{N}.js"; open(outp,'w').write(tmpl)
print(f"decider-round{N}: {len(tasks)} tasks -> {os.path.abspath(outp)} | frontier pending left: {sum(1 for p in wl['frontier'] if p['status']=='pending')}")
