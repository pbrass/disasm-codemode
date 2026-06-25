#!/usr/bin/env python3
"""prep_phase2.py N -> build phase-2 audit tasks for phase2-batches.json[N-1]:
for each suspected-bug function, gather its bug record + caller-owed preconditions + its callers
(lynchpins), extract HLIL+asm for the function and its callers, emit phase2-wf-bN.js."""
import sys, json, sqlite3, subprocess, re, os
import os
_SD=os.path.dirname(os.path.abspath(__file__))
N=int(sys.argv[1]); ROOT=os.environ.get("KAUDIT_ROOT",".")
con=sqlite3.connect(f"{ROOT}/kreview.db"); DC=os.path.expanduser('~/projects/disasm-codemode/bin/bn-decompile')
names=json.load(open(f"{ROOT}/phase2-batches.json"))[N-1]
def ensure(fn):
    hl=f"{ROOT}/hlil/{fn}.hlil.c"; am=f"{ROOT}/asm/{fn}.asm"
    r=con.execute("SELECT printf('0x%x',addr),printf('0x%x',addr+size) FROM func WHERE name=?", (fn,)).fetchone()
    if not r: return None
    if not os.path.exists(hl) or os.path.getsize(hl)<80:
        try: open(hl,'w').write(subprocess.run([DC,'--bv-match',os.environ.get('KAUDIT_BVMATCH',os.path.basename(os.environ.get('KAUDIT_BIN','target.elf'))),fn],capture_output=True,text=True,timeout=150).stdout)
        except Exception as e: print("  hlil-fail",fn,e)
    if not os.path.exists(am) or os.path.getsize(am)<80:
        d=subprocess.run(['objdump','-d','--no-show-raw-insn',f'--start-address={r[0]}',f'--stop-address={r[1]}',os.environ.get("KAUDIT_BIN","target.elf")],capture_output=True,text=True).stdout
        open(am,'w').write("\n".join(l for l in d.splitlines() if l.strip() and 'file format' not in l and 'Disassembly' not in l))
    return dict(name=fn,hlil=hl,asm=am)
tasks=[]
for fn in names:
    frow=con.execute("SELECT addr FROM func WHERE name=?", (fn,)).fetchone()
    if not frow: print("  MISSING",fn); continue
    addr=frow[0]
    bugs=con.execute("SELECT desc,why,location,confidence,severity FROM bug WHERE func_name=? AND status='open'", (fn,)).fetchall()
    desc=" || ".join(b[0] or '' for b in bugs); why=" || ".join(b[1] or '' for b in bugs)
    loc=" ; ".join(b[2] or '' for b in bugs);
    preconds=con.execute("SELECT text,kind,attack_note FROM precondition WHERE func_addr=? AND klass IN ('caller','unguaranteed')", (addr,)).fetchall()
    preconditions=[dict(text=t,kind=k,attack_note=a or '') for (t,k,a) in preconds][:6]
    # callers (lynchpins), top 3 by score
    callers=con.execute("""SELECT cf.name FROM edge e JOIN func cf ON cf.addr=e.caller
        WHERE e.callee=? GROUP BY cf.name ORDER BY MAX(cf.score) DESC LIMIT 3""", (addr,)).fetchall()
    cons=ensure(fn)
    lyn=[c for c in (ensure(cn[0]) for cn in callers) if c]
    tasks.append(dict(id=fn, theme=(bugs[0][3] if bugs else '')+'/'+(bugs[0][4][:30] if bugs and bugs[0][4] else ''),
                      bug_desc=desc[:1200], bug_why=why[:800], bug_location=loc[:300],
                      preconditions=preconditions, consumer=cons, lynchpins=lyn))
tmpl=open(os.path.join(_SD,"phase2-template.js")).read()
_repl="const TASKS = "+json.dumps(tasks)
tmpl=re.sub(r'^const TASKS = .*$', lambda m: _repl, tmpl, count=1, flags=re.M)
outp=f"{ROOT}/phase2-wf-b{N}.js"; open(outp,'w').write(tmpl)
print(f"phase2-batch{N}: {len(tasks)} tasks (callers extracted as lynchpins) -> {os.path.abspath(outp)}")
