#!/usr/bin/env python3
"""ingest_deciders.py <workflow-output.json>  -> resolve decider verdicts + extend the frontier.
established-safe->consumer bug refuted; violable-bug->confirmed-violable; partial->partial(stop);
uncertain->append the named next decider (depth-capped, cycle-guarded). Fixpoint when no pending left."""
import sys, json, sqlite3, re, os
import os
ROOT=os.environ.get("KAUDIT_ROOT","."); WL=f"{ROOT}/decider-worklist.json"; MAXDEPTH=5
recs=json.loads(re.search(r'\[\s*\{.*\}\s*\]',open(sys.argv[1]).read(),re.S).group(0))
wl=json.load(open(WL)); con=sqlite3.connect(f"{ROOT}/kreview.db"); cur=con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, func_name TEXT, verdict TEXT, evidence TEXT, guest_path TEXT, residual TEXT, next TEXT, confidence TEXT, guard TEXT)")
try: cur.execute("ALTER TABLE audit ADD COLUMN guard TEXT")
except Exception: pass
SYMS=set(r[0] for r in cur.execute("SELECT name FROM func") if r[0])
SYMSL=sorted((s for s in SYMS if s), key=len, reverse=True)
# terminal verdict -> bug.status. The three differentiated exhaustion reasons (guest-entry / external / depthcap)
# carry very different meaning: guest-entry LEANS VIOLABLE, external = undecidable here, depthcap = resumable.
TERM={'established-safe':'refuted','violable-bug':'confirmed-violable','guest-entry':'exhausted-guest-entry',
      'partial':'partial','uncertain-external':'exhausted-extsym'}
def find_sym(text):
    if not text: return None
    m=re.search(r'([A-Za-z_][\w.]{6,})', text)
    if m and m.group(1) in SYMS: return m.group(1)
    for s in SYMSL:
        if len(s)>6 and s in text: return s
    return None
def pair(c,d): return next((p for p in wl["frontier"] if p["consumer"]==c and p["decider"]==d), None)
tally={}
for r in recs:
    tid=r.get('target','') or ''
    if '__via__' not in tid:  # fallback: match any inflight pair by decider name in target
        cand=[p for p in wl["frontier"] if p["status"]=="inflight" and p["decider"] in tid]
        if not cand: continue
        c,d=cand[0]["consumer"],cand[0]["decider"]
    else:
        c,d=tid.split('__via__',1)
    v=r.get('verdict','uncertain-continue'); tally[v]=tally.get(v,0)+1
    p=pair(c,d); depth=(p.get("depth",1) if p else 1)
    if p: p["status"]="done"; p["verdict"]=v
    wl.setdefault("audited",{})[d]=v
    cur.execute("INSERT INTO audit(func_name,verdict,evidence,guest_path,residual,next,confidence) VALUES(?,?,?,?,?,?,?)",
      (d,v,(r.get('evidence') or '')[:8000]+f"  [decides {c}]",(r.get('guest_reachable_path') or '')[:8000],(r.get('residual_unknowns') or '')[:2000],(r.get('recommended_next') or '')[:1000],r.get('confidence','')))
    newstatus=None
    if v in TERM:
        newstatus=TERM[v]
    elif v=='uncertain-continue':
        d2=find_sym(r.get('recommended_next',''))
        chain_decs={pp["decider"] for pp in wl["frontier"] if pp["consumer"]==c}
        if not d2 or d2 not in SYMS or d2==c:                newstatus='exhausted-extsym'   # external symbol
        elif d2 in chain_decs or d2 in wl.get('audited',{}): newstatus='exhausted-cycle'
        elif depth>=MAXDEPTH:                                newstatus='exhausted-depthcap' # tooling limit (resumable)
        else:
            b=cur.execute("SELECT desc FROM bug WHERE func_name=? LIMIT 1",(c,)).fetchone()
            wl["frontier"].append({"consumer":c,"decider":d2,"bug_desc":(b[0] if b else c)[:2000],
                "precondition":(r.get('recommended_next') or '')[:1000],"status":"pending","depth":depth+1})
    if newstatus:
        cur.execute("UPDATE bug SET status=? WHERE func_name=? AND status NOT IN ('confirmed-violable')", (newstatus,c))
con.commit(); json.dump(wl,open(WL,'w'),indent=0)
pend=sum(1 for p in wl["frontier"] if p["status"]=="pending")
print(f"ingested {len(recs)} decider verdicts:", tally)
print(f"frontier pending (next round): {pend}  | {'FIXPOINT - run final summary' if pend==0 else 'continue'}")
print("bug.status:", dict(cur.execute("SELECT status,COUNT(*) FROM bug GROUP BY status").fetchall()))
