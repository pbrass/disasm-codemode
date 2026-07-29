#!/usr/bin/env python3
"""ingest_deciders.py <workflow-output.json>  -> resolve decider verdicts + extend the frontier.
established-safe->consumer bug refuted; violable-bug->confirmed-violable; partial->partial(stop);
uncertain->append the named next decider (depth-capped, cycle-guarded). Fixpoint when no pending left."""
import sys, json, sqlite3, re, os
import os
ROOT=os.environ.get("KAUDIT_ROOT","."); WL=f"{ROOT}/decider-worklist.json"; MAXDEPTH=5
raw=open(sys.argv[1]).read()
recs=None
try:
    recs=json.loads(raw)
except Exception:
    pass
if isinstance(recs,dict):
    recs=[recs]
if not isinstance(recs,list):
    m=re.search(r'\[\s*\{.*\}\s*\]',raw,re.S)
    if m:
        recs=json.loads(m.group(0))
if not isinstance(recs,list):
    print("could not parse decider verdict array/object"); sys.exit(1)
wl=json.load(open(WL)); con=sqlite3.connect(f"{ROOT}/kreview.db"); cur=con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, func_name TEXT, verdict TEXT, evidence TEXT, guest_path TEXT, residual TEXT, next TEXT, confidence TEXT, guard TEXT)")
for col in ["guard TEXT", "audit_pass INTEGER", "audited_at TEXT"]:
    try: cur.execute(f"ALTER TABLE audit ADD COLUMN {col}")
    except Exception: pass
try: cur.execute("ALTER TABLE func ADD COLUMN n_audited INTEGER DEFAULT 0")
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
def text(v,limit=None):
    if v is None: s=''
    elif isinstance(v,(list,dict)): s=json.dumps(v,indent=2)
    else: s=str(v)
    return s[:limit] if limit else s
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
    d_prev = cur.execute("SELECT COALESCE(MAX(audit_pass),0) FROM audit WHERE func_name=?", (d,)).fetchone()[0]
    cur.execute("INSERT INTO audit(func_name,verdict,evidence,guest_path,residual,next,confidence,audit_pass,audited_at) VALUES(?,?,?,?,?,?,?,?,datetime('now'))",
      (d,v,text(r.get('evidence'),8000)+f"  [decides {c}]",text(r.get('guest_reachable_path'),8000),text(r.get('residual_unknowns'),2000),text(r.get('recommended_next'),1000),text(r.get('confidence','')),d_prev+1))
    cur.execute("UPDATE func SET n_audited=COALESCE(n_audited,0)+1 WHERE name=?", (d,))
    newstatus=None
    if v in TERM:
        newstatus=TERM[v]
    elif v=='uncertain-continue':
        d2=find_sym(text(r.get('recommended_next','')))
        chain_decs={pp["decider"] for pp in wl["frontier"] if pp["consumer"]==c}
        if not d2 or d2 not in SYMS or d2==c:                newstatus='exhausted-extsym'   # external symbol
        elif d2 in chain_decs or d2 in wl.get('audited',{}): newstatus='exhausted-cycle'
        elif depth>=MAXDEPTH:                                newstatus='exhausted-depthcap' # tooling limit (resumable)
        else:
            b=cur.execute("SELECT desc FROM bug WHERE func_name=? LIMIT 1",(c,)).fetchone()
            wl["frontier"].append({"consumer":c,"decider":d2,"bug_desc":(b[0] if b else c)[:2000],
                "precondition":text(r.get('recommended_next'),1000),"status":"pending","depth":depth+1})
    if newstatus:
        cur.execute("UPDATE bug SET status=? WHERE func_name=? AND status NOT IN ('confirmed-violable')", (newstatus,c))
        c_prev = cur.execute("SELECT COALESCE(MAX(audit_pass),0) FROM audit WHERE func_name=?", (c,)).fetchone()[0]
        cur.execute("INSERT INTO audit(func_name,verdict,evidence,guest_path,residual,next,confidence,audit_pass,audited_at) VALUES(?,?,?,?,?,?,?,?,datetime('now'))",
          (c,v,text(r.get('evidence'),8000)+f"  [resolved via {d}]",text(r.get('guest_reachable_path'),8000),text(r.get('residual_unknowns'),2000),text(r.get('recommended_next'),1000),text(r.get('confidence','')),c_prev+1))
        cur.execute("UPDATE func SET n_audited=COALESCE(n_audited,0)+1 WHERE name=?", (c,))
con.commit(); json.dump(wl,open(WL,'w'),indent=0)
pend=sum(1 for p in wl["frontier"] if p["status"]=="pending")
print(f"ingested {len(recs)} decider verdicts:", tally)
print(f"frontier pending (next round): {pend}  | {'FIXPOINT - run final summary' if pend==0 else 'continue'}")
print("bug.status:", dict(cur.execute("SELECT status,COUNT(*) FROM bug GROUP BY status").fetchall()))
