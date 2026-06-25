#!/usr/bin/env python3
"""ingest_phase2.py <workflow-output.json> [batchN] -> fold phase-2 verdicts into the ledger.
Maps each verdict to its bug function (by name substring in 'target'), updates bug.status +
stores the verdict/evidence; updates matching caller/unguaranteed preconditions' status."""
import sys, json, sqlite3, re
import os
ROOT=os.environ.get("KAUDIT_ROOT",".")
raw=open(sys.argv[1]).read()
m=re.search(r'\[\s*\{.*\}\s*\]', raw, re.S)
recs=json.loads(m.group(0)) if m else []
con=sqlite3.connect(f"{ROOT}/kreview.db"); cur=con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, func_name TEXT, verdict TEXT, evidence TEXT, guest_path TEXT, residual TEXT, next TEXT, confidence TEXT, guard TEXT)")
try: cur.execute("ALTER TABLE audit ADD COLUMN guard TEXT")
except Exception: pass
cur.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, func_name TEXT, verdict TEXT, evidence TEXT, guest_path TEXT, residual TEXT, next TEXT, confidence TEXT)")
VMAP={'violable-bug':'confirmed-violable','established-safe':'refuted','partial':'partial','uncertain':'uncertain'}
allfns=[r[0] for r in cur.execute("SELECT name FROM func")]
n=0
for rec in recs:
    if not isinstance(rec,dict): continue
    tgt=rec.get('target','') or ''
    fn=next((f for f in allfns if f and f in tgt), None) or tgt
    v=rec.get('verdict','uncertain'); st=VMAP.get(v,'uncertain')
    cur.execute("INSERT INTO audit(func_name,verdict,evidence,guest_path,residual,next,confidence) VALUES(?,?,?,?,?,?,?)",
      (fn,v,rec.get('evidence',''),rec.get('guest_reachable_path',''),rec.get('residual_unknowns',''),rec.get('recommended_next',''),rec.get('confidence','')))
    cur.execute("UPDATE bug SET status=? WHERE func_name=?", (st,fn))
    cur.execute("UPDATE precondition SET status=? WHERE func_name=? AND klass IN ('caller','unguaranteed') AND status='open'", (st,fn))
    n+=1
con.commit()
print(f"ingested {n} verdicts")
for v,c in cur.execute("SELECT verdict,COUNT(*) FROM audit GROUP BY verdict ORDER BY COUNT(*) DESC"):
    print(f"  {v}: {c}")
