#!/usr/bin/env python3
"""ingest_guestentry.py <workflow-output.json> -> fold deep-dive verdicts into the ledger.
confirmed-violable -> bug.status=confirmed-violable; refuted -> refuted; needs-live-poc ->
candidate-needs-poc (a real candidate at demonstrated-trigger level); still-blocked-external -> exhausted-extsym."""
import sys, json, sqlite3, re
import os
ROOT=os.environ.get("KAUDIT_ROOT",".")
recs=json.loads(re.search(r'\[\s*\{.*\}\s*\]',open(sys.argv[1]).read(),re.S).group(0))
con=sqlite3.connect(f"{ROOT}/kreview.db"); cur=con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, func_name TEXT, verdict TEXT, evidence TEXT, guest_path TEXT, residual TEXT, next TEXT, confidence TEXT, guard TEXT)")
try: cur.execute("ALTER TABLE audit ADD COLUMN guard TEXT")
except Exception: pass
allfns=[r[0] for r in cur.execute("SELECT name FROM func")]
MAP={'confirmed-violable':'confirmed-violable','refuted':'refuted',
     'needs-live-poc':'candidate-needs-poc','still-blocked-external':'exhausted-extsym'}
tally={}
for r in recs:
    if not isinstance(r,dict): continue
    tgt=r.get('target','') or ''
    cands=sorted([f for f in allfns if f and f in tgt], key=len, reverse=True)
    c=tgt if tgt in allfns else (cands[0] if cands else tgt)
    v=r.get('verdict','needs-live-poc'); st=MAP.get(v,'candidate-needs-poc'); tally[v]=tally.get(v,0)+1
    ev=f"[DEEP-DIVE {v}] {r.get('oob_primitive','')} | impact: {r.get('impact','')} | {r.get('evidence','')}"
    cur.execute("INSERT INTO audit(func_name,verdict,evidence,guest_path,residual,next,confidence) VALUES(?,?,?,?,?,?,?)",
      (c, 'deepdive-'+v, ev[:2000], (r.get('guest_input') or '')[:600], (r.get('external_blocker') or '')[:300], '', r.get('confidence','')))
    cur.execute("UPDATE bug SET status=? WHERE func_name=?", (st,c))
con.commit()
print("deep-dive verdicts:", tally)
print("bug.status:", dict(cur.execute("SELECT status,COUNT(*) FROM bug GROUP BY status").fetchall()))
