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
for col in ["guard TEXT", "audit_pass INTEGER", "audited_at TEXT"]:
    try: cur.execute(f"ALTER TABLE audit ADD COLUMN {col}")
    except Exception: pass
try: cur.execute("ALTER TABLE func ADD COLUMN n_audited INTEGER DEFAULT 0")
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
    prim = r.get('unsafe_primitive') or r.get('oob_primitive') or ''
    ev=f"[DEEP-DIVE {v}] {prim} | impact: {r.get('impact','')} | {r.get('evidence','')}"
    c_prev = cur.execute("SELECT COALESCE(MAX(audit_pass),0) FROM audit WHERE func_name=?", (c,)).fetchone()[0]
    cur.execute("INSERT INTO audit(func_name,verdict,evidence,guest_path,residual,next,confidence,audit_pass,audited_at) VALUES(?,?,?,?,?,?,?,?,datetime('now'))",
      (c, 'deepdive-'+v, ev[:8000], (r.get('guest_input') or '')[:8000], (r.get('external_blocker') or '')[:2000], '', r.get('confidence',''),c_prev+1))
    cur.execute("UPDATE bug SET status=? WHERE func_name=?", (st,c))
    cur.execute("UPDATE func SET n_audited=COALESCE(n_audited,0)+1 WHERE name=?", (c,))
con.commit()
print("deep-dive verdicts:", tally)
print("bug.status:", dict(cur.execute("SELECT status,COUNT(*) FROM bug GROUP BY status").fetchall()))
