#!/usr/bin/env python3
"""ingest_phase2.py <workflow-output.json> -> fold phase-2 verdicts into the ledger.
Maps each verdict to its bug function, updates bug.status + stores the
verdict/evidence, and updates matching caller/unguaranteed preconditions'
status. Accepts either one JSON object or an array.
"""
import argparse, json, os, re, sqlite3, sys

ap=argparse.ArgumentParser(description="Load Stage-3 caller-audit verdicts into kreview.db")
ap.add_argument("workflow_output")
ap.add_argument("--append", action="store_true", help="append audit rows instead of replacing the function's previous phase-2 row")
args=ap.parse_args()

ROOT=os.environ.get("KAUDIT_ROOT",".")
raw=open(args.workflow_output).read()
recs=None
try:
    recs=json.loads(raw)
except Exception:
    pass
if not isinstance(recs, (list, dict)):
    m=re.search(r'\[\s*\{.*\}\s*\]', raw, re.S)
    if m:
        try: recs=json.loads(m.group(0))
        except Exception: pass
if isinstance(recs, dict):
    recs=[recs]
if not isinstance(recs, list):
    print("could not parse phase-2 verdict object/array"); sys.exit(1)
con=sqlite3.connect(f"{ROOT}/kreview.db"); cur=con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, func_name TEXT, verdict TEXT, evidence TEXT, guest_path TEXT, residual TEXT, next TEXT, confidence TEXT, guard TEXT)")
try: cur.execute("ALTER TABLE audit ADD COLUMN guard TEXT")
except Exception: pass
VMAP={
    'violable-bug':'confirmed-violable',
    'confirmed-violable':'confirmed-violable',
    'established-safe':'refuted',
    'refuted':'refuted',
    'partial':'partial',
    'uncertain':'uncertain',
}
allfns=[r[0] for r in cur.execute("SELECT name FROM func")]
n=0

def _func_for_target(tgt):
    if tgt in allfns:
        return tgt
    matches = [f for f in allfns if f and f in tgt]
    if matches:
        return max(matches, key=len)
    return tgt

def _status(verdict):
    v=(verdict or '').strip()
    vl=v.lower()
    for key, status in VMAP.items():
        if vl == key or vl.startswith(key + ':') or vl.startswith(key + ' '):
            return status
    return 'uncertain'

def _text(v):
    if v is None:
        return ''
    if isinstance(v, (list, dict)):
        return json.dumps(v, indent=2)
    return str(v)

for rec in recs:
    if not isinstance(rec,dict): continue
    tgt=rec.get('target','') or ''
    fn=_func_for_target(tgt)
    v=rec.get('verdict','uncertain'); st=_status(v)
    if not args.append:
        cur.execute("DELETE FROM audit WHERE func_name=?", (fn,))
    cur.execute("INSERT INTO audit(func_name,verdict,evidence,guest_path,residual,next,confidence,guard) VALUES(?,?,?,?,?,?,?,?)",
      (fn,v,_text(rec.get('evidence','')),_text(rec.get('guest_reachable_path','')),_text(rec.get('residual_unknowns','')),_text(rec.get('recommended_next','')),_text(rec.get('confidence','')),_text(rec.get('guard',''))))
    cur.execute("UPDATE bug SET status=? WHERE func_name=?", (st,fn))
    cur.execute("UPDATE precondition SET status=? WHERE func_name=? AND klass IN ('caller','unguaranteed') AND status='open'", (st,fn))
    n+=1
con.commit()
print(f"ingested {n} verdicts")
for v,c in cur.execute("SELECT verdict,COUNT(*) FROM audit GROUP BY verdict ORDER BY COUNT(*) DESC"):
    print(f"  {v}: {c}")
