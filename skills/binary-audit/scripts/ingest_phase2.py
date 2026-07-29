#!/usr/bin/env python3
"""ingest_phase2.py <workflow-output.json> -> fold phase-2 verdicts into the ledger.
Maps each verdict to its bug function, updates bug.status + stores the
verdict/evidence, and updates matching caller/unguaranteed preconditions'
status. Accepts either one JSON object or an array.
"""
import argparse, json, os, re, sqlite3, sys

ap=argparse.ArgumentParser(description="Load Stage-3 caller-audit verdicts into kreview.db")
ap.add_argument("workflow_output")
ap.add_argument("--replace", action="store_true", help="delete the function's previous audit rows before inserting (default: append, preserving history)")
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
for col in ["guard TEXT", "audit_pass INTEGER", "audited_at TEXT"]:
    try: cur.execute(f"ALTER TABLE audit ADD COLUMN {col}")
    except Exception: pass
try: cur.execute("ALTER TABLE func ADD COLUMN n_audited INTEGER DEFAULT 0")
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
    prev_pass = cur.execute("SELECT COALESCE(MAX(audit_pass),0) FROM audit WHERE func_name=?", (fn,)).fetchone()[0]
    this_pass = prev_pass + 1
    if args.replace:
        cur.execute("DELETE FROM audit WHERE func_name=?", (fn,))
    cur.execute("INSERT INTO audit(func_name,verdict,evidence,guest_path,residual,next,confidence,guard,audit_pass,audited_at) VALUES(?,?,?,?,?,?,?,?,?,datetime('now'))",
      (fn,v,_text(rec.get('evidence','')),_text(rec.get('guest_reachable_path','')),_text(rec.get('residual_unknowns','')),_text(rec.get('recommended_next','')),_text(rec.get('confidence','')),_text(rec.get('guard','')),this_pass))
    existing_bug = cur.execute("SELECT 1 FROM bug WHERE func_name=? LIMIT 1", (fn,)).fetchone()  # schema-agnostic existence check (bug table may lack an id column)
    if existing_bug:
        cur.execute("UPDATE bug SET status=? WHERE func_name=?", (st,fn))
    elif st in ('confirmed-violable',):
        addr_row = cur.execute("SELECT addr FROM func WHERE name=?", (fn,)).fetchone()
        faddr = addr_row[0] if addr_row else 0
        bug_class = 'oob'
        ev_lower = _text(rec.get('evidence','')).lower()
        if any(k in ev_lower for k in ('integer overflow','int overflow','wrap','shl','imul')):
            bug_class = 'int-overflow'
        elif any(k in ev_lower for k in ('uaf','lifetime','use-after','free')):
            bug_class = 'uaf-lifetime'
        elif 'double' in ev_lower and 'fetch' in ev_lower:
            bug_class = 'double-fetch'
        cur.execute("INSERT INTO bug(func_addr,func_name,desc,location,severity,confidence,why,status,bug_class) VALUES(?,?,?,?,'medium','high','phase-2 audit',?,?)",
          (faddr,fn,_text(rec.get('evidence',''))[:500],hex(faddr) if faddr else '',st,bug_class))
    cur.execute("UPDATE precondition SET status=? WHERE func_name=? AND klass IN ('caller','unguaranteed') AND status='open'", (st,fn))
    cur.execute("UPDATE func SET n_audited=? WHERE name=?", (this_pass, fn))
    n+=1
con.commit()
print(f"ingested {n} verdicts")
for v,c in cur.execute("SELECT verdict,COUNT(*) FROM audit GROUP BY verdict ORDER BY COUNT(*) DESC"):
    print(f"  {v}: {c}")
multi = cur.execute("SELECT COUNT(DISTINCT func_name) FROM audit GROUP BY func_name HAVING COUNT(*)>1").fetchall()
max_pass = cur.execute("SELECT func_name, MAX(audit_pass) FROM audit GROUP BY func_name ORDER BY MAX(audit_pass) DESC LIMIT 1").fetchone()
print(f"  functions with >1 audit pass: {len(multi)}")
if max_pass and max_pass[1]:
    print(f"  most-audited: {max_pass[0]} ({max_pass[1]} passes)")
