#!/usr/bin/env python3
"""ingest.py <workflow-output.json>  -> load review records into kreview.db ledger.
Tolerant of wrapper formats: finds the first JSON array of records in the file."""
import sys, json, sqlite3, re
import os
ROOT=os.environ.get("KAUDIT_ROOT",".")
raw=open(sys.argv[1]).read()
# the workflow return value is an array of records; find it
recs=None
try: recs=json.loads(raw)
except Exception: pass
if not isinstance(recs,list):
    m=re.search(r'\[\s*\{.*\}\s*\]', raw, re.S)
    if m:
        try: recs=json.loads(m.group(0))
        except Exception: pass
if not isinstance(recs,list):
    print("could not parse records array"); sys.exit(1)
con=sqlite3.connect(f"{ROOT}/kreview.db"); cur=con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS review(addr INTEGER PRIMARY KEY, name TEXT, reviewed_at TEXT, reviewer TEXT, verdict TEXT, notes TEXT)")
cur.execute("CREATE TABLE IF NOT EXISTS precondition(id INTEGER PRIMARY KEY, func_addr INTEGER, func_name TEXT, text TEXT, kind TEXT, klass TEXT, sink TEXT, status TEXT, attack_note TEXT)")
cur.execute("CREATE TABLE IF NOT EXISTS bug(id INTEGER PRIMARY KEY, func_addr INTEGER, func_name TEXT, desc TEXT, location TEXT, severity TEXT, confidence TEXT, why TEXT, status TEXT, bug_class TEXT)")
try: cur.execute("ALTER TABLE bug ADD COLUMN bug_class TEXT")   # v2 taxonomy migration (idempotent)
except Exception: pass
n_p=n_b=0
for rec in recs:
    if not isinstance(rec,dict): continue
    nm=rec.get('function')
    a=cur.execute("SELECT addr FROM func WHERE name=?", (nm,)).fetchone()
    addr=a[0] if a else None
    cur.execute("INSERT OR REPLACE INTO review VALUES(?,?,?,?,?,?)",(addr,nm,'2026-06-23','wf',rec.get('verdict'),(rec.get('summary') or '')[:4000]))
    for p in rec.get('preconditions') or []:
        cur.execute("INSERT INTO precondition(func_addr,func_name,text,kind,klass,sink,status,attack_note) VALUES(?,?,?,?,?,?,?,?)",
          (addr,nm,p.get('text'),p.get('kind'),p.get('klass'),p.get('sink',''),'open',p.get('attack_note',''))); n_p+=1
    for b in rec.get('suspected_bugs') or []:
        cur.execute("INSERT INTO bug(func_addr,func_name,desc,location,severity,confidence,why,status,bug_class) VALUES(?,?,?,?,?,?,?,?,?)",
          (addr,nm,b.get('desc'),b.get('location',''),b.get('severity',''),b.get('confidence','low'),b.get('why',''),'open',b.get('bug_class',b.get('pattern','oob')))); n_b+=1
con.commit()
print(f"ingested {len(recs)} reviews, {n_p} preconditions, {n_b} suspected bugs")
