#!/usr/bin/env python3
"""ingest.py <workflow-output.json>  -> load review records into kreview.db ledger.
Tolerant of wrapper formats: finds the first JSON array of records in the file.

By default this is idempotent per reviewed function: an updated review replaces
that function's previous Stage-2 preconditions/bugs instead of appending
duplicates. Use --append only when intentionally preserving multiple passes.
"""
import argparse, datetime, json, os, re, sqlite3, sys

ap=argparse.ArgumentParser(description="Load Stage-2 review records into kreview.db")
ap.add_argument("workflow_output")
ap.add_argument("--append", action="store_true", help="append preconditions/bugs instead of replacing records for reviewed functions")
args=ap.parse_args()

ROOT=os.environ.get("KAUDIT_ROOT",".")
raw=open(args.workflow_output).read()
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
for _col in ("bug_class TEXT","leak_back TEXT","disclosure_source TEXT","reachability TEXT","guarded_by TEXT"):
    try: cur.execute("ALTER TABLE bug ADD COLUMN %s" % _col)   # v2 + disclosure/reachability migration (idempotent)
    except Exception: pass
today=datetime.date.today().isoformat()
n_p=n_b=0
for rec in recs:
    if not isinstance(rec,dict): continue
    nm=rec.get('function')
    a=cur.execute("SELECT addr FROM func WHERE name=?", (nm,)).fetchone()
    addr=a[0] if a else None
    if not args.append:
        if addr is not None:
            cur.execute("DELETE FROM precondition WHERE func_addr=?", (addr,))
            cur.execute("DELETE FROM bug WHERE func_addr=?", (addr,))
        else:
            cur.execute("DELETE FROM precondition WHERE func_name=?", (nm,))
            cur.execute("DELETE FROM bug WHERE func_name=?", (nm,))
    cur.execute("INSERT OR REPLACE INTO review VALUES(?,?,?,?,?,?)",(addr,nm,today,'wf',rec.get('verdict'),(rec.get('summary') or '')[:4000]))
    for p in rec.get('preconditions') or []:
        cur.execute("INSERT INTO precondition(func_addr,func_name,text,kind,klass,sink,status,attack_note) VALUES(?,?,?,?,?,?,?,?)",
          (addr,nm,p.get('text'),p.get('kind'),p.get('klass'),p.get('sink',''),'open',p.get('attack_note',''))); n_p+=1
    for b in rec.get('suspected_bugs') or []:
        cur.execute("INSERT INTO bug(func_addr,func_name,desc,location,severity,confidence,why,status,bug_class,leak_back,disclosure_source,reachability,guarded_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
          (addr,nm,b.get('desc'),b.get('location',''),b.get('severity',''),b.get('confidence','low'),b.get('why',''),'open',b.get('bug_class',b.get('pattern','oob')),
           b.get('leak_back'),b.get('disclosure_source'),b.get('reachability'),b.get('guarded_by'))); n_b+=1
con.commit()
print(f"ingested {len(recs)} reviews, {n_p} preconditions, {n_b} suspected bugs")
