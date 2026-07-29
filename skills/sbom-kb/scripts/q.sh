#!/bin/bash
# Tiny query helper. Runs SQL against the DB (default: ./sbom.db; override with SBOM_DB).
# With no args, runs the headline "money" query (pre-auth-reachable n-days).
#   ./scripts/q.sh                              # v_preauth_ndays (the money query)
#   ./scripts/q.sh "SELECT * FROM v_todo"       # any SQL
#   SBOM_DB=./sbom.db ./scripts/q.sh            # against a specific DB
root="$(cd "$(dirname "$0")/.." && pwd)"
DB="${SBOM_DB:-$root/sbom.db}"
SQL="${*:-SELECT * FROM v_preauth_ndays}"
if command -v sqlite3 >/dev/null; then
  exec sqlite3 -header -column "$DB" "$SQL"
else
  exec python3 -c "import sqlite3,sys,os
c=sqlite3.connect(sys.argv[1]); cur=c.execute(sys.argv[2])
cols=[d[0] for d in cur.description]; print(' | '.join(cols))
[print(' | '.join('' if v is None else str(v) for v in r)) for r in cur]" "$DB" "$SQL"
fi
