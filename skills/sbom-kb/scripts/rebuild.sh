#!/bin/bash
# Reproducible build of sbom.db for YOUR target.
# First: edit the CONFIG block in scripts/build_sbom.py (or set env: SBOM_HOST, SBOM_PKGS_CUR,
# SBOM_PKGS_SUCC, SBOM_DB, SBOM_SEEDS). Stages 2-5 need a live SBOM_HOST (ssh) to resolve versions.
# build_sbom DROPS+recreates the DB, so stages 2-5 (which mutate it) MUST run after it, every time.
set -e
cd "$(dirname "$0")/.."          # skill root
DB="${SBOM_DB:-$PWD/sbom.db}"
echo "[1/5] build_sbom.py (packages, ldd graph, seeds, artifacts)..."
python3 scripts/build_sbom.py
if [ -n "$SBOM_HOST" ]; then
  echo "[2/5] resolve_and_classify.py (real lib versions + internal classification)..."
  python3 scripts/resolve_and_classify.py >/dev/null
  echo "[3/5] scan_static_deps.py (vendored/static OSS in binaries AND libraries)..."
  python3 scripts/scan_static_deps.py
  echo "[4/5] collect_proc_maps.py (runtime /proc/maps -> dlopen loads; needs the daemons running)..."
  python3 scripts/collect_proc_maps.py || echo "  (skipped -- daemons not running / no maps / SBOM_PROCS unset)"
  echo "[5/5] scan_dlopen_callers.py (which files import dlopen -> resolve targets with gh-/bn-callsites)..."
  python3 scripts/scan_dlopen_callers.py || true
else
  echo "[2-5/5] SKIPPED -- set SBOM_HOST=<ssh-alias of a live target host> for versions + static + dlopen passes"
fi
echo "--- v_completeness ---"
SBOM_DB="$DB" python3 -c "import sqlite3,os;\
[print(f'  {l:26} {d}/{t}') for l,d,t in sqlite3.connect(os.environ['SBOM_DB']).execute('SELECT * FROM v_completeness')]"
