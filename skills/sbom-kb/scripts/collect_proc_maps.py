#!/usr/bin/env python3
"""Snapshot /proc/<pid>/maps for the in-scope RUNNING daemons and load it into proc_map.

WHY: `ldd <binary>` gives the full *static* (DT_NEEDED) transitive closure, but it CANNOT see
libraries loaded at runtime via dlopen() -- PAM modules, NSS modules, SASL mechs, OpenSSL providers
(fips.so/legacy.so), and plugins. The kernel's /proc/<pid>/maps of a live process is the ground
truth of what is ACTUALLY mapped in. Diffing maps against ldd(exe) (by realpath) yields the
dlopen/runtime-only loads -- a whole ldd-invisible attack surface.

CAVEAT: maps only shows what's loaded AT SNAPSHOT TIME, so it catches steady-state plugins but can
miss *lazy* dlopens (a mech loaded only when a specific request arrives). Pair it with the dlopen
call-site scan (decompile + find dlopen() calls) for full coverage; ideally snapshot after the
daemons have served some traffic.

CONFIG via env: SBOM_HOST (ssh alias of a LIVE host), SBOM_DB, SBOM_BUILD (build label), and
SBOM_PROCS (space-separated process names to snapshot).
Run:  SBOM_HOST=myhost SBOM_BUILD=1.0.0 SBOM_PROCS="httpd sshd myservice" python3 collect_proc_maps.py
"""
import os, subprocess, sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DB    = os.environ.get("SBOM_DB",   os.path.join(ROOT, "sbom.db"))
HOST  = os.environ.get("SBOM_HOST", "")
BUILD = os.environ.get("SBOM_BUILD", "current")
PROCS = os.environ.get("SBOM_PROCS", "")  # space-separated, e.g. "httpd sshd myservice"

REMOTE = r'''
for d in %s; do
  pid=$(pgrep -x "$d" 2>/dev/null | head -1); [ -z "$pid" ] && continue
  exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
  ldd "$exe" 2>/dev/null | grep -oE "/[^ ]+\.so[0-9.]*" | xargs -r -n1 readlink -f 2>/dev/null | sort -u > /tmp/_lddreal.$$
  grep -hoE "/[^ ]+\.so[0-9.]*" /proc/$pid/maps 2>/dev/null | sort -u | while read lib; do
    real=$(readlink -f "$lib" 2>/dev/null); sn=$(echo "$lib" | sed "s#.*/##")
    grep -qxF "$real" /tmp/_lddreal.$$ && dl=0 || dl=1
    echo "%s|$pid|$d|$exe|$real|$sn|$dl"
  done
  rm -f /tmp/_lddreal.$$
done
''' % (PROCS, BUILD)


def main():
    if not HOST:
        raise SystemExit("set SBOM_HOST to a live host running the target daemons")
    if not PROCS:
        raise SystemExit("set SBOM_PROCS to space-separated process names (e.g. 'httpd sshd myservice')")
    out = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                          HOST, "bash -s"], input=REMOTE, capture_output=True, text=True, timeout=120).stdout
    rows = [l.split("|") for l in out.splitlines() if l.count("|") == 6]
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS proc_map (build TEXT,pid INTEGER,process TEXT,exe TEXT,
                   lib_path TEXT,soname TEXT,dlopen_only INTEGER,snapshot_date TEXT,
                   PRIMARY KEY(build,pid,lib_path))""")
    con.execute("DELETE FROM proc_map WHERE build=?", (BUILD,))
    import datetime
    for b, pid, proc, exe, lib, sn, dl in rows:
        con.execute("INSERT OR IGNORE INTO proc_map(build,pid,process,exe,lib_path,soname,dlopen_only,snapshot_date) "
                    "VALUES(?,?,?,?,?,?,?,date('now'))", (b, int(pid), proc, exe, lib, sn, int(dl)))
    con.commit()
    n = con.execute("SELECT COUNT(*) FROM proc_map WHERE build=?", (BUILD,)).fetchone()[0]
    print(f"proc_map: {n} mappings for build {BUILD} from {len(set(r[1] for r in rows))} processes")
    print("dlopen/runtime-only loads (ldd-invisible):")
    for sn, lb in con.execute("SELECT soname, GROUP_CONCAT(DISTINCT process) FROM proc_map "
                              "WHERE build=? AND dlopen_only=1 GROUP BY soname ORDER BY soname", (BUILD,)):
        print(f"  {sn:30} {lb}")
    con.close()


if __name__ == "__main__":
    main()
