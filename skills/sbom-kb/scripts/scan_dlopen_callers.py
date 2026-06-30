#!/usr/bin/env python3
"""Pre-filter for the dlopen pass: find which binaries + shared libraries actually CALL
dlopen()/dlmopen() (so they runtime-load plugins ldd can't show), and surface any literal `.so`
target strings. This SCOPES the dlopen call-site resolution -- it does not fully resolve format-string
targets (e.g. `%s.so`, a plugin dir + a name), which need a decompiler.

Two complementary passes give complete dlopen coverage:
  1. RUNTIME  -- `collect_proc_maps.py` snapshots /proc/<pid>/maps of the live daemons => the dlopens
                that have ALREADY fired (steady-state plugins, providers, NSS modules, SASL mechs).
  2. STATIC   -- this tool flags every binary/lib that IMPORTS dlopen, THEN you resolve the actual
                target with the disasm code-mode skills:  gh-callsites --sink dlopen  (Ghidra)
                or  bn-callsites --sink dlopen  (Binary Ninja) -- across the FLAGGED files only.
The static pass catches LAZY/conditional dlopens that a runtime snapshot misses.

CONFIG via env: SBOM_HOST (live host) or SBOM_SCAN_DIR (a local dir of pulled .so/binaries), SBOM_DB.
Run:  SBOM_HOST=<host> python3 scan_dlopen_callers.py     (or)     SBOM_SCAN_DIR=/path/to/libs ...
"""
import os, subprocess, sqlite3, re

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
DB   = os.environ.get("SBOM_DB", os.path.join(ROOT, "sbom.db"))
HOST = os.environ.get("SBOM_HOST", "")
SCAN_DIR = os.environ.get("SBOM_SCAN_DIR", "")   # if set, scan local files instead of ssh


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90).stdout


def imports_dlopen(path):
    cmd = f"nm -D '{path}' 2>/dev/null | grep -qE ' U dl(m)?open' && echo yes"
    out = sh(cmd if SCAN_DIR else f"ssh -o BatchMode=yes {HOST} \"{cmd}\"")
    return "yes" in out


def so_strings(path):
    rx = r"/[A-Za-z0-9_./-]*(sasl2|security|plugin)[A-Za-z0-9_./-]*\\.so[0-9.]*|%s[A-Za-z0-9_./-]*\\.so"
    cmd = f"strings -a '{path}' 2>/dev/null | grep -oE '{rx}' | sort -u | head -4"
    out = sh(cmd if SCAN_DIR else f"ssh -o BatchMode=yes {HOST} \"{cmd}\"")
    return [s for s in out.split() if s.strip()]


def targets():
    if SCAN_DIR:
        out = sh(f"find '{SCAN_DIR}' -type f \\( -name '*.so*' -o -perm -u+x \\) 2>/dev/null")
        return [(os.path.basename(p), p) for p in out.split() if p.strip()]
    con = sqlite3.connect(DB)
    rows = [(n, p) for n, p in con.execute("SELECT name, path FROM binary WHERE path LIKE '/%'")]
    rows += [(s, p) for s, p in con.execute("SELECT soname, path FROM library WHERE path LIKE '/%'")]
    con.close()
    return rows


def main():
    if not (HOST or SCAN_DIR):
        raise SystemExit("set SBOM_HOST (live host) or SBOM_SCAN_DIR (local dir of pulled files)")
    callers = []
    for name, path in targets():
        if imports_dlopen(path):
            callers.append((name, so_strings(path)))
    print(f"{len(callers)} dlopen caller(s) (binaries + libs). Resolve targets with the disasm")
    print("code-mode skills:  gh-callsites --sink dlopen <file>   /   bn-callsites --sink dlopen <file>\n")
    for name, strs in sorted(callers):
        print(f"  {name:30} {' '.join(strs) if strs else '(format-string target -> decompile to resolve)'}")


if __name__ == "__main__":
    main()
