#!/usr/bin/env python3
"""Build an SBOM + vuln knowledge-base DB (sbom.db) for a bundled-component / patch-diff /
reachability audit. Three data sources, ALL optional + incremental (re-run as you acquire more):

  1. PACKAGES  - diff two `rpm -qa`-style package lists (CURRENT/vulnerable build vs PATCHED build).
                 The diff = what the vendor bumped => an acknowledged fix => a candidate live n-day.
  2. DEP GRAPH - ldd each net-facing binary on a LIVE host -> library nodes + binary->lib links,
                 then grep the REAL upstream version out of each .so's build-path strings.
  3. SEEDS     - load the curated seeds/*.sql (CVEs, reachability, github silent-fix reviews).

Stages 2+3 (resolve_and_classify.py, scan_static_deps.py) then enrich it. See rebuild.sh.

>>> EDIT THE CONFIG BLOCK BELOW for your target. <<<  Anything you don't have yet -> leave it
empty/None and that source is skipped. Query: `sqlite3 sbom.db` (see queries.md).
"""
import sqlite3, subprocess, re, os, hashlib, glob

HERE   = os.path.dirname(os.path.abspath(__file__))
ROOT   = os.path.dirname(HERE)
SCHEMA = os.path.join(ROOT, "schema.sql")
SEEDS  = os.environ.get("SBOM_SEEDS", os.path.join(ROOT, "seeds"))
DB     = os.environ.get("SBOM_DB",    os.path.join(ROOT, "sbom.db"))

# ============================ CONFIG - EDIT FOR YOUR TARGET ============================
# ssh alias of a LIVE host of the CURRENT/vulnerable build (for ldd + version-grep). "" => skip the
# live dep-graph (you can still load packages + seeds and query). Env override: SBOM_HOST.
HOST = os.environ.get("SBOM_HOST", "")                 # e.g. "myappliance"

# Two package lists (one `name-version-release.arch` per line, e.g. `rpm -qa | sort`): the CURRENT
# (vulnerable) build and the PATCHED/successor build. None => skip packages. Env: SBOM_PKGS_CUR/SUCC.
SBOM_PKGS_CUR  = os.environ.get("SBOM_PKGS_CUR")       # e.g. "/path/to/pkgs-current.txt"
SBOM_PKGS_SUCC = os.environ.get("SBOM_PKGS_SUCC")      # e.g. "/path/to/pkgs-patched.txt"

# Net-facing binaries to map: (path_on_host, name, role, listen_ports, reachability).
#   reachability in {preauth-remote, postauth-remote, local, internal-loopback}
# EXAMPLE (replace with your target's binaries):
ATTACKABLE = [
    # ("/usr/sbin/httpd",   "httpd",  "Web server",     "80,443",  "preauth-remote"),
    # ("/usr/sbin/sshd",    "sshd",   "SSH",            "22",      "preauth-remote"),
    # ("/usr/sbin/postfix", "postfix","Mail (SMTP)",    "25",      "preauth-remote"),
]
# Plugins dlopened at runtime (NOT shown by ldd): (lib_path, owning_binary_path, link_type_label).
DLOPEN_PLUGINS = [
    # ("/usr/lib64/sasl2/libgssapiv2.so", "/usr/sbin/myservice", "dlopen-sasl"),
]
# Regex matching YOUR vendor's OWN package names (not third-party OSS). Everything else =>
# is_third_party=1 (upstream OSS with a public-CVE surface = where version-based n-days live).
# EXAMPLE: replace with your vendor's naming convention.
VENDOR_PKG_RE = re.compile(
    r'^myvendor|^myproduct')

# Acquisition provenance: local dirs of binaries/libs you pulled -> (host, build, os_version). Optional.
ARTIFACT_SOURCES = [
    # ("/path/to/pulled/binaries", "host-alias", "buildnum", "os.version"),
]
# ======================================================================================


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return ""


def pkgname(line):
    return re.sub(r'-[0-9][^-]*-[^-]*\.(x86_64|noarch|i686)$', '', line.strip())


def load_packages(con):
    if not (SBOM_PKGS_CUR and SBOM_PKGS_SUCC and os.path.exists(SBOM_PKGS_CUR) and os.path.exists(SBOM_PKGS_SUCC)):
        print("  [packages] skipped (set SBOM_PKGS_CUR + SBOM_PKGS_SUCC)"); return
    cur = {pkgname(l): l.strip() for l in open(SBOM_PKGS_CUR) if l.strip()}
    succ = {pkgname(l): l.strip() for l in open(SBOM_PKGS_SUCC) if l.strip()}
    for name in sorted(set(cur) | set(succ)):
        vc, vs = cur.get(name, ""), succ.get(name, "")
        changed = 1 if (vc and vs and vc != vs) else 0
        third = 0 if VENDOR_PKG_RE.search(name) else 1
        con.execute("INSERT OR REPLACE INTO package(name,version_cur,version_succ,changed_in_patch,is_third_party) VALUES(?,?,?,?,?)",
                    (name, vc, vs, changed, third))
    print(f"  [packages] {len(set(cur) | set(succ))} loaded "
          f"({sum(1 for n in set(cur)|set(succ) if cur.get(n,'')!=succ.get(n,'') and cur.get(n) and succ.get(n))} changed in patch)")


def grep_ver(path):
    if not HOST:
        return ""
    out = sh(f"ssh -o BatchMode=yes {HOST} \"grep -aoE "
             f"'OpenSSL [0-9][0-9.]+[a-z]?|/[a-zA-Z0-9_]+-[0-9][0-9.]*' "
             f"'{path}' 2>/dev/null | sort -u | head -4\"")
    return "; ".join(out.split())[:200]


def load_binaries_and_graph(con):
    for path, name, role, ports, reach in ATTACKABLE:
        con.execute("INSERT OR REPLACE INTO binary(path,name,role,listen_ports,reachability,analyzed) VALUES(?,?,?,?,?,0)",
                    (path, name, role, ports, reach))
        if not HOST:
            continue
        ldd = sh(f"ssh -o BatchMode=yes {HOST} \"ldd '{path}' 2>/dev/null\"")
        for m in re.finditer(r'=>\s*(\S+\.so[0-9.]*)', ldd):
            lib = m.group(1); soname = os.path.basename(lib)
            con.execute("INSERT OR IGNORE INTO library(soname,path) VALUES(?,?)", (soname, lib))
            con.execute("INSERT OR IGNORE INTO link(binary_path,library_soname,link_type) VALUES(?,?,?)", (path, soname, "dynamic"))
    for lib, owner, lt in DLOPEN_PLUGINS:
        soname = os.path.basename(lib)
        con.execute("INSERT OR IGNORE INTO library(soname,path) VALUES(?,?)", (soname, lib))
        con.execute("INSERT OR IGNORE INTO link(binary_path,library_soname,link_type) VALUES(?,?,?)", (owner, soname, lt))
    if HOST:
        for (soname,) in con.execute("SELECT soname FROM library").fetchall():
            p = con.execute("SELECT path FROM library WHERE soname=?", (soname,)).fetchone()[0]
            ver = grep_ver(p)
            if ver:
                con.execute("UPDATE library SET provenance=? WHERE soname=?", (ver, soname))
    nb = con.execute("SELECT COUNT(*) FROM binary").fetchone()[0]
    nl = con.execute("SELECT COUNT(*) FROM library").fetchone()[0]
    print(f"  [graph] {nb} binaries, {nl} libraries" + ("" if HOST else "  (SBOM_HOST unset -> binaries only, no ldd graph)"))


def load_artifacts(con):
    if not ARTIFACT_SOURCES:
        return
    for root, host, build, osv in ARTIFACT_SOURCES:
        if not os.path.isdir(root):
            continue
        for fp in glob.glob(f"{root}/**/*", recursive=True):
            if not os.path.isfile(fp):
                continue
            base = os.path.basename(fp)
            try:
                h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
            except Exception:
                h = ""
            ctype = "binary" if con.execute("SELECT 1 FROM binary WHERE name=?", (base,)).fetchone() else "library"
            con.execute("INSERT INTO artifact(component,component_type,source_host,build,os_version,remote_path,local_path,sha256,acquired) VALUES(?,?,?,?,?,?,?,?,?)",
                        (base, ctype, host, build, osv, "", fp, h, ""))


def main():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.executescript(open(SCHEMA).read())
    load_packages(con)
    load_binaries_and_graph(con)
    seeds = sorted(glob.glob(f"{SEEDS}/seed*.sql"))
    for sq in seeds:
        con.executescript(open(sq).read())
    print(f"  [seeds] loaded {len(seeds)} file(s) from {SEEDS}")
    load_artifacts(con)
    con.commit()
    print("--- counts ---")
    for t in ["host", "package", "binary", "library", "link", "cve", "analysis", "upstream_fix", "artifact"]:
        try:
            n = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except Exception:
            n = "-"
        print(f"  {t:14} {n}")
    con.close()
    print(f"DB: {DB}")


if __name__ == "__main__":
    main()
