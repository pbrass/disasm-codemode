#!/usr/bin/env python3
"""Polyglot (language-ecosystem) dependency collector for the SBOM KB.

`ldd`/`scan_static_deps.py` only see NATIVE (ELF .so / vendored-C) deps. Modern appliances are
POLYGLOT: the richest n-day surface is usually the **Java jar layer** (hundreds of bundled jars,
incl. ones buried inside WAR/EAR webapps that no package manager records), plus **Python** site
packages and **Go** modules statically linked into binaries. This scans a live host of the target
build and records those as first-class `library` rows tagged with `ecosystem` (java|python|go),
reusing the same cve/analysis/link machinery.

  java   -- every *.jar on disk AND every jar bundled inside *.war/*.ear; version from the filename
            (fallback: MANIFEST.MF Implementation-Version). Key = java:<artifact>; provenance = path
            (or "in <war>"). VMware/vendor-internal + *-SNAPSHOT jars are tagged is_internal in notes.
  python -- dist-info / egg-info / PKG-INFO Name+Version. Key = py:<pkg>.
  go     -- Go is STATIC-linked into ELF binaries, so there are no loose Go files: enumerate Go ELF
            binaries (runtime marker) and extract their embedded buildinfo modules. Uses `go version -m`
            if a toolchain is present, else parses offline via the `dep\\t<mod>\\t<ver>` records that
            `go version` embeds (the target usually has NO go toolchain). Key = go:<module-path>;
            each module is also `link`ed to the binary that carries it.

CONFIG via env: SBOM_HOST (ssh alias of a live host of the target build; REQUIRED), SBOM_DB,
  SBOM_LANG_ROOTS (space-sep dirs to scan, default "/"), SBOM_GO_DIRS (dirs to hunt Go ELF in,
  default "/usr/bin /usr/sbin /usr/lib /opt").
Run:  SBOM_HOST=<host> python3 scan_lang_deps.py
"""
import sqlite3, subprocess, re, os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
DB    = os.environ.get("SBOM_DB",   os.path.join(ROOT, "sbom.db"))
HOST  = os.environ.get("SBOM_HOST", "")
ROOTS = os.environ.get("SBOM_LANG_ROOTS", "/")
GODIRS= os.environ.get("SBOM_GO_DIRS", "/usr/bin /usr/sbin /usr/lib /opt")

if not HOST:
    sys.exit("scan_lang_deps: SBOM_HOST unset -- need a live host of the target build. Skipping.")

def sh(cmd, timeout=300):
    """Run a shell command on the target host over ssh; return stdout (best-effort)."""
    try:
        r = subprocess.run(["ssh", HOST, cmd], capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        print(f"  [warn] remote cmd failed: {e}", file=sys.stderr); return ""

# artifact-name is vendor-internal (not an upstream-CVE target) if it looks like product code
INTERNAL_RE = re.compile(r"(?i)(snapshot|vmware|vim25|vlsi|vsphere|vcenter|com_vmware|^lib(sts|websso|"
                         r"openidconnect|samlauthority)|-rest-|-rest-client|-rest-media|resourcebundle)")

def jar_name_version(basename):
    """nimbus-jose-jwt-8.23.jar -> (nimbus-jose-jwt, 8.23); vmware-opensaml-core-3.2.0-FIPS.jar ->
    (vmware-opensaml-core, 3.2.0-FIPS). Returns (name, version|None)."""
    b = re.sub(r"\.jar$", "", basename)
    m = re.match(r"^(.*?)-(\d[\w.]*(?:-(?:FIPS|SNAPSHOT|RELEASE|final|GA|beta\d*|rc\d*|jre|android|"
                r"[A-Za-z]\w*))*)$", b)
    if m: return m.group(1), m.group(2)
    return b, None

def upsert(cur, soname, path, version, ecosystem, provenance, internal):
    notes = "vendor-internal" if internal else ""
    cur.execute("""INSERT INTO library (soname,path,version,ecosystem,provenance,audit_status,notes)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(soname) DO UPDATE SET
                     version=COALESCE(excluded.version,library.version),
                     ecosystem=excluded.ecosystem,
                     path=COALESCE(library.path,excluded.path),
                     provenance=COALESCE(library.provenance,excluded.provenance),
                     notes=CASE WHEN library.notes='' OR library.notes IS NULL THEN excluded.notes ELSE library.notes END
                """, (soname, path, version, ecosystem,
                      provenance, "version-resolved" if version else "todo", notes))

def link(cur, binary_path, soname, link_type):
    cur.execute("INSERT OR IGNORE INTO link (binary_path,library_soname,link_type) VALUES (?,?,?)",
                (binary_path, soname, link_type))

def scan_java(cur):
    """ONE remote command: loose jars (as J|<path>) + every jar inside each war (as W|<war>|<jarbn>)."""
    print("[java] enumerating jars (loose + inside WARs)...")
    out = sh(f"""
      find {ROOTS} -xdev -name '*.jar' 2>/dev/null | sed 's#^#J|#'
      for w in $(find {ROOTS} -xdev \\( -name '*.war' -o -name '*.ear' \\) 2>/dev/null); do
        unzip -l "$w" 2>/dev/null | grep -oE '[^/ ]+\\.jar' | sort -u | sed "s#^#W|$w|#"
      done
    """, timeout=400)
    n_loose = n_emb = 0
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("J|"):
            p = line[2:]
            name, ver = jar_name_version(os.path.basename(p))
            key = f"java:{name}@{ver or '?'}"     # version-qualified: each distinct version = its own row
            upsert(cur, key, p, ver, "java", p, bool(INTERNAL_RE.search(name))); n_loose += 1
        elif line.startswith("W|"):
            _, w, jarbn = line.split("|", 2)
            name, ver = jar_name_version(jarbn)
            key = f"java:{name}@{ver or '?'}"
            upsert(cur, key, None, ver, "java", f"in {w}", bool(INTERNAL_RE.search(name)))
            link(cur, w, key, "bundled-in-war"); n_emb += 1
    print(f"  java: {n_loose} loose + {n_emb} war-embedded jar refs")

def scan_python(cur):
    print("[python] enumerating dist-info / PKG-INFO...")
    out = sh(r"""for p in $(find %s -xdev \( -name 'METADATA' -o -name 'PKG-INFO' \) 2>/dev/null); do
                  n=$(grep -m1 '^Name:' "$p" 2>/dev/null | awk '{print $2}');
                  v=$(grep -m1 '^Version:' "$p" 2>/dev/null | awk '{print $2}');
                  [ -n "$n" ] && echo "$n|$v|$p"; done""" % ROOTS, timeout=300)
    n = 0
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 2 or not parts[0]: continue
        name, ver = parts[0], parts[1] or None
        path = parts[2] if len(parts) > 2 else None
        upsert(cur, f"py:{name.lower()}@{ver or '?'}", path, ver, "python", path, bool(INTERNAL_RE.search(name)))
        n += 1
    print(f"  python: {n} packages")

def scan_go(cur):
    """ONE remote command: find candidate ELF, keep only Go ones (buildinf magic), emit
    B|<binary> then its buildinfo dep/mod lines M|<binary>|<mod>|<ver>. `go version -m` if present,
    else offline strings-parse (target usually has no go toolchain).

    Offline extraction parses the `debug/buildinfo` sentinel-framed modinfo block directly (the
    `mod`/`dep`/`=>` records live in ONE tab+newline-framed blob between two 16-byte sentinels, so
    `strings` splits on the tabs and loses them -- a byte-level parse is required). Runs a small
    parser via the target's own `python3` (present on most appliances) so we never transfer the (large)
    binaries; falls back to `go version -m` if a toolchain is present, else to the strings-grep."""
    print("[go] hunting Go ELF binaries + extracting buildinfo modules...")
    have_go = bool(sh("command -v go 2>/dev/null").strip())
    have_py = bool(sh("command -v python3 2>/dev/null").strip())
    # find Go binaries once (buildinf magic)
    gobins = [b.strip() for b in sh(
        f"""for d in {GODIRS}; do find $d -type f -perm -u+x 2>/dev/null; done | sort -u | while read b; do
              grep -aqm1 'Go buildinf:' "$b" 2>/dev/null && echo "$b"; done""", timeout=400).splitlines() if b.strip()]
    n_bin = len(gobins); n_mod = 0

    def emit(b, rec_line):
        nonlocal n_mod
        f = rec_line.split("\t")
        if len(f) >= 3 and f[0] in ("dep", "mod", "=>"):
            module, version = f[1].strip(), f[2].strip()
            if module and version.startswith(("v", "(devel")):
                key = f"go:{module}@{version}"
                upsert(cur, key, None, version, "go", f"static in {b}", False)
                link(cur, b, key, "static-go"); n_mod += 1

    if have_go:
        for b in gobins:
            for line in sh(f'go version -m "{b}" 2>/dev/null').splitlines():
                emit(b, line.strip())
        mode = "go version -m"
    elif have_py:
        # byte-level debug/buildinfo parse, executed on the target (no transfer). Sentinels per Go src.
        PARSER = (
            "import sys\n"
            "S=bytes.fromhex('3077af0c9274080241e1c107e6d618e6')\n"   # infoStart
            "E=bytes.fromhex('f932433186182072008242104116d8f2')\n"   # infoEnd
            "for p in sys.argv[1:]:\n"
            " try: d=open(p,'rb').read()\n"
            " except Exception: continue\n"
            " i=d.find(S)\n"
            " if i<0: continue\n"
            " j=d.find(E,i)\n"
            " if j<0: continue\n"
            " blob=d[i+16:j].decode('utf-8','replace')\n"
            " for ln in blob.split(chr(10)):\n"
            "  if ln[:4] in ('mod\\t','dep\\t','=>\\t'): print(p+chr(1)+ln)\n"
        )
        # batch the binaries through one remote python3 (argv); chunk to keep the arg list sane
        for k in range(0, len(gobins), 40):
            chunk = gobins[k:k+40]
            argv = " ".join("'%s'" % b for b in chunk)
            out = sh(f"python3 -c \"$(cat <<'PYEOF'\n{PARSER}PYEOF\n)\" {argv}", timeout=300)
            for line in out.splitlines():
                if "\x01" in line:
                    b, rec = line.split("\x01", 1); emit(b, rec)
        mode = "offline debug/buildinfo parse (remote python3)"
    else:
        for b in gobins:
            for line in sh(f'strings -a "{b}" 2>/dev/null | grep -aE "^(dep|mod|=>)\\s" | head -400').splitlines():
                emit(b, line.strip())
        mode = "strings-grep fallback (no go/python3 on target -- may miss modules)"
    print(f"  go: {n_bin} Go binaries, {n_mod} module refs  ({mode})")

def main():
    con = sqlite3.connect(DB); cur = con.cursor()
    # ensure the ecosystem column exists (idempotent for DBs built before the polyglot schema bump)
    cols = [r[1] for r in cur.execute("PRAGMA table_info(library)")]
    if "ecosystem" not in cols:
        cur.execute("ALTER TABLE library ADD COLUMN ecosystem TEXT DEFAULT 'native'")
    scan_java(cur); scan_python(cur); scan_go(cur)
    con.commit()
    print("--- ecosystem rollup ---")
    for eco, c, resolved in cur.execute(
        "SELECT ecosystem, COUNT(*), SUM(version IS NOT NULL) FROM library GROUP BY ecosystem ORDER BY 2 DESC"):
        print(f"  {eco:8} {c:5} components ({resolved} version-resolved)")
    con.close()

if __name__ == "__main__":
    main()
