#!/usr/bin/env python3
"""Resolve real versions for the upstream-OSS attack-surface libs (build-path/version
grep on the live host) and auto-classify vendor-internal libs (no public-CVE
surface). Updates library.version/upstream/github_url/audit_status in sbom.db."""
import sqlite3, subprocess, re, os
# --- portable config: set SBOM_DB / SBOM_HOST (env) for your target.
#     UPSTREAM (soname->upstream/github/version-regex) is reusable across any Linux ELF target;
#     extend it for libs your target ships that aren't already listed.
#     INTERNAL: set to a regex matching your vendor's own internal library names. ---
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
DB   = os.environ.get("SBOM_DB",   os.path.join(ROOT, "sbom.db"))
HOST = os.environ.get("SBOM_HOST", "")   # ssh alias of a LIVE host of the FLEET (vulnerable) build, for version-grep

# upstream OSS libs: soname-substr -> (upstream, github, version-grep regex)
UPSTREAM = {
 "libcrypto.so":("OpenSSL","https://github.com/openssl/openssl",r"OpenSSL 3\.[0-9.]+[a-z]?"),
 "libssl.so":("OpenSSL","https://github.com/openssl/openssl",r"OpenSSL 3\.[0-9.]+[a-z]?"),
 "libxml2.so":("libxml2","https://gitlab.gnome.org/GNOME/libxml2",r"2\.9\.[0-9]+|2\.1[0-9]\.[0-9]+"),
 "libz.so":("zlib","https://github.com/madler/zlib",r"1\.[23]\.[0-9.]+"),
 "libcurl.so":("curl","https://github.com/curl/curl",r"libcurl/[0-9.]+|8\.[0-9]+\.[0-9]+"),
 "libcares.so":("c-ares","https://github.com/c-ares/c-ares",r"1\.[0-9]+\.[0-9]+"),
 "libssh2.so":("libssh2","https://github.com/libssh2/libssh2",r"libssh2/[0-9.]+|1\.[0-9]+\.[0-9]+"),
 "libsqlite3.so":("SQLite","https://github.com/sqlite/sqlite",r"3\.[0-9]+\.[0-9]+"),
 "libjansson.so":("jansson","https://github.com/akheron/jansson",r"2\.[0-9]+(\.[0-9]+)?"),
 "libexpat.so":("expat","https://github.com/libexpat/libexpat",r"expat_2\.[0-9.]+|2\.7\.[0-9]"),
 "libzstd.so":("zstd","https://github.com/facebook/zstd",r"1\.[0-9]+\.[0-9]+"),
 "libodbc.so":("unixODBC","https://github.com/lurcher/unixODBC",r"[0-9]\.[0-9]\.[0-9]+"),
 "libpopt.so":("popt","https://github.com/rpm-software-management/popt",r"1\.[0-9]+(\.[0-9]+)?"),
 "libjwt.so":("libjwt","https://github.com/benmcollins/libjwt",r"[0-9]\.[0-9]+\.[0-9]+"),
 "libaws-c-common":("aws-c-common","https://github.com/awslabs/aws-c-common",r"0\.[0-9]+\.[0-9]+"),
 "libaws-cpp-sdk":("aws-sdk-cpp","https://github.com/aws/aws-sdk-cpp",r"1\.[0-9]+\.[0-9]+"),
 "libc.so.6":("glibc","https://sourceware.org/git/glibc.git",r"2\.3[0-9]"),
 "libpam.so":("Linux-PAM","https://github.com/linux-pam/linux-pam",r"1\.[0-9]\.[0-9]+"),
 "libstdc++.so":("gcc-libstdc++","https://gcc.gnu.org/git/gcc.git",r"GCC[ :][0-9.]+|1[0-9]\.[0-9]+"),
}
# Vendor-internal libs (no public CVE surface; reachability-annotate only).
# EDIT THIS for your target -- match your vendor's internal library naming convention.
INTERNAL = re.compile(os.environ.get("SBOM_INTERNAL_RE", r"^$"))  # default: match nothing
GLIBC = re.compile(r"^lib(c|m|dl|pthread|rt|nsl|resolv|util|crypt|anl)\.so")

def grepver(path, rx):
    out=subprocess.run(f"ssh -o BatchMode=yes {HOST} \"grep -aoE '{rx}' '{path}' 2>/dev/null | sort -u | head -3\"",
                       shell=True,capture_output=True,text=True,timeout=60).stdout
    return "; ".join(out.split())[:80]

con=sqlite3.connect(DB)
rows=con.execute("SELECT soname,path FROM library WHERE COALESCE(audit_status,'todo') != 'audited'").fetchall()
for soname,path in rows:
    matched=False
    for key,(up,gh,rx) in UPSTREAM.items():
        if key in soname:
            ver=grepver(path,rx) if path else ""
            con.execute("UPDATE library SET version=?,upstream=?,github_url=?,audit_status='version-resolved' WHERE soname=?",
                        (ver or up,up,gh,soname)); matched=True; break
    if matched: continue
    if GLIBC.match(soname):
        con.execute("UPDATE library SET upstream='glibc',github_url='https://sourceware.org/git/glibc.git',audit_status='version-resolved' WHERE soname=?",(soname,))
    elif INTERNAL.search(soname):
        con.execute("UPDATE library SET upstream='vendor (internal)',audit_status='audited',notes='Vendor-internal lib; NO upstream public-CVE surface; reachability via its daemon; any bug here is a 0-day found via code-audit, not a version-CVE n-day.' WHERE soname=?",(soname,))
    else:
        con.execute("UPDATE library SET notes=COALESCE(notes,'')||' [unclassified]' WHERE soname=?",(soname,))
con.commit()
print("by audit_status:")
for st,n in con.execute("SELECT COALESCE(audit_status,'todo'),COUNT(*) FROM library GROUP BY audit_status").fetchall():
    print(f"  {st:18} {n}")
print("\nUPSTREAM-OSS libs needing CVE research (version-resolved, not yet audited):")
for s,v,u in con.execute("SELECT soname,version,upstream FROM library WHERE audit_status='version-resolved' AND upstream NOT LIKE '%internal%' ORDER BY upstream").fetchall():
    print(f"  {u:16} {s:28} {v}")
con.close()
