#!/usr/bin/env python3
"""Detect STATICALLY-LINKED / vendored OSS -- in the attack-surface BINARIES **and** in the SHARED
LIBRARIES they load. `ldd` only shows dynamic NEEDED objects; OSS compiled *into* a binary or a
`.so` leaves version banners in `.rodata`. This greps a banner dictionary over every binary AND
every library in the SBOM and records embedded OSS as `link_type='static-bundled'` / `'static-in-lib'`.

>>> Scanning the LIBRARIES (not just the binaries) is essential: a vendor's "internal" `.so` can
    statically vendor outdated OSS (e.g. an internal framework lib bundling zlib + ICU) -- which
    the binary-only scan never attributes, and which breaks the "internal lib = no upstream-CVE
    surface" assumption. <<<

CONFIG via env: SBOM_HOST (ssh alias of a live host of the target build), SBOM_DB.
Run:  SBOM_HOST=<host> python3 scan_static_deps.py
"""
import sqlite3, subprocess, re, os

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
DB   = os.environ.get("SBOM_DB",   os.path.join(ROOT, "sbom.db"))
HOST = os.environ.get("SBOM_HOST", "")   # ssh alias of a LIVE host of your target build, for banner-grep

# oss-name -> (detection regex, canonical key, upstream, github). Reusable across any ELF.
BANNERS = {
 "OpenSSL":   (r"OpenSSL [0-9]\.[0-9]\.[0-9]+[a-z]?", "openssl", "OpenSSL", "https://github.com/openssl/openssl"),
 "expat":     (r"expat_[0-9]\.[0-9]\.[0-9]+", "expat", "expat", "https://github.com/libexpat/libexpat"),
 "zlib":      (r"(inflate|deflate) [0-9]\.[0-9]+\.[0-9.]+ Copyright", "zlib", "zlib", "https://github.com/madler/zlib"),
 "libxml2":   (r"/libxml2-[0-9.]+", "libxml2", "libxml2", "https://gitlab.gnome.org/GNOME/libxml2"),
 "pcre2":     (r"PCRE2? [0-9]+\.[0-9]+ ", "pcre", "PCRE", "https://github.com/PCRE2Project/pcre2"),
 "sqlite":    (r"SQLite version [0-9.]+", "sqlite", "SQLite", "https://github.com/sqlite/sqlite"),
 "curl":      (r"libcurl/[0-9.]+", "curl", "curl", "https://github.com/curl/curl"),
 "krb5":      (r"/krb5-[0-9]\.[0-9.]+", "krb5", "MIT krb5", "https://github.com/krb5/krb5"),
 "openldap":  (r"/openldap-2\.[0-9.]+", "openldap", "OpenLDAP", "https://git.openldap.org/openldap/openldap"),
 "cyrus-sasl":(r"/cyrus-sasl-[0-9.]+", "cyrus-sasl", "cyrus-sasl", "https://github.com/cyrusimap/cyrus-sasl"),
 "boost":     (r"boost_[0-9]_[0-9]+", "boost", "Boost", "https://github.com/boostorg/boost"),
 "protobuf":  (r"libprotobuf", "protobuf", "protobuf", "https://github.com/protocolbuffers/protobuf"),
 "grpc":      (r"grpc-c\+\+|grpcpp", "grpc", "gRPC", "https://github.com/grpc/grpc"),
 "c-ares":    (r"/c-ares-[0-9.]+", "cares", "c-ares", "https://github.com/c-ares/c-ares"),
 "libssh2":   (r"libssh2/[0-9.]+", "libssh2", "libssh2", "https://github.com/libssh2/libssh2"),
 "zstd":      (r"/zstd-[0-9.]+", "zstd", "zstd", "https://github.com/facebook/zstd"),
 "jansson":   (r"/jansson-[0-9.]+", "jansson", "jansson", "https://github.com/akheron/jansson"),
 "rapidjson": (r"/rapidjson/", "rapidjson", "RapidJSON", "https://github.com/Tencent/rapidjson"),
 "icu":       (r"icudt[0-9]+", "icu", "ICU", "https://github.com/unicode-org/icu"),
 "nghttp2":   (r"nghttp2/[0-9.]+", "nghttp2", "nghttp2", "https://github.com/nghttp2/nghttp2"),
}
_COMBINED = "|".join("(%s)" % rx for (rx, _, _, _) in BANNERS.values())


def banners_in(path):
    """One ssh grep over `path` for ALL banners; map each hit back to its OSS -> {oss:(ver,key,up,gh)}."""
    out = subprocess.run(f"ssh -o BatchMode=yes {HOST} \"grep -aoE '{_COMBINED}' '{path}' 2>/dev/null | sort -u | head -40\"",
                         shell=True, capture_output=True, text=True, timeout=90).stdout
    hits = [h for h in out.splitlines() if h.strip()]
    found = {}
    for oss, (rx, key, up, gh) in BANNERS.items():
        vers = [h for h in hits if re.search(rx, h)]
        if vers:
            found[oss] = ("; ".join(sorted(set(vers)))[:90], key, up, gh)
    return found


def main():
    if not HOST:
        raise SystemExit("set SBOM_HOST to a live host of the target build (for banner-grep)")
    con = sqlite3.connect(DB)

    # Scan attack-surface binaries from the DB (populated by build_sbom.py).
    bins = [(r[0], r[1]) for r in con.execute("SELECT name, path FROM binary WHERE path LIKE '/%'").fetchall()]
    print(f"[1] scanning {len(bins)} attack-surface BINARIES on {HOST} for vendored OSS...")
    for name, path in bins:
        dyn = {s.lower() for (s,) in con.execute("SELECT library_soname FROM link WHERE binary_path=?", (path,))}
        for oss, (ver, key, up, gh) in banners_in(path).items():
            if any(key in d or key.replace("-", "") in d for d in dyn):
                continue   # it's a dynamic dep, the banner is just that lib
            soname = f"{key}(static)"
            con.execute("INSERT OR IGNORE INTO library(soname,path,version,upstream,github_url,audit_status,notes) "
                        "VALUES(?,?,?,?,?, 'version-resolved', ?)",
                        (soname, f"(static in {name})", ver, up, gh, f"STATICALLY vendored into {name} (ldd-invisible)"))
            con.execute("INSERT OR IGNORE INTO link(binary_path,library_soname,link_type) VALUES(?,?,'static-bundled')", (path, soname))
            print(f"    {name:12} <= {oss} {ver}")

    print(f"\n[2] scanning SHARED LIBRARIES in the SBOM for vendored OSS (the lib-level pass)...")
    libs = con.execute("SELECT soname, path FROM library WHERE path LIKE '/%'").fetchall()
    nfound = 0
    for hostlib, lpath in libs:
        for oss, (ver, key, up, gh) in banners_in(lpath).items():
            vkey = f"{key}(static-in-{hostlib})"
            con.execute("INSERT OR IGNORE INTO library(soname,path,version,upstream,github_url,audit_status,notes) "
                        "VALUES(?,?,?,?,?, 'version-resolved', ?)",
                        (vkey, f"(static in {hostlib})", ver, up, gh,
                         f"STATICALLY vendored INSIDE {hostlib} (ldd-invisible). Reachable wherever {hostlib} is loaded."))
            for (bp,) in con.execute("SELECT DISTINCT binary_path FROM link WHERE library_soname=?", (hostlib,)):
                con.execute("INSERT OR IGNORE INTO link(binary_path,library_soname,link_type) VALUES(?,?,'static-in-lib')", (bp, vkey))
            print(f"    {hostlib:26} <= {oss} {ver}")
            nfound += 1

    con.commit()
    nb = con.execute("SELECT COUNT(*) FROM link WHERE link_type='static-bundled'").fetchone()[0]
    nl = con.execute("SELECT COUNT(*) FROM link WHERE link_type='static-in-lib'").fetchone()[0]
    print(f"\nstatic-bundled (in binary): {nb}   static-in-lib: {nl}")
    con.close()


if __name__ == "__main__":
    main()
