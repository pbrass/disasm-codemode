#!/usr/bin/env python3
"""Self-describing scope for a binary-audit ledger.

The single biggest schema defect in `kreview.db` was that nothing in it recorded
WHAT was audited. The directory path was the only evidence -- so a ledger at
`audit/vmci/kreview.db` meant "the vmci module of some particular build" purely
by convention, and promoting its bugs into a findings DB needed a human to
supply target/build/component by hand for every ledger.

This writes that provenance into the ledger itself, so a downstream consumer can
read it instead of being told it. `fdb register-ledger` reads this table when
--target/--build are not passed.

Nothing here is required: an extractor run with no scope still produces a valid
ledger, it just records what little it knows and says so. That keeps the flag
optional for quick one-off audits while making the scoped run the easy default.
"""
import hashlib
import os
import sqlite3
import time

DDL = """
CREATE TABLE IF NOT EXISTS audit_scope(
  id INTEGER PRIMARY KEY CHECK(id = 1),   -- one row; the ledger audits one binary
  target      TEXT,   -- product-line slug, matching findings-db target.slug ('esxi')
  build       TEXT,   -- vendor build number, matching build.build ('25205845')
  component   TEXT,   -- binary/module within the build ('vmkernel', 'vmx', 'nfs41client')
  binary_path TEXT,
  binary_sha256 TEXT,
  profile     TEXT,   -- the ranking function this ledger was scored with
  extractor   TEXT,   -- which extractor wrote it (symbol table vs Binary Ninja)
  extracted_at TEXT
);
"""

ENV = {"target": "KAUDIT_TARGET", "build": "KAUDIT_BUILD",
       "component": "KAUDIT_COMPONENT"}


def add_args(ap):
    """Attach --target/--build/--component to an argparse parser."""
    ap.add_argument("--target", help="product-line slug, e.g. esxi "
                                     "(env KAUDIT_TARGET)")
    ap.add_argument("--build", help="vendor build number, e.g. 25205845 "
                                    "(env KAUDIT_BUILD)")
    ap.add_argument("--component", help="binary/module name, e.g. vmkernel "
                                        "(env KAUDIT_COMPONENT)")


def from_args(args):
    """-> {target,build,component}, CLI flag winning over env var."""
    return {k: (getattr(args, k, None) or os.environ.get(env) or None)
            for k, env in ENV.items()}


def sha256(path):
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write(db_path, *, extractor, binary_path=None, profile=None, **scope):
    """Record what this ledger audits. Returns the row as a dict.

    Called AFTER the extractor's own executescript, which drops and recreates
    func/edge -- audit_scope is deliberately not in that drop list, but writing
    afterwards keeps it correct even if someone adds it later.
    """
    row = {
        "target": scope.get("target"),
        "build": scope.get("build"),
        "component": scope.get("component"),
        "binary_path": os.path.abspath(binary_path) if binary_path else None,
        "binary_sha256": sha256(binary_path),
        "profile": os.path.abspath(profile) if profile else None,
        "extractor": extractor,
        "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    con = sqlite3.connect(db_path)
    con.executescript(DDL)
    cols = ", ".join(row)
    con.execute(f"INSERT OR REPLACE INTO audit_scope(id, {cols}) "
                f"VALUES(1, {', '.join('?' * len(row))})", tuple(row.values()))
    con.commit()
    con.close()
    return row


def report(row):
    """One line to stderr/stdout describing the scope, or warning it is absent."""
    named = [f"{k}={row[k]}" for k in ("target", "build", "component") if row[k]]
    if named:
        return "[audit-scope] " + " ".join(named)
    return ("[audit-scope] no target/build/component recorded -- pass "
            "--target/--build/--component (or set KAUDIT_TARGET/KAUDIT_BUILD/"
            "KAUDIT_COMPONENT) so downstream tools need no manual mapping")


def read(db_path):
    """-> the scope dict, or None if this ledger predates the scope table."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        r = con.execute("SELECT * FROM audit_scope WHERE id = 1").fetchone()
    except sqlite3.OperationalError:
        return None          # legacy ledger; the caller falls back to flags
    finally:
        con.close()
    return dict(r) if r else None
