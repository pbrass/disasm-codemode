#!/usr/bin/env python3
"""bnstatus.py - is the Binary Ninja code-mode MCP reachable, and what's loaded?

Run this first when a code-mode call fails for an unclear reason: it distinguishes "the MCP is
down / not started" from a real analysis error, and prints how to fix it. Exit 0 if up, 1 if down.
Env: BINJA_MCP_URL (default http://127.0.0.1:42069), BINJA_MCP_KEY (default binja-codemode-local).
"""
import os, sys, re, json, urllib.request

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
def _scrub(s):  # the loaded-binary path is attacker-influenceable; neutralize escape bytes
    return _CTRL.sub(lambda m: "\\x%02x" % ord(m.group(0)), s) if s else s

URL = os.environ.get("BINJA_MCP_URL", "http://127.0.0.1:42069").rstrip("/")
KEY = os.environ.get("BINJA_MCP_KEY", "binja-codemode-local")

try:
    req = urllib.request.Request(URL + "/status", headers={"Authorization": "Bearer " + KEY})
    j = json.load(urllib.request.urlopen(req, timeout=6))
    binf = j.get("binary") or {}
    print("BN code-mode MCP: %s  (%s)" % (j.get("status", "running"), URL))
    print("loaded binary   : %s" % _scrub(binf.get("filename") or "(none open)"))
    sys.exit(0)
except Exception as e:
    sys.stderr.write(
        "BN code-mode MCP NOT reachable at %s (%s)\n" % (URL, e.__class__.__name__)
        + "Fix: in Binary Ninja, start the code-mode MCP server\n"
        + "     (Plugins > MCP Code Mode > Start Server; binds 127.0.0.1:42069).\n"
        + "     It also auto-starts once a binary is open. Then retry.\n"
        + "     Point elsewhere with BINJA_MCP_URL / BINJA_MCP_KEY.\n")
    sys.exit(1)
