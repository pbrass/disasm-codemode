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

def _list_tabs():
    # /status only reports the ACTIVE binary; enumerate ALL open GUI tabs so --bv-match is unambiguous
    code = ("from binaryninjaui import UIContext\n"
            "_n=[]\n"
            "for _c in UIContext.allContexts():\n"
            "    for _v,_nm in _c.getAvailableBinaryViews(): _n.append(_nm)\n"
            "print('\\n'.join(_n) if _n else '(no tabs)')\n")
    req = urllib.request.Request(URL + "/execute", data=json.dumps({"code": code}).encode(),
        headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"}, method="POST")
    out = json.load(urllib.request.urlopen(req, timeout=15)).get("output", "") or ""
    return [re.sub(r"^\[[0-9.]+s\]\s*", "", t).strip() for t in out.splitlines() if t.strip()]

try:
    req = urllib.request.Request(URL + "/status", headers={"Authorization": "Bearer " + KEY})
    j = json.load(urllib.request.urlopen(req, timeout=6))
    binf = j.get("binary") or {}
    print("BN code-mode MCP: %s  (%s)" % (j.get("status", "running"), URL))
    print("active binary   : %s" % _scrub(binf.get("filename") or "(none open)"))
    try:
        tabs = _list_tabs()
        print("open tabs (%d)  : %s" % (len(tabs), ", ".join(_scrub(t) for t in tabs) or "(none)"))
        print("  -> bn-* --bv-match <substr> must match exactly ONE of these; else bn-open <ABS path> or --file <ABS path>.")
    except Exception:
        pass
    sys.exit(0)
except Exception as e:
    sys.stderr.write(
        "BN code-mode MCP NOT reachable at %s (%s)\n" % (URL, e.__class__.__name__)
        + "This is the ONE step a human must do (the GUI is a desktop app). Ask the user to:\n"
        + "  1. Open the Binary Ninja GUI.\n"
        + "  2. Load at least one file (any binary or .bndb) — the MCP won't start with no view open.\n"
        + "  3. Enable the code-mode MCP server by clicking its button in the BOTTOM-LEFT corner of the\n"
        + "     main window (it then binds 127.0.0.1:42069).\n"
        + "Then re-run bn-status. Point elsewhere with BINJA_MCP_URL / BINJA_MCP_KEY.\n")
    sys.exit(1)
