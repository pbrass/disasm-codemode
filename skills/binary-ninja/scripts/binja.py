#!/usr/bin/env python3
# Helper: send Python code to the Binary Ninja Code-Mode MCP /execute endpoint.
# Usage: binja.py < code.py   OR   binja.py 'one-liner'
import sys, os, re, json, urllib.request
# Tainted-output guard: a malicious analyzed binary can embed terminal-escape bytes in symbol
# names/strings; neutralize them before printing (see reference/mcp-codemode-guide.md §F).
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
def _scrub(s):
    return _CTRL.sub(lambda m: "\\x%02x" % ord(m.group(0)), s) if s else s
URL=os.environ.get("BINJA_MCP_URL", "http://127.0.0.1:42069")
KEY=os.environ.get("BINJA_MCP_KEY", "binja-codemode-local")
# Client HTTP timeout must exceed the server /execute timeout (600s) so giant-module
# analyses (large binaries, 1-5 min) don't get cut off client-side. Override via BINJA_HTTP_TIMEOUT.
HTTP_TIMEOUT=float(os.environ.get("BINJA_HTTP_TIMEOUT","900"))
code = sys.argv[1] if len(sys.argv)>1 else sys.stdin.read()
def call(path, payload):
    req=urllib.request.Request(URL+path, data=json.dumps(payload).encode(),
        headers={"Authorization":f"Bearer {KEY}","Content-Type":"application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r: return json.load(r)
res=call("/execute", {"code": code})
if res.get("output"): print(_scrub(res["output"]), end="")
if res.get("error"): print("\n[ERROR]\n"+_scrub(res["error"]), file=sys.stderr)
if res.get("timed_out"): print("[TIMED OUT]", file=sys.stderr)
