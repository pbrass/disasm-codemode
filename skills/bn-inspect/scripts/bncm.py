#!/usr/bin/env python3
"""Shared client + INJECTION-SAFE helpers for the bn-inspect templates.

Talks to the Binary Ninja code-mode MCP `/execute` endpoint (same endpoint/env as the
binary-ninja skill's binja.py). Importable (no module-level side effects).

SECURITY MODEL (why these templates are not template-injectable)
----------------------------------------------------------------
Each template sends Python source to `/execute`. User-supplied values (function names,
addresses, regexes, section names, search strings, paths) reach that source through TWO
independent guards:

  1. VALIDATION — every input is checked by a type-specific validator (vsym/vaddr/vregex/
     vsection/vneedle/vpath/vbvmatch) that REJECTS control characters and the quote/
     backslash/backtick/semicolon break-out characters (the user's "reject suspicious
     characters" request). Rejection exits non-zero before anything is sent.

  2. ESCAPED-LITERAL EMBEDDING — validated values are embedded ONLY as `pylit(v)` literals
     (strings via json.dumps -> a valid, fully-escaped Python string literal; ints as ints;
     bools/None as keywords). They are placed in a PROLOGUE of `name = <literal>` lines.

The per-template BODY is a CONSTANT string that only references those prologue variable
names. User input is NEVER concatenated/f-string-interpolated into the body, and nothing is
ever passed through a shell. So even if a quote/backslash slipped past guard 1, json.dumps in
guard 2 keeps it inside the string literal — it cannot break out into executed code.

CODE-MODE SANDBOX NOTE: inside `/execute`, comprehension/def bodies do NOT see names assigned
at the top level of the executed code (they resolve free names against module globals only).
So the BODIES below reference prologue vars (`_name`, `_rx`, ...) only from plain `for`/`if`
statements, never from inside a comprehension/generator/def body. (The outermost iterable of
a comprehension is fine — it is evaluated in the enclosing scope.)
"""
import sys, os, re, json, urllib.request

URL = os.environ.get("BINJA_MCP_URL", "http://127.0.0.1:42069").rstrip("/")
KEY = os.environ.get("BINJA_MCP_KEY", "binja-codemode-local")
HTTP_TIMEOUT = float(os.environ.get("BINJA_HTTP_TIMEOUT", "900"))


def die(msg, code=2):
    sys.stderr.write("[reject] %s\n" % msg)
    sys.exit(code)


# ---------------------------------------------------------------- validation
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
# break-out characters for the Python-string / JSON contexts we build:
_BREAKOUT = ("\"", "'", "\\", "`", ";")


def _common(s, what, maxlen):
    if not isinstance(s, str) or s == "":
        die("%s is empty" % what)
    if len(s) > maxlen:
        die("%s too long (>%d chars)" % (what, maxlen))
    if _CTRL.search(s):
        die("%s contains a control character" % what)
    return s


_SYM = re.compile(r"^[A-Za-z0-9_.:$@~?<>,*&()\[\]/+-]{1,512}$")


def vsym(s, what="name"):
    """Function / symbol name. Allows the punctuation real C/C++/Go/Rust symbols use, but
    rejects quote/backslash/backtick/semicolon (and any control char)."""
    _common(s, what, 512)
    for b in _BREAKOUT:
        if b in s:
            die("%s contains forbidden character %r" % (what, b))
    if not _SYM.match(s):
        die("%s has characters outside the allowed symbol set" % what)
    return s


def vaddr(s, what="address"):
    """Hex (0x...) or decimal address -> int in [0, 2**64)."""
    _common(s, what, 34)
    t = s.lower()
    if re.fullmatch(r"0x[0-9a-f]+", t):
        n = int(t, 16)
    elif re.fullmatch(r"[0-9]+", t):
        n = int(t, 10)
    else:
        die("%s must be hex (0x...) or decimal digits" % what)
    if not (0 <= n < (1 << 64)):
        die("%s out of 64-bit range" % what)
    return n


def vregex(s, what="pattern"):
    """A regex run by re.search inside BN. Embedded as a json.dumps literal (cannot inject
    code); we reject control chars, cap length, and require it to compile."""
    _common(s, what, 512)
    try:
        re.compile(s)
    except re.error as e:
        die("%s is not a valid regex: %s" % (what, e))
    return s


def vsection(s, what="section"):
    _common(s, what, 64)
    if not re.fullmatch(r"[.A-Za-z0-9_$-]{1,64}", s):
        die("%s has invalid characters" % what)
    return s


def vneedle(s, what="string"):
    """A search needle MAY legitimately contain quotes etc., so we do not char-restrict it;
    safety comes from pylit/json.dumps escaping. We only reject control chars + cap length."""
    return _common(s, what, 1024)


def vpath(s, what="file"):
    _common(s, what, 4096)
    for b in _BREAKOUT + ("$", "*", "?", "\n"):
        if b in s:
            die("%s contains forbidden character %r" % (what, b))
    if not re.fullmatch(r"[A-Za-z0-9_./ +=-]{1,4096}", s):
        die("%s has invalid characters (allowed: letters digits _ . / space + = -)" % what)
    return s


def vbvmatch(s, what="bv-match"):
    _common(s, what, 256)
    if not re.fullmatch(r"[A-Za-z0-9_./ +-]{1,256}", s):
        die("%s has invalid characters" % what)
    return s


# ---------------------------------------------------------- safe literal embed
def pylit(v):
    """Render a Python value as a valid, fully-escaped Python literal."""
    if isinstance(v, bool):
        return "True" if v else "False"
    if v is None:
        return "None"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)               # JSON string == valid escaped Python str literal
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(pylit(x) for x in v) + "]"
    die("unsupported literal type %s" % type(v).__name__)


# ---------------------------------------------- tainted-output sanitization
# Everything the code-mode MCP returns about the analyzed binary (function/symbol names,
# string values, decompiled HLIL, disassembly) is ATTACKER-CONTROLLED — a malicious binary
# can embed ANSI/OSC terminal-escape sequences in a symbol name or string. Printed raw, those
# can hijack the terminal (OSC 52 clipboard, title/cursor moves, OSC 8 hyperlinks) or spoof
# output to mislead the reader/agent. scrub() renders every control byte as a visible \xNN
# (keeping \n and \t so HLIL/structured output stays readable).
_CTRL_OUT = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def scrub(s):
    if not s:
        return s
    return _CTRL_OUT.sub(lambda m: "\\x%02x" % ord(m.group(0)), s)


# ----------------------------------------------- BV selection prologue (const)
# Uses prologue vars `_file` (path or None) and `_bvmatch` (substr or None).
SELECT_BV = r'''
import binaryninja, re
_bv = None
if _file:
    try:
        _bv = binaryninja.load(_file, update_analysis=True)
    except Exception as _e:
        print("[bn-inspect] ERROR: could not load %r (%s)" % (_file, _e))
        raise SystemExit
else:
    try:
        from binaryninjaui import UIContext
        for _ctx in UIContext.allContexts():
            for _vv, _nm in _ctx.getAvailableBinaryViews():
                if _bvmatch and _bvmatch in _nm:
                    _bv = _vv
    except Exception:
        pass
    if _bv is None:
        try:
            _bv = binja._bv
        except Exception:
            _bv = None
if _bv is None:
    print("[bn-inspect] ERROR: no BinaryView. Give --file PATH (headless) or open the tab and use --bv-match SUBSTR.")
    raise SystemExit
'''


def execute(code):
    req = urllib.request.Request(
        URL + "/execute", data=json.dumps({"code": code}).encode(),
        headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return json.load(r)


def add_target_args(ap):
    """Standard --file / --bv-match selection (mutually exclusive, one required)."""
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", help="path to a binary to load HEADLESS (validated)")
    g.add_argument("--bv-match", help="substring of an OPEN BN GUI tab name to use (no reload)")


def target_params(args):
    """Validate the target selection -> {_file, _bvmatch} prologue params."""
    f = vpath(args.file) if args.file else None
    m = vbvmatch(args.bv_match) if args.bv_match else None
    return {"_file": f, "_bvmatch": m}


def run(body, **params):
    """Build prologue(validated literals) + SELECT_BV + constant body; execute; print output.

    The SELECT_BV/body are wrapped in `try/except SystemExit` because the code-mode executor
    DISCARDS captured stdout when the executed code raises (incl. SystemExit) -- so a body that
    does `print("[no function...]"); raise SystemExit` would otherwise lose its message. Catching
    SystemExit lets the graceful message reach the agent while still stopping the body early."""
    prologue = "".join("%s = %s\n" % (k, pylit(v)) for k, v in params.items())
    inner = SELECT_BV + body
    indented = "\n".join(("    " + ln) if ln.strip() else ln for ln in inner.split("\n"))
    res = execute(prologue + "try:\n" + indented + "\nexcept SystemExit:\n    pass\n")
    out = scrub(res.get("output") or "")           # output is tainted (attacker-controlled binary)
    sys.stdout.write(out)
    if out and not out.endswith("\n"):
        sys.stdout.write("\n")
    if res.get("error"):
        sys.stderr.write("[BN ERROR]\n" + scrub(res["error"]) + "\n")
        sys.exit(1)
    if res.get("timed_out"):
        sys.stderr.write("[BN TIMED OUT] (large binary? raise BINJA_HTTP_TIMEOUT or use --bv-match)\n")
        sys.exit(1)
    return out
