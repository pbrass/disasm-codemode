#!/usr/bin/env python3
"""Shared client + INJECTION-SAFE helpers for the `ghidra` code-mode templates.

Talks to ghidra-headless-mcp (github.com/mrphrazer/ghidra-headless-mcp) over its MCP JSON-RPC
transport and drives the `ghidra.eval` code-mode primitive (arbitrary Python against the live
PyGhidra runtime). Importable (no module-level side effects).

This is the Ghidra sibling of the binary-ninja skill's bncm.py: SAME security model, SAME
validator/pylit/scrub helpers, SAME "constant body + validated-literal prologue" template shape.
Only the transport (MCP/TCP instead of BN's HTTP /execute) and the target model (a server-side
analyzed *session* instead of a BinaryView) differ.

SECURITY MODEL (why these templates are not template-injectable)
----------------------------------------------------------------
User-supplied values (function/symbol names, addresses, regexes, sections, search strings,
paths) reach the executed Python through TWO independent guards:

  1. VALIDATION — every input is checked by a type-specific validator (vsym/vaddr/vregex/
     vsection/vneedle/vpath/vprogmatch) that REJECTS control characters and the quote/
     backslash/backtick/semicolon break-out characters. Rejection exits non-zero before
     anything is sent.

  2. ESCAPED-LITERAL EMBEDDING — validated values are embedded ONLY as `pylit(v)` literals
     (strings via json.dumps -> a valid, fully-escaped Python string literal; ints as ints).
     They are placed in a PROLOGUE of `name = <literal>` lines.

The per-template BODY is a CONSTANT string that only references those prologue variable names
and the eval-context objects (`program`, `decompiler`, `flat_api`, `listing`, `memory`,
`symbol_table`, `pyghidra`, `ghidra`). User input is NEVER concatenated/f-string-interpolated
into the body, and nothing is ever passed through a shell. So even if a quote/backslash slipped
past guard 1, json.dumps in guard 2 keeps it inside the string literal.

TAINTED OUTPUT — everything ghidra.eval returns about the analyzed binary (decompiled C,
function/symbol names, string values, disassembly) is ATTACKER-CONTROLLED. A malicious binary
can embed ANSI/OSC terminal escapes in a name/string. scrub() renders every control byte as a
visible \\xNN before we print it (keeping \\n and \\t so output stays readable).

CONNECTION — set GHIDRA_MCP_HOST / GHIDRA_MCP_PORT (default 127.0.0.1:8765) to the running
ghidra-headless-mcp TCP server. Start one with:
  GHIDRA_INSTALL_DIR=/path/to/ghidra python3 ghidra_headless_mcp.py --transport tcp --port 8765
"""
import sys, os, re, json, socket, time

HOST = os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8765"))
TIMEOUT = float(os.environ.get("GHIDRA_MCP_TIMEOUT", "600"))            # per-call read timeout
CONNECT_TIMEOUT = float(os.environ.get("GHIDRA_MCP_CONNECT_TIMEOUT", "10"))

# exit codes: 2 = input rejected, 1 = hard error (eval/analysis failed), 3 = MCP unreachable
EXIT_REJECT, EXIT_ERROR, EXIT_UNREACHABLE = 2, 1, 3


def die(msg, code=EXIT_REJECT):
    sys.stderr.write("[reject] %s\n" % msg)
    sys.exit(code)


def fail(msg, code=EXIT_ERROR):
    sys.stderr.write("[ghidra] %s\n" % msg)
    sys.exit(code)


# ---------------------------------------------------------------- validation
# (identical to bncm.py — the safety surface must not drift between the two skills)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
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
    """A regex run by re.search inside the eval. Embedded as a json.dumps literal (cannot
    inject code); we reject control chars, cap length, and require it to compile."""
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


def vprogmatch(s, what="program-match"):
    """Substring used to select an already-open server-side session by program name/path."""
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
_CTRL_OUT = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def scrub(s):
    if not s:
        return s
    return _CTRL_OUT.sub(lambda m: "\\x%02x" % ord(m.group(0)), s)


# ------------------------------------------------------- MCP JSON-RPC client
class MCPError(Exception):
    pass


class Client:
    """Minimal line-delimited MCP/JSON-RPC client for ghidra-headless-mcp's TCP transport."""

    def __init__(self, host=HOST, port=PORT):
        try:
            self.sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as e:
            fail("ghidra-headless-mcp not reachable at %s:%d (%s).\n"
                 "         start it:  GHIDRA_INSTALL_DIR=/path/to/ghidra \\\n"
                 "                    python3 ghidra_headless_mcp.py --transport tcp --port %d"
                 % (host, port, e, port), code=EXIT_UNREACHABLE)
        self.buf = b""
        self._id = 0
        self._handshake()

    def _readline(self, timeout):
        self.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                raise MCPError("timed out waiting for a response (raise GHIDRA_MCP_TIMEOUT)")
            if not chunk:
                raise MCPError("server closed the connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line

    def rpc(self, method, params=None, timeout=TIMEOUT, notify=False):
        self._id += 1
        msg = {"jsonrpc": "2.0", "method": method}
        if not notify:
            msg["id"] = self._id
        if params is not None:
            msg["params"] = params
        self.sock.sendall((json.dumps(msg) + "\n").encode())
        if notify:
            return None
        resp = json.loads(self._readline(timeout).decode())
        if "error" in resp:
            raise MCPError("%s -> %s" % (method, resp["error"]))
        return resp["result"]

    def _handshake(self):
        self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                "clientInfo": {"name": "disasm-codemode", "version": "0"}}, timeout=60)
        self.rpc("notifications/initialized", notify=True)

    def call_tool(self, name, arguments, timeout=TIMEOUT):
        """Returns (structuredContent dict, isError bool)."""
        res = self.rpc("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
        return res.get("structuredContent", {}) or {}, bool(res.get("isError"))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------- session find-or-open
def _abspath(p):
    return os.path.abspath(os.path.expanduser(p))


def ensure_session(client, *, file=None, program=None, reanalyze=False):
    """Resolve the target to a server-side session_id.

    --file PATH    : reuse an already-open session for that path if present (find-or-open),
                     else program.open + auto-analyze.  --reanalyze forces a fresh open.
    --program SUB  : attach to an already-open session whose program name/path contains SUB
                     (no reload). Errors if none match.
    """
    if program is not None:
        opened, _ = client.call_tool("program.list_open", {}, timeout=60)
        for rec in _session_records(opened):
            hay = "%s %s %s" % (rec.get("program_name", ""), rec.get("filename", ""),
                                rec.get("source_path", ""))
            if program in hay and rec.get("session_id"):
                return rec["session_id"]
        fail("no open session matches --program %r (open one with --file PATH first)" % program)

    abspath = _abspath(file)
    if not os.path.exists(abspath):
        die("--file does not exist: %s" % abspath)
    if not reanalyze:
        opened, _ = client.call_tool("program.list_open", {}, timeout=60)
        for rec in _session_records(opened):
            recpath = rec.get("filename") or rec.get("source_path")
            if recpath and rec.get("session_id"):
                try:
                    if _abspath(recpath) == abspath:
                        return rec["session_id"]
                except (OSError, ValueError):
                    pass
    summary, err = client.call_tool(
        "program.open", {"path": abspath, "update_analysis": True, "read_only": True}, timeout=TIMEOUT)
    if err or not summary.get("session_id"):
        fail("program.open failed for %s: %s" % (abspath, scrub(json.dumps(summary))[:400]))
    return summary["session_id"]


def _session_records(payload):
    """program.list_open returns a list of session records under one of a few key names;
    be defensive about the exact shape across versions."""
    if isinstance(payload, dict):
        for k in ("sessions", "open", "programs", "items", "results"):
            if isinstance(payload.get(k), list):
                return [r for r in payload[k] if isinstance(r, dict)]
        if payload.get("session_id"):
            return [payload]
        return []
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    return []


# ------------------------------------------------------------ argparse glue
def add_target_args(ap):
    """Standard target selection: --file PATH (open/reuse) XOR --program SUBSTR (attach)."""
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", help="path to a binary to import + auto-analyze (reuses an open session for the same path)")
    g.add_argument("--program", help="substring of an ALREADY-OPEN server-side program name/path to use (no reload)")
    ap.add_argument("--reanalyze", action="store_true", help="force a fresh program.open even if a session is already open")


def target_kwargs(args):
    """Validate target selection -> kwargs for ensure_session()."""
    if getattr(args, "file", None):
        return {"file": vpath(args.file), "reanalyze": bool(getattr(args, "reanalyze", False))}
    return {"program": vprogmatch(args.program)}


# ------------------------------------------------------------- run a template
def build_eval_code(body, **params):
    """Build the prologue(validated literals) + wrapped constant body sent to ghidra.eval.

    Separated from run() so the injection-safe embedding can be unit-tested without a server.

    The body is wrapped in try/except because ghidra.eval (like BN's /execute) DISCARDS captured
    stdout if the executed code raises: a body that does `print("[no function...]"); raise
    SystemExit` would otherwise lose its message. Catching SystemExit lets the graceful message
    through; catching Exception turns an unexpected API error into a readable line instead of a
    lost-stdout tool error."""
    prologue = "".join("%s = %s\n" % (k, pylit(v)) for k, v in params.items())
    indented = "\n".join(("    " + ln) if ln.strip() else ln for ln in body.split("\n"))
    # _toaddr(): build a Ghidra Address from an int via the STRING overload. flat_api.toAddr(int)
    # makes JPype pick toAddr(int) and OverflowError on any offset > 2**31-1 (i.e. most real 64-bit
    # addresses) — the string form sidesteps overload resolution entirely. Bodies use _toaddr(...).
    helpers = ("def _toaddr(_v):\n"
               "    return flat_api.toAddr('0x%x' % (int(_v) & 0xffffffffffffffff))\n")
    return ("import re\n" + helpers + prologue
            + "try:\n" + indented
            + "\nexcept SystemExit:\n    pass\n"
            + "except Exception as _e:\n"
            + "    print('[ghidra] body error: %s: %s' % (type(_e).__name__, _e))\n")


def run(body, args, **params):
    """Resolve the target session, eval the built code against it, and print SCRUBBED stdout."""
    code = build_eval_code(body, **params)
    client = Client()
    try:
        session_id = ensure_session(client, **target_kwargs(args))
        out, err = client.call_tool("ghidra.eval", {"code": code, "session_id": session_id})
    finally:
        client.close()

    text = scrub(out.get("stdout") or "")          # tainted: attacker-controlled binary
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
    if out.get("stderr"):
        sys.stderr.write("[ghidra stderr]\n" + scrub(out["stderr"]) + "\n")
    if err:
        sys.stderr.write("[ghidra ERROR] " + scrub(json.dumps(out))[:600] + "\n")
        sys.exit(EXIT_ERROR)
    return text
