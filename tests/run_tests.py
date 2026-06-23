#!/usr/bin/env python3
"""Thorough test suite for the disasm-codemode plugin skills.

Run with a python that has capstone + pyelftools (for cap_scan/symdiff):
    python3 tests/run_tests.py
It builds the C fixtures, runs unit tests for the injection guards (no BN needed),
then - if the Binary Ninja code-mode MCP is up - the integration tests for every
skill CLI + scanner template, plus the BN-independent cap_scan/symdiff tests.
Exit code is nonzero if any test FAILS (SKIPs do not fail the run)."""
import os, sys, re, json, subprocess, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FX = os.path.join(HERE, "fixtures")
INSPECT = os.path.join(ROOT, "skills", "bn-inspect", "scripts")
HUNT = os.path.join(ROOT, "skills", "bn-hunt", "scripts")
BNJA = os.path.join(ROOT, "skills", "binary-ninja", "scripts")
GHIDRA = os.path.join(ROOT, "skills", "ghidra", "scripts")
PY = sys.executable
MCP_URL = os.environ.get("BINJA_MCP_URL", "http://127.0.0.1:42069").rstrip("/")
MCP_KEY = os.environ.get("BINJA_MCP_KEY", "binja-codemode-local")
GH_HOST = os.environ.get("GHIDRA_MCP_HOST", "127.0.0.1")
GH_PORT = int(os.environ.get("GHIDRA_MCP_PORT", "8765"))

# fixtures
T = os.path.join(FX, "target")
TSTRIP = os.path.join(FX, "target.stripped")
TO = os.path.join(FX, "target.o")
TO2 = os.path.join(FX, "target_v2.o")
NOTELF = os.path.join(FX, "notelf.txt")
EMPTY = os.path.join(FX, "empty.bin")
MISSING = os.path.join(FX, "does_not_exist_zzz.bin")

P = F = S = 0
FAILS = []


def ok(name):
    global P; P += 1; print("  [pass] " + name)


def bad(name, why, extra=""):
    global F; F += 1; FAILS.append(name)
    print("  [FAIL] %s :: %s" % (name, why))
    if extra:
        print("         " + extra.replace("\n", "\n         ")[:600])


def skip(name, why):
    global S; S += 1; print("  [skip] %s :: %s" % (name, why))


def sh(cmd, timeout=180):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def expect(name, cmd, rc=None, has=(), nothas=()):
    """Run a CLI; assert exit code + substring/regex presence/absence over stdout+stderr."""
    try:
        code, o, e = sh(cmd)
    except subprocess.TimeoutExpired:
        return bad(name, "TIMEOUT")
    blob = o + "\n" + e
    probs = []
    if rc is not None and code != rc:
        probs.append("rc=%s want %s" % (code, rc))
    for h in has:
        if not re.search(h, blob):
            probs.append("missing /%s/" % h)
    for nh in nothas:
        if re.search(nh, blob):
            probs.append("unexpected /%s/" % nh)
    if probs:
        return bad(name, "; ".join(probs), o or e)
    ok(name)


def uassert(name, cond, extra=""):
    if cond:
        ok(name)
    else:
        bad(name, "assertion false", extra)


# ----------------------------------------------------------------- MCP helpers
def mcp_up():
    try:
        req = urllib.request.Request(MCP_URL + "/status", headers={"Authorization": "Bearer " + MCP_KEY})
        urllib.request.urlopen(req, timeout=8).read()
        return True
    except Exception:
        return False


def mcp_execute(code):
    req = urllib.request.Request(MCP_URL + "/execute", data=json.dumps({"code": code}).encode(),
                                 headers={"Authorization": "Bearer " + MCP_KEY, "Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)


def addr_of(fn):
    code, o, e = sh([PY, os.path.join(INSPECT, "findfunc.py"), "--file", T, fn])
    m = re.search(r"0x([0-9a-fA-F]+)\s+" + re.escape(fn) + r"\b", o)
    return ("0x" + m.group(1)) if m else None


# =========================================================== UNIT: bncm guards
def unit_bncm():
    print("\n## unit: bncm.py injection guards (no BN)")
    sys.path.insert(0, INSPECT)
    import importlib
    import bncm
    importlib.reload(bncm)

    # pylit: valid, escaped, round-tripping literals
    nasties = ['a"b', "a'b", "a\\b", "a\nb", "a\tb", "résumé", '"; import os; os.system("id"); "', "`id`", "$(id)", "x" * 300]
    for s in nasties:
        try:
            lit = bncm.pylit(s)
            roundtrip = (eval(lit) == s)
            isstr = lit[:1] in ("\"", "'")
            uassert("pylit round-trips %r" % s[:14], roundtrip and isstr, "lit=" + lit[:80])
        except SystemExit:
            bad("pylit round-trips %r" % s[:14], "pylit rejected a legal string")
    uassert("pylit int", bncm.pylit(4096) == "4096")
    uassert("pylit bool", bncm.pylit(True) == "True" and bncm.pylit(False) == "False")
    uassert("pylit None", bncm.pylit(None) == "None")
    uassert("pylit list round-trips", eval(bncm.pylit([1, 'a"b', True, None])) == [1, 'a"b', True, None])

    def rejects(fn, *a):
        try:
            fn(*a); return False
        except SystemExit as ex:
            return ex.code == 2

    uassert("vsym accepts real symbol", bncm.vsym("VmDir_a.b::c$x") == "VmDir_a.b::c$x")
    for b in ["a'b", 'a"b', "a\\b", "a`b", "a;b", "a\nb", "", "x" * 600]:
        uassert("vsym rejects %r" % b[:8], rejects(bncm.vsym, b))
    uassert("vaddr hex", bncm.vaddr("0x1000") == 4096)
    uassert("vaddr dec", bncm.vaddr("4096") == 4096)
    for b in ["0xZ", "12x", "", "0x" + "f" * 20, "-1", "0x"]:
        uassert("vaddr rejects %r" % b[:10], rejects(bncm.vaddr, b))
    uassert("vpath accepts", bncm.vpath("/tmp/a_b.bin") == "/tmp/a_b.bin")
    for b in ["/tmp/a;rm", "/tmp/$x", "/tmp/a*", "a'b", "/tmp/a`b", "/tmp/a\nb"]:
        uassert("vpath rejects %r" % b[:10], rejects(bncm.vpath, b))
    uassert("vsection accepts", bncm.vsection(".rodata") == ".rodata")
    uassert("vsection rejects", rejects(bncm.vsection, ".text;x"))
    uassert("vregex accepts", bncm.vregex("a.*b|c") == "a.*b|c")
    uassert("vregex rejects invalid", rejects(bncm.vregex, "a["))
    uassert("vneedle allows quotes", bncm.vneedle('he said "hi"') == 'he said "hi"')
    uassert("vneedle rejects control", rejects(bncm.vneedle, "a\x01b"))

    # run(): the un-char-restricted needle must be embedded as an inert escaped literal
    cap = {}
    orig = bncm.execute
    bncm.execute = lambda code: (cap.__setitem__("code", code), {"output": "ok\n"})[1]
    try:
        payload = '"; import os; os.system("id"); X="'
        bncm.run("print('done')", X=payload, _file=None, _bvmatch=None)
        code = cap.get("code", "")
        xlines = [l for l in code.splitlines() if l.startswith("X = ")]
        embedded_ok = bool(xlines) and eval(xlines[0][4:]) == payload
        no_bareword_injection = "os.system" not in "\n".join(l for l in code.splitlines() if not l.startswith("X = "))
        uassert("run() embeds injection as an inert literal", embedded_ok and no_bareword_injection,
                "X-line=" + (xlines[0] if xlines else "<none>"))
    finally:
        bncm.execute = orig


# ===================================================== INTEGRATION: bn-inspect
def test_inspect():
    print("\n## bn-inspect")
    dec = [PY, os.path.join(INSPECT, "decompile.py")]
    ff = [PY, os.path.join(INSPECT, "findfunc.py")]
    xr = [PY, os.path.join(INSPECT, "xrefs.py")]
    sx = [PY, os.path.join(INSPECT, "strxref.py")]
    sc = [PY, os.path.join(INSPECT, "scansec.py")]

    # decompile
    expect("decompile leaf (HLIL)", dec + ["--file", T, "leaf"], rc=0, has=[r"leaf @ 0x", r"return"], nothas=[r"Traceback"])
    expect("decompile main --grep", dec + ["--file", T, "main", "--grep", "memcpy|sprintf|malloc"], rc=0, has=[r"\|"])
    expect("decompile --asm", dec + ["--file", T, "leaf", "--asm"], rc=0, has=[r"disassembly", r"ret"])
    expect("decompile missing-name graceful", dec + ["--file", T, "no_such_fn_zzz"], rc=0, has=[r"no function named"], nothas=[r"Traceback"])
    expect("decompile bad-addr graceful", dec + ["--file", T, "--addr", "0xffffff00"], rc=0, has=[r"no function at"], nothas=[r"Traceback"])
    expect("decompile injection reject", dec + ["--file", T, "a'b"], rc=2, has=[r"\[reject\]"])
    expect("decompile missing file graceful", dec + ["--file", MISSING, "leaf"], rc=0, has=[r"could not load|no BinaryView"], nothas=[r"Traceback \(most"])

    # findfunc
    expect("findfunc substring", ff + ["--file", T, "leaf"], rc=0, has=[r"match 'leaf'", r"leaf"])
    expect("findfunc regex", ff + ["--file", T, "--regex", r"^(big_frame|recurse_sum)$"], rc=0, has=[r"big_frame", r"recurse_sum"])
    expect("findfunc no match", ff + ["--file", T, "zzz_nomatch_zzz"], rc=0, has=[r"0 function\(s\) match"])
    expect("findfunc reject", ff + ["--file", T, "a;b"], rc=2, has=[r"\[reject\]"])
    # --addr two-step
    a = addr_of("leaf")
    if a:
        expect("findfunc --addr resolves", ff + ["--file", T, "--addr", a], rc=0, has=[r"leaf"])
    else:
        skip("findfunc --addr resolves", "could not resolve leaf addr")
    # --no-imports drops imported memcpy
    c1, o1, _ = sh(ff + ["--file", T, "memcpy"])
    c2, o2, _ = sh(ff + ["--file", T, "memcpy", "--no-imports"])
    n1, n2 = o1.count("0x"), o2.count("0x")
    uassert("findfunc --no-imports drops imports", n2 < n1 or (n1 == 0 and n2 == 0), "with=%d no-imports=%d" % (n1, n2))

    # xrefs
    expect("xrefs leaf callers", xr + ["--file", T, "leaf"], rc=0, has=[r"callers \(\d", r"main"])
    expect("xrefs never_called (no callers)", xr + ["--file", T, "never_called"], rc=0, has=[r"callers \(0\)"])
    expect("xrefs not found graceful", xr + ["--file", T, "nope_zzz"], rc=0, has=[r"target function not found"], nothas=[r"Traceback"])

    # strxref
    expect("strxref find string + ref", sx + ["--file", T, "MAGIC_HANDLER_STRING"], rc=0, has=[r"MAGIC_HANDLER_STRING_v1", r"handler"])
    expect("strxref --decompile", sx + ["--file", T, "MAGIC_HANDLER_STRING_v1", "--decompile"], rc=0, has=[r"// ===== handler"])
    expect("strxref no match", sx + ["--file", T, "zzz_no_such_string"], rc=0, has=[r"0 string match"])
    expect("strxref adversarial needle safe", sx + ["--file", T, 'a"b; import os'], rc=0, has=[r"string match"], nothas=[r"Traceback|Forbidden"])

    # scansec
    expect("scansec list", sc + ["--file", T], rc=0, has=[r"sections \(\d", r"\.text"])
    expect("scansec strings", sc + ["--file", T, "--section", ".rodata", "--strings"], rc=0, has=[r"MAGIC_HANDLER_STRING_v1"])
    expect("scansec ptrs graceful", sc + ["--file", T, "--section", ".data", "--ptrs"], rc=0, has=[r"value\(s\) in"], nothas=[r"Traceback"])
    expect("scansec bad section graceful", sc + ["--file", T, "--section", ".nope", "--strings"], rc=0, has=[r"no section"], nothas=[r"Traceback"])
    expect("scansec unmapped read graceful", sc + ["--file", T, "--read", "0xffffffff00", "--len", "16"], rc=0, has=[r"no data readable"], nothas=[r"Traceback"])
    # --read a real section (two-step)
    _, lo, _ = sh(sc + ["--file", T])
    m = re.search(r"\.rodata\s+0x([0-9a-fA-F]+)", lo)
    if m:
        expect("scansec read hexdump", sc + ["--file", T, "--read", "0x" + m.group(1), "--len", "32"], rc=0, has=[r"[0-9a-f]{12}  "])
    else:
        skip("scansec read hexdump", "no .rodata addr")


# ======================================================== INTEGRATION: bn-hunt
def test_hunt():
    print("\n## bn-hunt")
    cs = [PY, os.path.join(HUNT, "callsites.py")]
    fr = [PY, os.path.join(HUNT, "frame.py")]
    dr = [PY, os.path.join(HUNT, "disasm-range.py")]

    expect("callsites memcpy", cs + ["--file", T, "--sink", "memcpy"], rc=0, has=[r"call sites to memcpy", r"memcpy\("], nothas=[r"Traceback"])
    expect("callsites memcpy --arg 2", cs + ["--file", T, "--sink", "memcpy", "--arg", "2"], rc=0, has=[r"arg\[2\] ="])
    expect("callsites sprintf", cs + ["--file", T, "--sink", "sprintf"], rc=0, has=[r"call sites to sprintf"])
    expect("callsites --in scope", cs + ["--file", T, "--sink", "memcpy", "--in", "stack_copy"], rc=0, has=[r"within \*stack_copy\*", r"stack_copy"])
    expect("callsites unknown sink graceful", cs + ["--file", T, "--sink", "no_such_sink_zz"], rc=0, has=[r"not found as a function or symbol"], nothas=[r"Traceback"])
    expect("callsites injection reject", cs + ["--file", T, "--sink", "a'b"], rc=2, has=[r"\[reject\]"])

    expect("frame single (big_frame >= 4096)", fr + ["--file", T, "--func", "big_frame"], rc=0, has=[r"stack frame : \d", r"parameters \("])
    expect("frame recursion flag", fr + ["--file", T, "--func", "recurse_sum"], rc=0, has=[r"self-recursive: True"])
    expect("frame --top", fr + ["--file", T, "--top", "8"], rc=0, has=[r"by stack-frame size", r"big_frame"])
    expect("frame not found graceful", fr + ["--file", T, "--func", "nope_zz"], rc=0, has=[r"function not found"], nothas=[r"Traceback"])
    # big_frame should report a large frame
    _, fo, _ = sh(fr + ["--file", T, "--func", "big_frame"])
    m = re.search(r"stack frame : (\d+)", fo)
    uassert("frame big_frame large (>=2048)", bool(m) and int(m.group(1)) >= 2048, "got: " + (m.group(0) if m else fo[:120]))

    a = addr_of("leaf")
    if a:
        expect("disasm-range window", dr + ["--file", T, "--addr", a, "--count", "6"], rc=0, has=[r"0x[0-9a-f]{12}  \w"])
    else:
        skip("disasm-range window", "no leaf addr")
    expect("disasm-range unmapped graceful", dr + ["--file", T, "--addr", "0xffffffff00", "--count", "4"], rc=0, has=[r"no instruction"], nothas=[r"Traceback"])
    expect("disasm-range bad addr reject", dr + ["--file", T, "--addr", "0xZZ"], rc=2, has=[r"\[reject\]"])


# ============================================== INTEGRATION: bn_scan_* templates
def test_scanners():
    print("\n## binary-ninja: bn_scan_* templates")
    scanners = [("bn_scan_intof.py", r"INTOF candidate hits:", "alloc_table"),
                ("bn_scan_heapmismatch.py", r"hits:|candidate", None),
                ("bn_scan_dangcopy.py", r"hits:|candidate", None),
                ("bn_scan_doublefetch.py", r"hits:|candidate", None)]
    for fn, header, must in scanners:
        path = os.path.join(BNJA, fn)
        src = open(path).read().replace('"BNDBPATH"', json.dumps(T)).replace("update_analysis=False", "update_analysis=True")
        try:
            res = mcp_execute(src)
        except Exception as ex:
            bad("scanner " + fn, "MCP execute failed: %r" % ex); continue
        out = (res.get("output") or "") + "\n" + (res.get("error") or "")
        probs = []
        if not re.search(header, out):
            probs.append("missing header /%s/" % header)
        if res.get("error") or re.search(r"Traceback|Forbidden attribute", out):
            probs.append("error: " + (res.get("error") or "")[:120])
        if must and must not in out:
            probs.append("expected to flag %r" % must)
        bad("scanner " + fn, "; ".join(probs), out[:400]) if probs else ok("scanner " + fn)
    # graceful on a stripped binary (re-analyzed; should still produce a header)
    path = os.path.join(BNJA, "bn_scan_intof.py")
    src = open(path).read().replace('"BNDBPATH"', json.dumps(TSTRIP)).replace("update_analysis=False", "update_analysis=True")
    try:
        out = (mcp_execute(src).get("output") or "")
        uassert("scanner intof on stripped binary graceful", "candidate hits:" in out, out[:200])
    except Exception as ex:
        bad("scanner intof on stripped binary graceful", repr(ex))


# ============================================ BN-INDEPENDENT: cap_scan / symdiff
def test_capscan():
    print("\n## binary-ninja: cap_scan.py (capstone/pyelftools)")
    cap = [PY, os.path.join(BNJA, "cap_scan.py")]
    expect("cap_scan target.o finds candidates", cap + [TO], rc=0, has=[r"target\.o: \d+ candidates", r"stack_copy|alloc_table"], nothas=[r"Traceback"])
    expect("cap_scan --all", cap + [TO, "--all"], rc=0, has=[r"candidates"], nothas=[r"Traceback"])
    expect("cap_scan stripped (no symtab) graceful", cap + [TSTRIP], rc=0, has=[r"candidate|no .symtab|no symbol"], nothas=[r"Traceback \(most"])
    expect("cap_scan missing file graceful", cap + [MISSING], has=[r"cannot|not found|No such|error"], nothas=[r"Traceback \(most"])
    expect("cap_scan non-ELF graceful", cap + [NOTELF], has=[r"not.*ELF|cannot|magic|error"], nothas=[r"Traceback \(most"])
    expect("cap_scan empty file graceful", cap + [EMPTY], has=[r"not.*ELF|cannot|empty|magic|error"], nothas=[r"Traceback \(most"])
    expect("cap_scan via bin/ wrapper", [os.path.join(ROOT, "bin", "bn-cap-scan"), TO], rc=0, has=[r"candidates"], nothas=[r"Traceback"])


def test_symdiff():
    print("\n## binary-ninja: symdiff.py (capstone/pyelftools)")
    sd = [PY, os.path.join(BNJA, "symdiff.py")]
    expect("symdiff v1 vs v2 (stack_copy changed)", sd + [TO, TO2, "--list"], rc=0, has=[r"CHANGED=\d", r"stack_copy"], nothas=[r"Traceback"])
    expect("symdiff identical => 0 changed", sd + [TO, TO], rc=0, has=[r"CHANGED=0"], nothas=[r"Traceback"])
    expect("symdiff --filter", sd + [TO, TO2, "--filter", "stack"], rc=0, has=[r"stack_copy"])
    expect("symdiff missing file graceful", sd + [MISSING, TO], has=[r"cannot|not found|No such|error"], nothas=[r"Traceback \(most"])
    expect("symdiff non-ELF graceful", sd + [NOTELF, TO], has=[r"not.*ELF|cannot|magic|error"], nothas=[r"Traceback \(most"])
    expect("symdiff via bin/ wrapper", [os.path.join(ROOT, "bin", "bn-symdiff"), TO, TO2, "--list"], rc=0, has=[r"CHANGED=", r"stack_copy"], nothas=[r"Traceback"])


# =================================================== bulk-decompile (needs tab)
def test_bulkdecompile():
    print("\n## bulk-decompile")
    dd = [PY, os.path.join(ROOT, "skills", "bulk-decompile", "scripts", "dump_decompile.py")]
    # graceful no-match (headless, no GUI tab open for this fixture)
    expect("dump_decompile no-match graceful", dd + ["--bv-match", "zzz_no_tab_zzz", "--out", "/tmp/bd_zzz", "--all"],
           has=[r"no open GUI tab matched|NO-MATCH"], nothas=[r"Traceback \(most"])
    # success path: exercise rebind()+dump against whatever binary is ALREADY open in the GUI
    # (read-only; dumps a single leaf function's closure so it is fast regardless of binary size).
    probe = ("from binaryninjaui import UIContext\n"
             "bv=None\n"
             "for _c in UIContext.allContexts():\n"
             "    for _v,_n in _c.getAvailableBinaryViews():\n"
             "        bv=_v\n"
             "leaf=None\n"
             "if bv is not None:\n"
             "    for f in bv.functions:\n"
             "        if len(f.callees)==0 and f.name and not f.name.startswith('sub_'):\n"
             "            leaf=f.name; break\n"
             "    print((bv.file.filename or ''))\n"
             "    print((leaf or ''))\n"
             "else:\n"
             "    print(''); print('')\n")
    try:
        out0 = mcp_execute(probe).get("output") or ""
    except Exception as ex:
        return skip("dump_decompile success path", "MCP probe failed: %r" % ex)
    lines = [re.sub(r'^\[[0-9.]+s\]\s?', '', l) for l in out0.strip().splitlines() if l.strip()]
    fname = lines[-2] if len(lines) >= 2 else ""
    leaf = lines[-1] if lines else ""
    if not fname or not leaf:
        return skip("dump_decompile success path", "no binary with a named leaf function open in the GUI")
    import shutil, glob
    out = "/tmp/bd_succ_test"
    shutil.rmtree(out, ignore_errors=True)
    base = os.path.basename(fname)[:24]
    code, o, e = sh(dd + ["--bv-match", base, "--entry", leaf, "--out", out, "--asm"], timeout=180)
    idx = os.path.join(out, "INDEX.json")
    hl = glob.glob(os.path.join(out, "*.hlil.c"))
    uassert("dump_decompile success: rebind+dump wrote files",
            os.path.exists(idx) and len(hl) >= 1,
            "rc=%d match=%r entry=%r out:\n%s" % (code, base, leaf, (o or e)[:300]))
    shutil.rmtree(out, ignore_errors=True)


def test_packaging():
    print("\n## packaging / manifests / bin wrappers (static)")
    BIN = os.path.join(ROOT, "bin")
    # plugin.json
    try:
        pj = json.load(open(os.path.join(ROOT, ".claude-plugin", "plugin.json")))
        miss = [k for k in ("name", "version", "description", "author", "license", "homepage", "repository", "keywords") if k not in pj]
        uassert("plugin.json valid + complete", pj.get("name") == "disasm-codemode" and not miss, "missing: %s" % miss)
    except Exception as e:
        bad("plugin.json valid + complete", repr(e))
    # marketplace.json
    try:
        mj = json.load(open(os.path.join(ROOT, ".claude-plugin", "marketplace.json")))
        p0 = (mj.get("plugins") or [{}])[0]
        uassert("marketplace.json valid", bool(mj.get("name")) and p0.get("name") == "disasm-codemode" and bool(p0.get("source")))
    except Exception as e:
        bad("marketplace.json valid", repr(e))
    # agent frontmatter
    try:
        atxt = open(os.path.join(ROOT, "agents", "bn-triage.md")).read()
        fm = atxt.split("---")[1] if atxt.startswith("---") else ""
        uassert("agent bn-triage frontmatter", ("name:" in fm) and ("description:" in fm) and ("tools:" in fm))
    except Exception as e:
        bad("agent bn-triage frontmatter", repr(e))
    # authoritative manifest/structure validation (best-effort; skip if the CLI isn't present)
    import shutil as _sh
    if _sh.which("claude"):
        try:
            code, o, e = sh(["claude", "plugin", "validate", ROOT])
            uassert("claude plugin validate", code == 0 and re.search(r"passed|valid|✔", o + e, re.I), (o + e)[:200])
        except Exception as e:
            bad("claude plugin validate", repr(e))
    else:
        skip("claude plugin validate", "claude CLI not on PATH")
    # bin/ wrappers present, executable, shebang'd
    expected = ["bn-decompile", "bn-find", "bn-xrefs", "bn-strxref", "bn-scansec", "bn-callsites",
                "bn-frame", "bn-disasm-range", "bn-scan", "bn-cap-scan", "bn-symdiff",
                "bn-bulk-decompile", "bn-open", "bn-status", "bn-exec",
                "gh-decompile", "gh-find", "gh-xrefs", "gh-strxref", "gh-scansec", "gh-callsites",
                "gh-frame", "gh-disasm-range", "gh-scan", "gh-exec", "gh-status"]
    have = set(os.listdir(BIN)) if os.path.isdir(BIN) else set()
    uassert("bin/ has all wrappers", all(w in have for w in expected), "missing: %s" % [w for w in expected if w not in have])
    nonexec = [w for w in expected if w in have and not os.access(os.path.join(BIN, w), os.X_OK)]
    noshebang = [w for w in expected if w in have and not open(os.path.join(BIN, w)).readline().startswith("#!")]
    uassert("bin/ wrappers executable", not nonexec, "non-exec: %s" % nonexec)
    uassert("bin/ wrappers have shebang", not noshebang, "no shebang: %s" % noshebang)
    # bncm shared + in sync (symlinked, not duplicated)
    try:
        a = open(os.path.join(INSPECT, "bncm.py")).read()
        b = open(os.path.join(HUNT, "bncm.py")).read()
        uassert("bncm.py in sync across skills", a == b)
        uassert("bn-hunt bncm.py is a symlink", os.path.islink(os.path.join(HUNT, "bncm.py")))
    except Exception as e:
        bad("bncm.py shared", repr(e))
    # SKILL.md examples reference the bn-* commands; no stale bnopen.sh
    si = open(os.path.join(ROOT, "skills", "bn-inspect", "SKILL.md")).read()
    shh = open(os.path.join(ROOT, "skills", "bn-hunt", "SKILL.md")).read()
    uassert("bn-inspect SKILL uses bn-* commands", all(c in si for c in ("bn-decompile", "bn-find", "bn-xrefs", "bn-strxref", "bn-scansec")))
    uassert("bn-hunt SKILL uses bn-* commands", all(c in shh for c in ("bn-callsites", "bn-frame", "bn-disasm-range")))
    uassert("no stale bnopen.sh reference in bn-inspect SKILL", "bnopen.sh" not in si)
    # ghidra skill: SKILL.md, scripts, reference guide
    gs = open(os.path.join(ROOT, "skills", "ghidra", "SKILL.md")).read()
    uassert("ghidra SKILL uses gh-* commands", all(c in gs for c in (
        "gh-decompile", "gh-find", "gh-xrefs", "gh-strxref", "gh-scansec", "gh-callsites",
        "gh-frame", "gh-disasm-range", "gh-scan", "gh-exec", "gh-status")))
    uassert("ghidra skill has ghcm.py + all templates", all(os.path.exists(os.path.join(GHIDRA, s)) for s in (
        "ghcm.py", "decompile.py", "findfunc.py", "xrefs.py", "strxref.py", "scansec.py",
        "callsites.py", "frame.py", "disasm-range.py", "scan.py", "ghexec.py", "ghstatus.py")))
    uassert("ghidra reference guide present",
            os.path.exists(os.path.join(ROOT, "skills", "ghidra", "reference", "ghidra-codemode-guide.md")))
    # bn-scan argument validation (no MCP needed — wrapper checks args first)
    expect("bn-scan unknown-class reject", [os.path.join(BIN, "bn-scan"), "nope_class", TO], rc=2, has=[r"unknown class"])
    expect("bn-scan missing-target usage", [os.path.join(BIN, "bn-scan"), "intof"], rc=2, has=[r"usage"])


def test_bin_wrappers():
    print("\n## bin/ wrappers (functional, need MCP)")
    B = os.path.join(ROOT, "bin")
    expect("bin/bn-status", [os.path.join(B, "bn-status")], rc=0, has=[r"code-mode MCP"])
    expect("bin/bn-exec", [os.path.join(B, "bn-exec"), "print(6*7)"], rc=0, has=[r"\b42\b"])
    expect("bin/bn-find resolves+runs", [os.path.join(B, "bn-find"), "--file", T, "leaf"], rc=0, has=[r"leaf"])
    expect("bin/bn-decompile", [os.path.join(B, "bn-decompile"), "--file", T, "leaf"], rc=0, has=[r"leaf @ 0x"])
    expect("bin/bn-callsites", [os.path.join(B, "bn-callsites"), "--file", T, "--sink", "memcpy"], rc=0, has=[r"memcpy\("])
    expect("bin/bn-scan intof", [os.path.join(B, "bn-scan"), "intof", T], rc=0, has=[r"INTOF candidate"])
    expect("bin/ injection reject (through wrapper)", [os.path.join(B, "bn-find"), "--file", T, "a';bad"], rc=2, has=[r"\[reject\]"])
    expect("bin/bn-open opens a tab", [os.path.join(B, "bn-open"), T], rc=0, has=[r"opened tab for"])


def _make_evil(src, dst, sym, evil):
    """Copy `src` to `dst` and overwrite the .strtab name of symbol `sym` (same length) with
    `evil` bytes — to simulate a malicious binary whose symbol name carries terminal escapes."""
    import shutil
    shutil.copy(src, dst)
    from elftools.elf.elffile import ELFFile
    with open(dst, "r+b") as f:
        elf = ELFFile(f)
        st = elf.get_section_by_name(".symtab")
        strt = elf.get_section_by_name(".strtab")
        if not st or not strt:
            return False
        base = strt["sh_offset"]
        off = None
        for s in st.iter_symbols():
            if s.name == sym:
                off = s["st_name"]; break
        if off is None or len(evil) != len(sym):
            return False
        f.seek(base + off); f.write(evil)
        return True


def test_security():
    print("\n## security: tainted-output handling (hostile-binary threat model)")
    sys.path.insert(0, INSPECT); sys.path.insert(0, GHIDRA)
    import importlib, bncm, ghcm
    importlib.reload(bncm); importlib.reload(ghcm)
    # unit: scrub() neutralizes terminal-escape bytes, keeps \n/\t/printable, renders visibly
    nasty = "n\x1b[31m\x1b]0;t\x07\x9b1m\rX\x00\x7f"
    sc = bncm.scrub(nasty)
    uassert("scrub removes ESC/CSI/OSC/BEL/CR/NUL/DEL/C1", not any(c in sc for c in "\x1b\x9b\x07\r\x00\x7f"), repr(sc))
    uassert("scrub keeps newline/tab/printable", bncm.scrub("a\tb\nc d") == "a\tb\nc d")
    uassert("scrub renders bytes visibly", "\\x1b" in sc)
    # ghcm.scrub must behave identically (the two skills share the tainted-output design)
    gsc = ghcm.scrub(nasty)
    uassert("ghcm.scrub removes ESC/CSI/OSC/BEL/CR/NUL/DEL/C1", not any(c in gsc for c in "\x1b\x9b\x07\r\x00\x7f"), repr(gsc))
    uassert("ghcm.scrub keeps newline/tab + renders visibly", ghcm.scrub("a\tb\nc d") == "a\tb\nc d" and "\\x1b" in gsc)
    # unit: dump_decompile.safe() blocks path traversal + strips control bytes from names
    sys.path.insert(0, os.path.join(ROOT, "skills", "bulk-decompile", "scripts"))
    import dump_decompile as dd
    rsafe = dd.safe("../../etc/passwd")
    uassert("safe() blocks path traversal", "/" not in rsafe and "\\" not in rsafe and len(rsafe) <= 120)
    uassert("safe() strips control bytes from names", "\x1b" not in dd.safe("a\x1b[31mb"))
    # JSON-safety: scrubbing must NOT touch dump_decompile's function-list JSON (a raw 0x7f would
    # become an invalid \xNN escape); it must scrub the decompilation TEXT (dump_one) instead.
    import inspect, json as _json
    try:
        _json.loads(bncm.scrub('["a\x7fb"]')); _broke = False
    except ValueError:
        _broke = True
    uassert("scrub would corrupt JSON (justifies not scrubbing the func list)", _broke)
    uassert("dump_decompile.execute() leaves JSON intact (no scrub)", "_scrub(" not in inspect.getsource(dd.execute))
    uassert("dump_decompile.dump_one() scrubs decompilation text", "_scrub(" in inspect.getsource(dd.dump_one))
    # bn-scan refuses a target path that could break the sed/load string
    expect("bn-scan rejects evil target path", [os.path.join(ROOT, "bin", "bn-scan"), "intof", '/tmp/x";evil'],
           rc=2, has=[r"forbidden|outside"])
    # bn-open must NOT execute shell metacharacters in the path ($(...) / backticks -> host RCE)
    pwn = "/tmp/PWNED_BNOPEN_%d" % os.getpid()
    try:
        os.remove(pwn)
    except OSError:
        pass
    expect("bn-open rejects shell-injection path", [os.path.join(ROOT, "bin", "bn-open"), "/tmp/x$(touch %s)" % pwn],
           rc=2, has=[r"forbidden|outside|refus"])
    uassert("bn-open did not execute the injected command", not os.path.exists(pwn))
    try:
        os.remove(pwn)
    except OSError:
        pass
    # integration: an evil symbol NAME must not reach the terminal raw
    try:
        import capstone, elftools  # noqa
        caps = True
    except Exception:
        caps = False
    if not caps:
        return skip("evil-binary scrub integration", "needs pyelftools")
    evo = os.path.join(FX, "target_evil.o")
    if _make_evil(TO, evo, "heap_copy", b"\x1b[31mPWN!"):   # heap_copy is a cap_scan candidate
        expect("cap_scan scrubs an evil symbol name", [PY, os.path.join(BNJA, "cap_scan.py"), evo],
               rc=0, has=[r"candidates", r"\\x1b"], nothas=["\x1b", "\x9b"])
    else:
        skip("cap_scan evil-name scrub", "could not patch .strtab")
    if mcp_up():
        ev = os.path.join(FX, "target_evil")
        if _make_evil(T, ev, "handler", b"\x1b[31m!!"):
            expect("findfunc scrubs an evil symbol name", [PY, os.path.join(INSPECT, "findfunc.py"), "--file", ev, "--regex", "."],
                   rc=0, has=[r"\\x1b"], nothas=["\x1b", "\x9b", "\x07"])
        else:
            skip("findfunc evil-name scrub", "could not patch .strtab")
    else:
        skip("findfunc evil-name scrub", "MCP down")
    # ghidra: code-mode output must be scrubbed before printing. A patched symbol name is unreliable
    # on Ghidra (it prefers the clean DWARF name), so inject exact attacker-chosen control bytes
    # through the SAME captured-stdout path that gh-find/gh-decompile output flows through.
    if gh_up():
        expect("gh code-mode stdout is scrubbed (tainted-output path)",
               [PY, os.path.join(GHIDRA, "ghexec.py"), "--file", T, "--code",
                r'print("X\x1b[31m\x9b1m\x07\x00Y")'],
               rc=0, has=[r"\\x1b", r"\\x9b"], nothas=["\x1b", "\x9b", "\x07"])
        # the eval RESULT value (eval-mode expression return) must be scrubbed too, not just stdout
        expect("gh-exec scrubs the eval result value",
               [PY, os.path.join(GHIDRA, "ghexec.py"), "--file", T, "--code", r'"R\x1b[7mE\x07"'],
               rc=0, has=[r"=>.*\\x1b"], nothas=["\x1b", "\x07"])
    else:
        skip("gh tainted-output scrub", "ghidra server down")


# =============================================================== GHIDRA helpers
def gh_up():
    """True iff the ghidra-headless-mcp TCP server is reachable + healthy (else integration skips).
    ghcm.Client() exits(3) on connection failure, so catch SystemExit to avoid killing the run."""
    sys.path.insert(0, GHIDRA)
    try:
        import ghcm
    except Exception:
        return False
    try:
        c = ghcm.Client()
    except (SystemExit, Exception):
        return False
    try:
        p, _ = c.call_tool("health.ping", {}, timeout=15)
        return isinstance(p, dict) and p.get("status") == "ok"
    except Exception:
        return False
    finally:
        try:
            c.close()
        except Exception:
            pass


def gh_addr_of(fn):
    code, o, e = sh([PY, os.path.join(GHIDRA, "findfunc.py"), "--file", T, fn])
    m = re.search(r"0x([0-9a-fA-F]+)\s+" + re.escape(fn) + r"\b", o)
    return ("0x" + m.group(1)) if m else None


# =========================================================== UNIT: ghcm guards
def unit_ghcm():
    print("\n## unit: ghcm.py injection guards (no Ghidra server)")
    sys.path.insert(0, GHIDRA)
    import importlib
    import ghcm
    importlib.reload(ghcm)

    nasties = ['a"b', "a'b", "a\\b", "a\nb", "a\tb", "résumé", '"; import os; os.system("id"); "', "`id`", "$(id)", "x" * 300]
    for s in nasties:
        try:
            lit = ghcm.pylit(s)
            uassert("ghcm.pylit round-trips %r" % s[:14], (eval(lit) == s) and lit[:1] in ("\"", "'"), "lit=" + lit[:80])
        except SystemExit:
            bad("ghcm.pylit round-trips %r" % s[:14], "pylit rejected a legal string")
    uassert("ghcm.pylit int/bool/None", ghcm.pylit(7) == "7" and ghcm.pylit(True) == "True" and ghcm.pylit(None) == "None")
    uassert("ghcm.pylit list round-trips", eval(ghcm.pylit([1, 'a"b', True, None])) == [1, 'a"b', True, None])

    def rejects(fn, *a):
        try:
            fn(*a); return False
        except SystemExit as ex:
            return ex.code == 2

    uassert("ghcm.vsym accepts real symbol", ghcm.vsym("VmDir_a.b::c$x") == "VmDir_a.b::c$x")
    for b in ["a'b", 'a"b', "a\\b", "a`b", "a;b", "a\nb", "", "x" * 600]:
        uassert("ghcm.vsym rejects %r" % b[:8], rejects(ghcm.vsym, b))
    uassert("ghcm.vaddr hex/dec", ghcm.vaddr("0x1000") == 4096 and ghcm.vaddr("4096") == 4096)
    for b in ["0xZ", "12x", "", "0x" + "f" * 20, "-1", "0x"]:
        uassert("ghcm.vaddr rejects %r" % b[:10], rejects(ghcm.vaddr, b))
    uassert("ghcm.vpath accepts", ghcm.vpath("/tmp/a_b.bin") == "/tmp/a_b.bin")
    for b in ["/tmp/a;rm", "/tmp/$x", "/tmp/a*", "a'b", "/tmp/a`b", "/tmp/a\nb"]:
        uassert("ghcm.vpath rejects %r" % b[:10], rejects(ghcm.vpath, b))
    uassert("ghcm.vsection accepts/rejects", ghcm.vsection(".rodata") == ".rodata" and rejects(ghcm.vsection, ".text;x"))
    uassert("ghcm.vregex accepts/rejects", ghcm.vregex("a.*b|c") == "a.*b|c" and rejects(ghcm.vregex, "a["))
    uassert("ghcm.vneedle allows quotes / rejects control",
            ghcm.vneedle('he said "hi"') == 'he said "hi"' and rejects(ghcm.vneedle, "a\x01b"))
    uassert("ghcm.vprogmatch accepts/rejects", ghcm.vprogmatch("target") == "target" and rejects(ghcm.vprogmatch, "a;b"))

    # build_eval_code(): the un-char-restricted needle must embed as an inert escaped literal
    payload = '"; import os; os.system("id"); _needle="'
    code = ghcm.build_eval_code("print('done')", _needle=payload)
    xlines = [l for l in code.splitlines() if l.startswith("_needle = ")]
    embedded_ok = bool(xlines) and eval(xlines[0][len("_needle = "):]) == payload
    no_inj = "os.system" not in "\n".join(l for l in code.splitlines() if not l.startswith("_needle = "))
    uassert("ghcm.build_eval_code embeds injection as an inert literal", embedded_ok and no_inj,
            "line=" + (xlines[0] if xlines else "<none>"))
    uassert("ghcm.build_eval_code wraps body (stdout survives early exit)",
            "try:" in code and "except SystemExit" in code)


# ==================================================== INTEGRATION: ghidra inspect
def test_ghidra_inspect():
    print("\n## ghidra: inspect (gh-decompile / find / xrefs / strxref / scansec)")
    dec = [PY, os.path.join(GHIDRA, "decompile.py")]
    ff = [PY, os.path.join(GHIDRA, "findfunc.py")]
    xr = [PY, os.path.join(GHIDRA, "xrefs.py")]
    sx = [PY, os.path.join(GHIDRA, "strxref.py")]
    sc = [PY, os.path.join(GHIDRA, "scansec.py")]
    FA = ["--file", T]

    # decompile
    expect("gh decompile leaf", dec + FA + ["--name", "leaf"], rc=0, has=[r"leaf", r"return 0x2a|return 42"], nothas=[r"Traceback", r"body error"])
    expect("gh decompile heap_copy shows copy", dec + FA + ["--name", "heap_copy"], rc=0, has=[r"memcpy\("], nothas=[r"Traceback"])
    expect("gh decompile missing-name graceful", dec + FA + ["--name", "no_such_fn_zzz"], rc=0, has=[r"no function named"], nothas=[r"Traceback"])
    expect("gh decompile bad-addr graceful", dec + FA + ["--addr", "0xffffff00"], rc=0, has=[r"no function at"], nothas=[r"Traceback"])
    expect("gh decompile injection reject", dec + FA + ["--name", "a'b"], rc=2, has=[r"\[reject\]"])
    expect("gh decompile missing file reject", dec + ["--file", MISSING, "--name", "leaf"], rc=2, has=[r"does not exist"])

    # findfunc
    expect("gh findfunc substring", ff + FA + ["leaf"], rc=0, has=[r"match 'leaf'", r"leaf"])
    expect("gh findfunc regex", ff + FA + ["--regex", r"^(big_frame|recurse_sum)$"], rc=0, has=[r"big_frame", r"recurse_sum"])
    expect("gh findfunc no match", ff + FA + ["zzz_nomatch_zzz"], rc=0, has=[r"0 function\(s\) match"])
    expect("gh findfunc reject", ff + FA + ["a;b"], rc=2, has=[r"\[reject\]"])
    a = gh_addr_of("leaf")
    if a:
        expect("gh findfunc --addr resolves", ff + FA + ["--addr", a], rc=0, has=[r"leaf"])
    else:
        skip("gh findfunc --addr resolves", "could not resolve leaf addr")
    c1, o1, _ = sh(ff + FA + ["memcpy"])
    c2, o2, _ = sh(ff + FA + ["memcpy", "--no-imports"])
    uassert("gh findfunc --no-imports drops thunks", o2.count("0x") < o1.count("0x") or o1.count("0x") == 0,
            "with=%d no-imports=%d" % (o1.count("0x"), o2.count("0x")))

    # xrefs
    expect("gh xrefs leaf callers", xr + FA + ["leaf"], rc=0, has=[r"callers \(\d", r"main"])
    expect("gh xrefs never_called (no callers)", xr + FA + ["never_called"], rc=0, has=[r"callers \(0\)"])
    expect("gh xrefs not found graceful", xr + FA + ["nope_zzz"], rc=0, has=[r"target function not found"], nothas=[r"Traceback"])

    # strxref (incl. the global-pointer hop -> handler)
    expect("gh strxref find string + ref", sx + FA + ["MAGIC_HANDLER_STRING"], rc=0, has=[r"MAGIC_HANDLER_STRING_v1", r"handler"])
    expect("gh strxref --decompile", sx + FA + ["MAGIC_HANDLER_STRING_v1", "--decompile"], rc=0, has=[r"// ===== handler"])
    expect("gh strxref no match", sx + FA + ["zzz_no_such_string"], rc=0, has=[r"0 string match"])
    expect("gh strxref adversarial needle safe", sx + FA + ['a"b; import os'], rc=0, has=[r"string match"], nothas=[r"Traceback"])

    # scansec
    expect("gh scansec list", sc + FA, rc=0, has=[r"blocks / sections \(\d", r"\.text"])
    expect("gh scansec strings", sc + FA + ["--section", ".rodata", "--strings"], rc=0, has=[r"MAGIC_HANDLER_STRING_v1"])
    expect("gh scansec ptrs graceful", sc + FA + ["--section", ".data", "--ptrs"], rc=0, has=[r"value\(s\) in"], nothas=[r"Traceback"])
    expect("gh scansec bad section graceful", sc + FA + ["--section", ".nope", "--strings"], rc=0, has=[r"no section"], nothas=[r"Traceback"])
    expect("gh scansec unmapped read graceful", sc + FA + ["--read", "0xffffffff00", "--len", "16"], rc=0, has=[r"no data readable"], nothas=[r"Traceback"])
    _, lo, _ = sh(sc + FA)
    m = re.search(r"\.rodata\s+0x([0-9a-fA-F]+)", lo)
    if m:
        expect("gh scansec read hexdump", sc + FA + ["--read", "0x" + m.group(1), "--len", "32"], rc=0, has=[r"[0-9a-f]{12}  "])
    else:
        skip("gh scansec read hexdump", "no .rodata addr")


# ====================================================== INTEGRATION: ghidra hunt
def test_ghidra_hunt():
    print("\n## ghidra: hunt (gh-callsites / frame / disasm-range / scan)")
    cs = [PY, os.path.join(GHIDRA, "callsites.py")]
    fr = [PY, os.path.join(GHIDRA, "frame.py")]
    dr = [PY, os.path.join(GHIDRA, "disasm-range.py")]
    scn = [PY, os.path.join(GHIDRA, "scan.py")]
    FA = ["--file", T]

    expect("gh callsites memcpy", cs + FA + ["--sink", "memcpy"], rc=0, has=[r"call sites to memcpy", r"memcpy\("], nothas=[r"Traceback"])
    expect("gh callsites --in scope", cs + FA + ["--sink", "memcpy", "--in", "heap_copy"], rc=0, has=[r"within \*heap_copy\*", r"heap_copy"])
    expect("gh callsites unknown sink graceful", cs + FA + ["--sink", "no_such_sink_zz"], rc=0, has=[r"not found as a function or symbol"], nothas=[r"Traceback"])
    expect("gh callsites injection reject", cs + FA + ["--sink", "a'b"], rc=2, has=[r"\[reject\]"])

    expect("gh frame single (big_frame)", fr + FA + ["--func", "big_frame"], rc=0, has=[r"stack frame : \d", r"parameters \("])
    expect("gh frame recursion flag", fr + FA + ["--func", "recurse_sum"], rc=0, has=[r"self-recursive: True"])
    expect("gh frame --top", fr + FA + ["--top", "8"], rc=0, has=[r"by stack-frame size", r"big_frame"])
    expect("gh frame not found graceful", fr + FA + ["--func", "nope_zz"], rc=0, has=[r"function not found"], nothas=[r"Traceback"])
    _, fo, _ = sh(fr + FA + ["--func", "big_frame"])
    m = re.search(r"stack frame : (\d+)", fo)
    uassert("gh frame big_frame large (>=2048)", bool(m) and int(m.group(1)) >= 2048, "got: " + (m.group(0) if m else fo[:120]))

    a = gh_addr_of("heap_copy")
    if a:
        expect("gh disasm-range window", dr + FA + ["--addr", a, "--count", "6"], rc=0, has=[r"0x[0-9a-f]{12}  \w"])
    else:
        skip("gh disasm-range window", "no heap_copy addr")
    expect("gh disasm-range unmapped graceful", dr + FA + ["--addr", "0xffffffff00", "--count", "4"], rc=0, has=[r"no instruction"], nothas=[r"Traceback"])
    expect("gh disasm-range bad addr reject", dr + FA + ["--addr", "0xZZ"], rc=2, has=[r"\[reject\]"])

    # gh-scan bug-class finder
    expect("gh scan all flags fixture bugs", scn + FA + ["--class", "all"], rc=0,
           has=[r"\[intof\] alloc_table", r"\[fmt\] log_msg", r"copylen"], nothas=[r"Traceback"])
    expect("gh scan intof only", scn + FA + ["--class", "intof"], rc=0, has=[r"\[intof\] alloc_table"], nothas=[r"\[fmt\]"])
    expect("gh scan bad class reject", scn + FA + ["--class", "bogus"], rc=2, has=[r"\[reject\]"])
    expect("gh scan --regex filter", scn + FA + ["--class", "fmt", "--regex", "^log_"], rc=0, has=[r"log_msg", r"across 1 function"])


# ============================================== INTEGRATION: ghidra bin wrappers
def test_ghidra_bin_wrappers():
    print("\n## ghidra: bin/ wrappers (functional, need server)")
    B = os.path.join(ROOT, "bin")
    expect("bin/gh-status", [os.path.join(B, "gh-status")], rc=0, has=[r"ghidra-headless-mcp @"])
    expect("bin/gh-exec", [os.path.join(B, "gh-exec"), "--file", T, "--code", "print(6*7)"], rc=0, has=[r"\b42\b"])
    expect("bin/gh-find resolves+runs", [os.path.join(B, "gh-find"), "--file", T, "leaf"], rc=0, has=[r"leaf"])
    expect("bin/gh-decompile", [os.path.join(B, "gh-decompile"), "--file", T, "--name", "leaf"], rc=0, has=[r"leaf"])
    expect("bin/gh-callsites", [os.path.join(B, "gh-callsites"), "--file", T, "--sink", "memcpy"], rc=0, has=[r"memcpy\("])
    expect("bin/gh-scan", [os.path.join(B, "gh-scan"), "--file", T, "--class", "intof"], rc=0, has=[r"\[intof\]"])
    expect("bin/ injection reject (through wrapper)", [os.path.join(B, "gh-find"), "--file", T, "a';bad"], rc=2, has=[r"\[reject\]"])


def main():
    print("=== disasm-codemode test suite ===")
    print("[*] building fixtures ...")
    rc, o, e = sh(["bash", os.path.join(FX, "build.sh")])
    if rc != 0:
        print("[FATAL] fixture build failed:\n" + o + e); sys.exit(3)
    print(o.strip())

    unit_bncm()                 # always (no BN)
    unit_ghcm()                 # always (no Ghidra server)
    test_packaging()            # always (manifests, bin wrappers, structure, bn-scan arg-validation)
    test_security()             # tainted-output handling (unit always; evil-binary integration needs caps/MCP)
    have_caps = True
    try:
        import capstone, elftools  # noqa
    except Exception:
        have_caps = False
    if have_caps:
        test_capscan(); test_symdiff()
    else:
        skip("cap_scan/symdiff suite", "capstone/pyelftools not in this python")

    if mcp_up():
        test_inspect(); test_hunt(); test_scanners(); test_bin_wrappers(); test_bulkdecompile()
    else:
        skip("ALL Binary Ninja integration tests", "MCP not reachable at " + MCP_URL)

    if gh_up():
        test_ghidra_inspect(); test_ghidra_hunt(); test_ghidra_bin_wrappers()
    else:
        skip("ALL Ghidra integration tests", "ghidra-headless-mcp not reachable at %s:%d" % (GH_HOST, GH_PORT))

    print("\n=== summary: %d passed, %d failed, %d skipped ===" % (P, F, S))
    if FAILS:
        print("FAILED: " + ", ".join(FAILS))
    sys.exit(1 if F else 0)


if __name__ == "__main__":
    main()
