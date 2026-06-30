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
SYMBOLICATE = os.path.join(ROOT, "skills", "symbolicate", "scripts")
SBOMKB = os.path.join(ROOT, "skills", "sbom-kb")
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
                "bn-bulk-decompile", "bn-open", "bn-status", "bn-exec", "bn-audit-sync",
                "bn-re-apply", "bn-re-vars",
                "bn-audit-dump-table-bn", "bn-audit-extract-bn", "bn-audit-graph-report",
                "bn-audit-make-batches", "bn-audit-make-graph-batches", "bn-audit-make-phase2",
                "bn-audit-prep-batch-bn", "bn-audit-prep-deciders-bn",
                "bn-audit-prep-functions-bn", "bn-audit-prep-phase2-bn",
                "bn-audit-validate-reviews",
                "bn-sym-extract", "bn-sym-determ", "bn-sym-prep", "bn-sym-makewf",
                "bn-sym-ingest", "bn-sym-combine", "bn-sym-prep-locality",
                "bn-sym-prep-second", "bn-sym-review-protos", "bn-sym-slice-protos",
                "bn-sym-split",
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
    # symbolicate skill: core scripts + newer fanout/prototype helpers
    sym_skill = os.path.join(ROOT, "skills", "symbolicate", "SKILL.md")
    sym_files = ["extract.py", "determ.py", "prep_batch.py", "make_wf.py", "ingest.py",
                 "split_batch.py", "combine_outputs.py", "prep_locality_pass.py",
                 "prep_second_pass.py", "review_protos.py", "slice_protos.py"]
    uassert("symbolicate SKILL present", os.path.exists(sym_skill) and "name: symbolicate" in open(sym_skill).read())
    uassert("symbolicate scripts present", all(os.path.exists(os.path.join(SYMBOLICATE, f)) for f in sym_files),
            "missing: %s" % [f for f in sym_files if not os.path.exists(os.path.join(SYMBOLICATE, f))])
    uassert("symbolicate profile present", os.path.exists(os.path.join(ROOT, "skills", "symbolicate", "profiles", "vmware.json")))
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
    # binary-audit skill: SKILL.md + the ledger->bndb sync script + ingest scripts (renamed from kernel-audit)
    BA = os.path.join(ROOT, "skills", "binary-audit")
    uassert("binary-audit skill present (renamed from kernel-audit)",
            os.path.exists(os.path.join(BA, "SKILL.md")) and os.path.isdir(os.path.join(BA, "scripts")))
    uassert("binary-audit has sync_to_bv + ingest scripts", all(os.path.exists(os.path.join(BA, "scripts", s)) for s in (
        "sync_to_bv.py", "ingest.py", "ingest_deciders.py", "ingest_guestentry.py")))
    uassert("no stale kernel-audit skill dir", not os.path.isdir(os.path.join(ROOT, "skills", "kernel-audit")))
    # binary-ninja RE-sync: the sidecar apply + var-inspect scripts
    uassert("binary-ninja has re_sync + re_vars scripts", all(os.path.exists(os.path.join(BNJA, s)) for s in (
        "re_sync.py", "re_vars.py")))
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


# ============================================ binary-audit: ledger -> bndb sync
BA_SCRIPTS = os.path.join(ROOT, "skills", "binary-audit", "scripts")


def _mk_ledger(path, func="leaf", status="confirmed-violable"):
    """Build a minimal binary-audit ledger with one reviewed function carrying a bug, a caller-owed +
    a self-checked precondition, and a Stage-3 audit. Long desc/guest_path with unique tail tokens so a
    truncation regression is caught. Returns (long_desc, long_path)."""
    import sqlite3
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE review(addr INTEGER PRIMARY KEY, name TEXT, reviewed_at TEXT, reviewer TEXT, verdict TEXT, notes TEXT);"
        "CREATE TABLE precondition(id INTEGER PRIMARY KEY, func_addr INTEGER, func_name TEXT, text TEXT, kind TEXT, klass TEXT, sink TEXT, status TEXT, attack_note TEXT);"
        "CREATE TABLE bug(id INTEGER PRIMARY KEY, func_addr INTEGER, func_name TEXT, desc TEXT, location TEXT, severity TEXT, confidence TEXT, why TEXT, status TEXT, bug_class TEXT);"
        "CREATE TABLE audit(id INTEGER PRIMARY KEY, func_name TEXT, verdict TEXT, evidence TEXT, guest_path TEXT, residual TEXT, next TEXT, confidence TEXT, guard TEXT);")
    longdesc = ("server-controlled stripe index used unclamped as an array subscript; " * 30) + "DESC_TAIL_ZZZ"
    longpath = ("rogue MDS -> GETDEVICEINFO -> XDR decode -> verbatim copy -> dispatch; " * 20) + "PATH_TAIL_ZZZ"
    db.execute("INSERT INTO review VALUES(?,?,?,?,?,?)", (0x1000, func, "t", "wf", "needs-caller-analysis", "n"))
    db.execute("INSERT INTO bug(func_name,desc,bug_class,status) VALUES(?,?,?,?)", (func, longdesc, "oob", status))
    db.execute("INSERT INTO precondition(func_name,text,kind,klass) VALUES(?,?,?,?)", (func, "CALLER_OWED_MARKER stripe index < count", "len-bound", "caller"))
    db.execute("INSERT INTO precondition(func_name,text,kind,klass) VALUES(?,?,?,?)", (func, "SELF_CHECKED_MARKER internal boilerplate", "nonnull", "self"))
    db.execute("INSERT INTO audit(func_name,verdict,guest_path) VALUES(?,?,?)", (func, status, longpath))
    db.commit(); db.close()
    return longdesc, longpath


def unit_binary_audit():
    """No MCP: the comment-builder (build_items) + the ingest cap. The actual BN write is the live test below."""
    print("\n## binary-audit: ledger -> comment build (no MCP)")
    import tempfile, shutil, sqlite3
    sys.path.insert(0, BA_SCRIPTS)
    try:
        import sync_to_bv  # imports bncm (stdlib only — no MCP call at import)
    except Exception as e:
        return bad("import sync_to_bv", repr(e))
    td = tempfile.mkdtemp(prefix="ba_unit_")
    try:
        led = os.path.join(td, "kreview.db")
        longdesc, longpath = _mk_ledger(led)
        items = sync_to_bv.build_items(led, False, 0)
        uassert("build_items: one function", len(items) == 1, "got %d" % len(items))
        c = items[0]["comment"] if items else ""
        uassert("comment wrapped in [binaudit] markers", c.startswith("[binaudit]") and c.rstrip().endswith("[/binaudit]"))
        uassert("full bug desc, no truncation", "DESC_TAIL_ZZZ" in c and "…" not in c, c[-80:])
        uassert("full guest_path, no truncation", "PATH_TAIL_ZZZ" in c)
        uassert("caller-owed precondition included", "CALLER_OWED_MARKER" in c)
        uassert("self-checked precondition excluded", "SELF_CHECKED_MARKER" not in c)
        uassert("tag mirrors confirmed-violable", items and items[0]["tag"] == "violable", "tag=%r" % (items[0]["tag"] if items else None))
        uassert("build_items deterministic / regenerable", sync_to_bv.build_items(led, False, 0) == items)
    except Exception as e:
        bad("build_items run", repr(e))
    finally:
        shutil.rmtree(td, ignore_errors=True)

    # ingest cap: a long review summary + bug desc must survive well past the old 600-char clip
    print("## binary-audit: ingest cap (no MCP)")
    td2 = tempfile.mkdtemp(prefix="ba_ing_")
    try:
        cx = sqlite3.connect(os.path.join(td2, "kreview.db"))
        cx.execute("CREATE TABLE func(addr INTEGER, name TEXT)"); cx.commit(); cx.close()  # ingest.py looks it up
        wf = [{"function": "leaf", "verdict": "reviewed", "summary": "S" * 1500,
               "preconditions": [{"text": "P" * 40, "kind": "len-bound", "klass": "caller"}],
               "suspected_bugs": [{"desc": "B" * 2000, "bug_class": "oob"}]}]
        wfp = os.path.join(td2, "wf.json"); open(wfp, "w").write(json.dumps(wf))
        env = dict(os.environ, KAUDIT_ROOT=td2)
        p = subprocess.run([PY, os.path.join(BA_SCRIPTS, "ingest.py"), wfp], capture_output=True, text=True, env=env, timeout=60)
        cx = sqlite3.connect(os.path.join(td2, "kreview.db"))
        rev = cx.execute("SELECT notes FROM review WHERE name='leaf'").fetchone()
        bg = cx.execute("SELECT desc FROM bug WHERE func_name='leaf'").fetchone()
        cx.close()
        uassert("ingest runs clean", p.returncode == 0 and "Traceback" not in (p.stdout + p.stderr), (p.stdout + p.stderr)[:300])
        uassert("ingest keeps 1500-char summary (past old 600 cap)", rev and rev[0] and len(rev[0]) == 1500, "len=%r" % (len(rev[0]) if rev and rev[0] else None))
        uassert("ingest keeps bug desc uncapped", bg and bg[0] and len(bg[0]) == 2000)
    except Exception as e:
        bad("ingest cap run", repr(e))
    finally:
        shutil.rmtree(td2, ignore_errors=True)

    # phase2 target resolution: exact names must win over shorter substring names
    print("## binary-audit: phase2 exact target matching (no MCP)")
    td3 = tempfile.mkdtemp(prefix="ba_p2_")
    try:
        dbp = os.path.join(td3, "kreview.db")
        cx = sqlite3.connect(dbp)
        cx.executescript(
            "CREATE TABLE func(addr INTEGER, name TEXT, score REAL);"
            "CREATE TABLE bug(func_name TEXT, status TEXT);"
            "CREATE TABLE precondition(func_name TEXT, klass TEXT, status TEXT);")
        cx.execute("INSERT INTO func VALUES(?,?,?)", (0x1000, "Snapshot_Load", 1.0))
        cx.execute("INSERT INTO func VALUES(?,?,?)", (0x2000, "Snapshot_LoadConfig_2", 2.0))
        cx.execute("INSERT INTO precondition VALUES(?,?,?)", ("Snapshot_Load", "caller", "open"))
        cx.execute("INSERT INTO precondition VALUES(?,?,?)", ("Snapshot_LoadConfig_2", "caller", "open"))
        cx.commit(); cx.close()
        outp = os.path.join(td3, "phase2.json")
        open(outp, "w").write(json.dumps({"target": "Snapshot_LoadConfig_2", "verdict": "partial", "confidence": "med"}))
        env = dict(os.environ, KAUDIT_ROOT=td3)
        p = subprocess.run([PY, os.path.join(BA_SCRIPTS, "ingest_phase2.py"), outp],
                           capture_output=True, text=True, env=env, timeout=60)
        cx = sqlite3.connect(dbp)
        rows = dict(cx.execute("SELECT func_name,status FROM precondition"))
        audit = cx.execute("SELECT func_name,verdict FROM audit").fetchone()
        cx.close()
        uassert("phase2 ingest exact-match runs", p.returncode == 0 and "Traceback" not in (p.stdout + p.stderr), (p.stdout + p.stderr)[:300])
        uassert("phase2 exact target matched long name", audit == ("Snapshot_LoadConfig_2", "partial"), "audit=%r" % (audit,))
        uassert("phase2 shorter substring left open", rows.get("Snapshot_Load") == "open", "rows=%r" % rows)
        uassert("phase2 exact precondition updated", rows.get("Snapshot_LoadConfig_2") == "partial", "rows=%r" % rows)
    except Exception as e:
        bad("phase2 exact matching run", repr(e))
    finally:
        shutil.rmtree(td3, ignore_errors=True)

    # ingest.py disclosure lens: migrate + store leak_back/disclosure_source/reachability/guarded_by
    # + init-complete precondition kind; a bug WITHOUT the new fields must still ingest (backward-compat).
    print("## binary-audit: ingest disclosure columns (no MCP)")
    td4 = tempfile.mkdtemp(prefix="ba_disc_")
    try:
        cx = sqlite3.connect(os.path.join(td4, "kreview.db"))
        cx.execute("CREATE TABLE func(addr INTEGER, name TEXT)")
        cx.execute("INSERT INTO func VALUES(?,?)", (0x10, "leaker"))
        cx.execute("INSERT INTO func VALUES(?,?)", (0x20, "plain"))
        cx.commit(); cx.close()
        wf = [{"function": "leaker", "verdict": "bug",
               "summary": "writes a partially-initialized struct to the guest CQ ring",
               "preconditions": [{"text": "every CQE byte initialized", "kind": "init-complete", "klass": "caller"}],
               "suspected_bugs": [{"desc": "uninit CQE padding leaked to guest", "bug_class": "uninit-disclosure",
                                   "leak_back": "reaches-attacker", "disclosure_source": "stack",
                                   "reachability": "guest", "guarded_by": "", "impact": "guest-readable-leak"}]},
              {"function": "plain", "verdict": "bug",   # new class (null-deref) + impact; no disclosure fields
               "suspected_bugs": [{"desc": "unchecked alloc deref", "bug_class": "null-deref",
                                   "impact": "host-psod"}]}]
        wfp = os.path.join(td4, "wf.json"); open(wfp, "w").write(json.dumps(wf))
        env = dict(os.environ, KAUDIT_ROOT=td4)
        p = subprocess.run([PY, os.path.join(BA_SCRIPTS, "ingest.py"), wfp], capture_output=True, text=True, env=env, timeout=60)
        cx = sqlite3.connect(os.path.join(td4, "kreview.db"))
        cols = [r[1] for r in cx.execute("PRAGMA table_info(bug)")]
        leak = cx.execute("SELECT leak_back,disclosure_source,reachability,impact FROM bug WHERE func_name='leaker'").fetchone()
        pk = cx.execute("SELECT kind FROM precondition WHERE func_name='leaker'").fetchone()
        plain = cx.execute("SELECT bug_class,impact,leak_back FROM bug WHERE func_name='plain'").fetchone()
        cx.close()
        uassert("ingest runs clean (disclosure)", p.returncode == 0 and "Traceback" not in (p.stdout + p.stderr), (p.stdout + p.stderr)[:300])
        uassert("bug migrated with disclosure+impact columns", all(c in cols for c in ("leak_back", "disclosure_source", "reachability", "guarded_by", "impact")), "cols=%r" % cols)
        uassert("disclosure + impact fields stored", leak == ("reaches-attacker", "stack", "guest", "guest-readable-leak"), "leak=%r" % (leak,))
        uassert("init-complete precondition kind stored", pk == ("init-complete",), "pk=%r" % (pk,))
        uassert("new bug_class (null-deref) + impact stored; missing disclosure fields OK", plain == ("null-deref", "host-psod", None), "plain=%r" % (plain,))
    except Exception as e:
        bad("ingest disclosure run", repr(e))
    finally:
        shutil.rmtree(td4, ignore_errors=True)

    # phase2 audit-append-history: re-ingest APPENDS (audit_pass 1,2) + func.n_audited tracks;
    # a confirmed-violable verdict for a function with no prior bug auto-creates one (class-inferred).
    print("## binary-audit: phase2 append-history + auto-bug (no MCP)")
    td5 = tempfile.mkdtemp(prefix="ba_p2h_")
    try:
        dbp = os.path.join(td5, "kreview.db")
        cx = sqlite3.connect(dbp)
        cx.executescript(
            "CREATE TABLE func(addr INTEGER, name TEXT, score REAL);"
            "CREATE TABLE bug(id INTEGER PRIMARY KEY, func_addr INTEGER, func_name TEXT, desc TEXT, location TEXT, severity TEXT, confidence TEXT, why TEXT, status TEXT, bug_class TEXT);"
            "CREATE TABLE precondition(func_name TEXT, klass TEXT, status TEXT);")
        cx.execute("INSERT INTO func VALUES(?,?,?)", (0x3000, "NewBugFn", 1.0))
        cx.execute("INSERT INTO precondition VALUES(?,?,?)", ("NewBugFn", "caller", "open"))
        cx.commit(); cx.close()
        env = dict(os.environ, KAUDIT_ROOT=td5)
        o1 = os.path.join(td5, "p1.json"); open(o1, "w").write(json.dumps({"target": "NewBugFn", "verdict": "uncertain"}))
        subprocess.run([PY, os.path.join(BA_SCRIPTS, "ingest_phase2.py"), o1], capture_output=True, text=True, env=env, timeout=60)
        o2 = os.path.join(td5, "p2.json"); open(o2, "w").write(json.dumps({"target": "NewBugFn", "verdict": "violable-bug", "evidence": "integer overflow in the size math"}))
        p = subprocess.run([PY, os.path.join(BA_SCRIPTS, "ingest_phase2.py"), o2], capture_output=True, text=True, env=env, timeout=60)
        cx = sqlite3.connect(dbp)
        passes = [r[0] for r in cx.execute("SELECT audit_pass FROM audit WHERE func_name='NewBugFn' ORDER BY audit_pass")]
        naud = cx.execute("SELECT n_audited FROM func WHERE name='NewBugFn'").fetchone()
        newbug = cx.execute("SELECT status,bug_class FROM bug WHERE func_name='NewBugFn'").fetchone()
        cx.close()
        uassert("phase2 append-history runs clean", p.returncode == 0 and "Traceback" not in (p.stdout + p.stderr), (p.stdout + p.stderr)[:300])
        uassert("audit rows APPEND across passes (1,2)", passes == [1, 2], "passes=%r" % (passes,))
        uassert("func.n_audited tracks pass count", naud == (2,), "naud=%r" % (naud,))
        uassert("confirmed-violable auto-creates a class-inferred bug", newbug == ("confirmed-violable", "int-overflow"), "newbug=%r" % (newbug,))
    except Exception as e:
        bad("phase2 append-history run", repr(e))
    finally:
        shutil.rmtree(td5, ignore_errors=True)

    # disclosure-lens wiring: review-wf retains the SCHEMA + wires the binary-audit-reviewer agent,
    # the agent definitions (agents/) carry the lens prose, and the profile sink set must match the
    # copy-to-attacker disclosure sinks (so candidates rank up).
    print("## binary-audit: disclosure lens wiring + review/triage agents (no MCP)")
    try:
        import re as _re
        rwf = open(os.path.join(BA_SCRIPTS, "review-wf.js")).read()
        for tok in ("init-complete", "leak_back", "reaches-attacker", "disclosure_source", "reachability", "host-local", "guarded_by",
                    "null-deref", "div-zero", "uninit-use", "type-confusion", "logic", "impact", "host-psod", "nonzero-divisor"):
            uassert("review-wf carries %r" % tok, tok in rwf, "missing from review-wf.js")
        # review-wf now FANS OUT the binary-audit-reviewer agent; the lens PROSE lives in the agent
        # system prompt (markdown -> structurally immune to the template-literal break-out bug), while
        # review-wf retains the SCHEMA (tool-layer enforcement) + a slim per-function task.
        uassert("review-wf fans out the binary-audit-reviewer agent", "agentType: 'binary-audit-reviewer'" in rwf)
        uassert("review-wf task passes TARGET/ATTACKER/CONTEXT + OUT", all(t in rwf for t in ("${TARGET}", "${ATTACKER}", "${CONTEXT}", "outpath")))
        # the lens prose now lives in the auto-discovered agent definitions (agents/)
        arev = open(os.path.join(ROOT, "agents", "binary-audit-reviewer.md")).read()
        for tok in ("name: binary-audit-reviewer", "tools:", "disclosure lens", "Restore", "host-local",
                    "init-complete", "null-deref", "div-zero", "uninit-use", "type-confusion", "logic",
                    "impact", "leak-back", "reachability", "OUT"):
            uassert("reviewer agent carries %r" % tok, tok in arev, "missing from binary-audit-reviewer.md")
        atri = open(os.path.join(ROOT, "agents", "bn-triage.md")).read()
        for tok in ("name: bn-triage", "guard taxonomy", "copy-then-use", "architecturally-masked",
                    "clamp-to-produced", "exploitability ladder", "DEMONSTRATED", "CONFIRMED-LATENT",
                    "IMPACT:", "REACHABILITY:", "leak-back"):
            uassert("bn-triage carries %r" % tok, tok in atri, "missing from bn-triage.md")
        # regression (2026-06-28): review-wf.js MUST parse as valid JS under the Workflow harness wrapping.
        # The prompt is a backtick-delimited template literal; markdown backticks in the prose (`div`, `*_Alloc`,
        # `*Cpt*`...) previously broke OUT of the string -> the skill's primary launch path,
        # Workflow(review-wf-bN.js), failed to parse. (The prior pass drove it via Codex/text, so it never hit a
        # JS parser.) node --check on a harness-faithful wrap (strip `export`, stub the hooks, wrap top-level
        # return/await in an async fn) is the real guard.
        import shutil as _sh, tempfile as _tf
        _node = _sh.which("node")
        if not _node:
            skip("review-wf.js parses as valid JS", "node not installed")
        else:
            _wrapped = ("const phase=()=>{},log=()=>{},agent=async()=>({}),pipeline=async()=>[],parallel=async()=>[];\n"
                        "async function __wf(){\n" + rwf.replace("export const meta", "const meta") + "\n}\n")
            _mjs = os.path.join(_tf.gettempdir(), "_ba_reviewwf_check.mjs")
            open(_mjs, "w").write(_wrapped)
            _r = subprocess.run([_node, "--check", _mjs], capture_output=True, text=True)
            uassert("review-wf.js parses as valid JS (Workflow launch path)", _r.returncode == 0, _r.stderr[:400])
            try: os.remove(_mjs)
            except Exception: pass
        profdir = os.path.join(os.path.dirname(BA_SCRIPTS), "profiles")
        prof = json.load(open(os.path.join(profdir, "esxi-vmkernel.json")))
        srx = _re.compile(prof["sink_regex"])
        for s in ("SgCopyTo", "CopyToMachine", "CopySGData", "DeliverPkt", "AllocKernelMem"):
            uassert("sink_regex matches disclosure sink %r" % s, bool(srx.search(s)), "no match")
        vmxp = json.load(open(os.path.join(profdir, "vmx-userworld.json")))
        ctx = vmxp["review_context"].lower()
        for tok in ("null-deref", "div-zero", "type-confusion", "injection", "impact", "host-local"):
            uassert("vmx profile review_context covers %r" % tok, tok in ctx, "missing from vmx review_context")
    except Exception as e:
        bad("disclosure lens wiring", repr(e))


def unit_symbolicate():
    """No MCP: deterministic naming, workflow generation, split/combine, and sidecar ingest."""
    print("\n## symbolicate: sidecar + fanout helpers (no MCP)")
    import tempfile, shutil, sqlite3
    td = tempfile.mkdtemp(prefix="sym_unit_")
    try:
        dbp = os.path.join(td, "symdb.sqlite")
        cx = sqlite3.connect(dbp)
        cx.executescript(
            "CREATE TABLE func(addr INTEGER PRIMARY KEY, name TEXT);"
            "CREATE TABLE strref(func_addr INTEGER, s TEXT, pfx TEXT, is_logpfx INTEGER);"
            "CREATE TABLE domain(func_addr INTEGER, tag TEXT);"
            "CREATE TABLE edge(caller INTEGER, callee INTEGER, callee_name TEXT);")
        cx.execute("INSERT INTO func VALUES(?,?)", (0x1000, "sub_1000"))
        cx.execute("INSERT INTO func VALUES(?,?)", (0x2000, "AlreadyNamed"))
        cx.execute("INSERT INTO func VALUES(?,?)", (0x3000, "sub_3000"))
        cx.execute("INSERT INTO strref VALUES(?,?,?,?)", (0x1000, "Vmxnet3_InitQueues: ready", "Vmxnet3_InitQueues", 1))
        cx.execute("INSERT INTO strref VALUES(?,?,?,?)", (0x3000, "SharedPrefix: a", "SharedPrefix", 1))
        cx.execute("INSERT INTO strref VALUES(?,?,?,?)", (0x2000, "SharedPrefix: b", "SharedPrefix", 1))
        cx.execute("INSERT INTO domain VALUES(?,?)", (0x1000, "Vmxnet3"))
        cx.commit(); cx.close()
        side = os.path.join(td, "sidecar.json")
        prof = os.path.join(ROOT, "skills", "symbolicate", "profiles", "vmware.json")
        p = subprocess.run([PY, os.path.join(SYMBOLICATE, "determ.py"),
                            "--db", dbp, "--sidecar", side, "--profile", prof],
                           capture_output=True, text=True, timeout=60)
        data = json.load(open(side))
        rec = data.get("functions", {}).get("0x1000", {})
        uassert("sym determ runs", p.returncode == 0 and "Traceback" not in (p.stdout + p.stderr), (p.stdout + p.stderr)[:300])
        uassert("sym determ names exact log prefix", rec.get("name") == "Vmxnet3_InitQueues", "rec=%r" % rec)
        uassert("sym determ annotates provenance", rec.get("_source") == "determ-logstring" and rec.get("_confidence") == "high")
        uassert("sym determ ignores shared prefix", "0x3000" not in data.get("functions", {}), json.dumps(data, sort_keys=True)[:300])

        wf_batch = os.path.join(td, "batch.json")
        wf_out = os.path.join(td, "batch.wf.js")
        batch = [
            {"addr": "0x1000", "tier": "haiku", "strings": ["Vmxnet3_InitQueues: ready"], "named_callees": [], "named_callers": [], "domain": ["Vmxnet3"], "hlil": "return 0"},
            {"addr": "0x3000", "tier": "sonnet", "strings": ["thin"], "named_callees": [], "named_callers": [], "domain": [], "hlil": "return 1"},
        ]
        open(wf_batch, "w").write(json.dumps(batch))
        p2 = subprocess.run([PY, os.path.join(SYMBOLICATE, "make_wf.py"), wf_batch, "--out", wf_out],
                            capture_output=True, text=True, timeout=60)
        wft = open(wf_out).read()
        uassert("sym make_wf runs", p2.returncode == 0 and "symbolicate-name" in wft and "0x1000" in wft, (p2.stdout + p2.stderr)[:300])

        chunks = os.path.join(td, "chunks")
        results = os.path.join(td, "results")
        os.mkdir(results)
        p3 = subprocess.run([PY, os.path.join(SYMBOLICATE, "split_batch.py"), wf_batch, "--out-dir", chunks, "--haiku-size", "1", "--sonnet-size", "1"],
                            capture_output=True, text=True, timeout=60)
        chunk_files = sorted(os.path.join(chunks, f) for f in os.listdir(chunks) if f.endswith(".json"))
        uassert("sym split runs", p3.returncode == 0 and len(chunk_files) == 2, "chunks=%r out=%s" % (chunk_files, p3.stdout))
        for cf in chunk_files:
            src = json.load(open(cf))
            out = []
            for item in src:
                if item["addr"] == "0x3000":
                    out.append({"addr": item["addr"], "tier": "wrong-tier", "name": "", "confidence": "none", "comment": "abstain", "proto": "int bad(void);"})
                else:
                    out.append({"addr": item["addr"], "tier": item["tier"], "name": "Vmxnet3_InitQueues", "confidence": "high", "comment": "queue init", "proto": "int Vmxnet3_InitQueues(void);"})
            open(os.path.join(results, os.path.basename(cf).replace(".json", ".out.json")), "w").write(json.dumps(out))
        combined = os.path.join(td, "combined.json")
        p4 = subprocess.run([PY, os.path.join(SYMBOLICATE, "combine_outputs.py"),
                             "--chunks", chunks, "--results", results, "--out", combined, "--strict"],
                            capture_output=True, text=True, timeout=60)
        comb = json.load(open(combined))
        abst = [r for r in comb if r["addr"] == "0x3000"][0]
        uassert("sym combine runs strict", p4.returncode == 0 and len(comb) == 2, (p4.stdout + p4.stderr)[:500])
        uassert("sym combine clears abstention fields", abst["confidence"] == "none" and not abst["name"] and not abst["proto"], "abst=%r" % abst)

        p5 = subprocess.run([PY, os.path.join(SYMBOLICATE, "ingest.py"), combined, "--sidecar", side],
                            capture_output=True, text=True, timeout=60)
        merged = json.load(open(side))
        uassert("sym ingest runs", p5.returncode == 0 and "Traceback" not in (p5.stdout + p5.stderr), (p5.stdout + p5.stderr)[:300])
        uassert("sym ingest preserves high-confidence name", merged["functions"]["0x1000"]["name"] == "Vmxnet3_InitQueues")
    except Exception as e:
        bad("symbolicate unit run", repr(e))
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_binary_audit_live():
    """MCP: bn-audit-sync --file --save writes the comment+tag and PERSISTS it; reload proves full text survived."""
    print("\n## binary-audit: sync -> bndb write/save/persist (needs MCP)")
    import tempfile, shutil
    td = tempfile.mkdtemp(prefix="ba_live_")
    try:
        led = os.path.join(td, "kreview.db")
        _mk_ledger(led, func="leaf")           # 'leaf' exists in the fixture target
        tgt = os.path.join(td, "target_copy")
        shutil.copy(T, tgt)
        bndb = tgt + ".bndb"
        sync = os.path.join(ROOT, "bin", "bn-audit-sync")
        code, o, e = sh([sync, led, "--file", tgt, "--save"])
        blob = o + "\n" + e
        uassert("sync --file --save annotates 1 fn", bool(re.search(r"annotated 1 function", blob)), blob[:300])
        uassert("sync --file --save reports saved", bool(re.search(r"saved -> ", blob)) and os.path.exists(bndb) and os.path.getsize(bndb) > 0, blob[:300])
        # reload the SAVED db independently (object load, no tab) and confirm the comment persisted in full
        rd = ("f=_bv.get_functions_by_name('leaf');c=(f[0].comment if f else '') or '';"
              "print('READBACK',int('[binaudit]' in c),int('DESC_TAIL_ZZZ' in c),int('PATH_TAIL_ZZZ' in c),c.count(chr(8230)))")
        rc2, o2, e2 = sh([PY, "-c",
            "import sys;sys.path.insert(0,%r);import bncm;bncm.run(%r,_file=%r,_bvmatch=None)" % (INSPECT, rd, bndb)])
        m = re.search(r"READBACK (\d) (\d) (\d) (\d+)", o2 + e2)
        if not m:
            bad("sync persisted-comment readback", "no READBACK line", (o2 + e2)[:300])
        else:
            uassert("persisted: [binaudit] marker present", m.group(1) == "1")
            uassert("persisted: full bug desc", m.group(2) == "1")
            uassert("persisted: full guest_path", m.group(3) == "1")
            uassert("persisted: zero truncation marks", m.group(4) == "0")
    except Exception as e:
        bad("binary-audit live sync", repr(e))
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_re_sync_live():
    """MCP: bn-re-apply pushes a sidecar (rename, struct, var retype, function + line comments incl. a
    LONG multi-line analysis) into a bndb, persists it, and an independent reload confirms it landed
    intact — long comments must NOT be truncated. Then re-apply for idempotency."""
    print("\n## binary-ninja: re_sync sidecar -> bndb apply/persist (needs MCP)")
    import tempfile, shutil
    td = tempfile.mkdtemp(prefix="resync_live_")
    try:
        tgt = os.path.join(td, "target_copy")
        shutil.copy(T, tgt)
        bndb = tgt + ".bndb"
        # 'leaf' exists in the fixture; build a sidecar with a LONG multi-line comment (~5 KB)
        _base = "RECON: the caller-owed length bound is not re-checked here; a missing upstream clamp yields a stack OOB write. "
        long_comment = "\n\n".join("[para %d] %s" % (i, _base * 3) for i in range(1, 12)) + "\n\nTAIL_MARKER_RESYNC"
        leaf_addr = addr_of("leaf")
        if not leaf_addr:
            return skip("re_sync live", "could not resolve leaf addr")
        side = {
            "binary": "target_copy",
            "types_c": "struct ReSyncProbe { uint32_t a; uint64_t b; void *c; };",
            "functions": {leaf_addr: {
                "name": "leaf_RESYNC",
                "comment": long_comment,
                "line_comments": {leaf_addr: "fn entry note"},
            }},
        }
        sp = os.path.join(td, "side.json"); open(sp, "w").write(json.dumps(side))
        apply = os.path.join(ROOT, "bin", "bn-re-apply")
        code, o, e = sh([apply, sp, "--file", tgt, "--save"])
        blob = o + "\n" + e
        uassert("re-apply reports applied", bool(re.search(r"\[re-sync\] applied:.*funcs=1", blob)), blob[:300])
        uassert("re-apply --file --save persists", bool(re.search(r"saved -> ", blob)) and os.path.exists(bndb), blob[:300])
        # idempotency: second apply yields the same func count, no item errors
        code2, o2b, e2b = sh([apply, sp, "--file", bndb, "--save"])
        uassert("re-apply idempotent (no errors)", "funcs=1" in (o2b + e2b) and "item error" not in (o2b + e2b), (o2b + e2b)[:300])
        # independent reload of the saved db: name + struct + LONG comment intact
        rd = ("f=_bv.get_functions_by_name('leaf_RESYNC');c=(f[0].comment if f else '') or '';"
              "st=_bv.get_type_by_name('ReSyncProbe');"
              "print('RB',int(bool(f)),len(c),int(c.rstrip().endswith('TAIL_MARKER_RESYNC')),int('\\n\\n[para 11]' in c),int(st is not None))")
        rc3, o3, e3 = sh([PY, "-c",
            "import sys;sys.path.insert(0,%r);import bncm;bncm.run(%r,_file=%r,_bvmatch=None)" % (INSPECT, rd, bndb)])
        m = re.search(r"RB (\d) (\d+) (\d) (\d) (\d)", o3 + e3)
        if not m:
            bad("re_sync persisted readback", "no RB line", (o3 + e3)[:300])
        else:
            uassert("persisted: function renamed", m.group(1) == "1")
            uassert("persisted: long comment intact (len==authored)", int(m.group(2)) == len(long_comment), "got %s want %d" % (m.group(2), len(long_comment)))
            uassert("persisted: comment tail not truncated", m.group(3) == "1")
            uassert("persisted: multi-line structure intact", m.group(4) == "1")
            uassert("persisted: struct type defined", m.group(5) == "1")
    except Exception as e:
        bad("re_sync live", repr(e))
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_sbom_kb():
    """sbom-kb skill: schema, build, views, query helper — no network/BN needed."""
    import tempfile, sqlite3, shutil
    print("\n--- sbom-kb tests ---")
    td = tempfile.mkdtemp(prefix="sbomkb_test_")
    schema = os.path.join(SBOMKB, "schema.sql")
    seeds = os.path.join(SBOMKB, "seeds")
    build_script = os.path.join(SBOMKB, "scripts", "build_sbom.py")
    resolve_script = os.path.join(SBOMKB, "scripts", "resolve_and_classify.py")
    q_sh = os.path.join(SBOMKB, "scripts", "q.sh")
    try:
        # 1. schema loads without error
        db = os.path.join(td, "test.db")
        con = sqlite3.connect(db)
        con.executescript(open(schema).read())
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for t in ["host", "binary", "library", "link", "package", "cve", "analysis",
                   "upstream_fix", "github_review", "residual_check", "proc_map", "artifact"]:
            uassert(f"sbom: schema has table '{t}'", t in tables)
        views = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='view'").fetchall()]
        for v in ["v_preauth_ndays", "v_patched_packages", "v_findings", "v_todo",
                   "v_completeness", "v_binary_rollup", "v_github_coverage", "v_dlopen_loads"]:
            uassert(f"sbom: schema has view '{v}'", v in views)

        # 2. empty DB views return 0 rows without error
        for v in views:
            rows = con.execute(f"SELECT * FROM {v}").fetchall()
            uassert(f"sbom: empty {v} is queryable", isinstance(rows, list))

        # 3. insert test data and verify views
        con.execute("INSERT INTO binary(path,name,role,listen_ports,reachability,work_status) "
                    "VALUES('/usr/sbin/testd','testd','test daemon','443','preauth-remote','todo')")
        con.execute("INSERT INTO library(soname,path,version,upstream,audit_status) "
                    "VALUES('libfoo.so.1','/usr/lib/libfoo.so.1','1.2.3','libfoo','version-resolved')")
        con.execute("INSERT INTO link(binary_path,library_soname,link_type) "
                    "VALUES('/usr/sbin/testd','libfoo.so.1','dynamic')")
        con.execute("INSERT INTO cve(cve_id,component,component_type,severity,present_on_fleet,triage_status) "
                    "VALUES('CVE-2099-0001','libfoo.so.1','library','High',1,'todo')")
        con.execute("INSERT INTO analysis(cve_id,component,reachable,exploitability,verdict,status) "
                    "VALUES('CVE-2099-0001','libfoo.so.1','preauth-remote','plausible','live n-day','open')")
        con.commit()

        ndays = con.execute("SELECT * FROM v_preauth_ndays").fetchall()
        uassert("sbom: v_preauth_ndays returns test CVE", len(ndays) == 1 and ndays[0][0] == "CVE-2099-0001")

        rollup = con.execute("SELECT * FROM v_binary_rollup").fetchall()
        uassert("sbom: v_binary_rollup has testd with 1 dep", len(rollup) == 1 and rollup[0][3] == 1)

        todo = con.execute("SELECT * FROM v_todo").fetchall()
        uassert("sbom: v_todo lists open items", len(todo) >= 3)

        comp = con.execute("SELECT * FROM v_completeness").fetchall()
        uassert("sbom: v_completeness has 4 levels", len(comp) == 4)

        findings = con.execute("SELECT * FROM v_findings").fetchall()
        uassert("sbom: v_findings returns the test finding", len(findings) == 1)

        # 4. build_sbom.py runs with no config (produces empty DB)
        db2 = os.path.join(td, "built.db")
        env = dict(os.environ, SBOM_DB=db2, SBOM_SEEDS=seeds)
        rc4, o4, e4 = sh([PY, build_script], timeout=30)
        # run with correct env
        p4 = subprocess.run([PY, build_script], capture_output=True, text=True, timeout=30,
                            env=env)
        blob4 = p4.stdout + "\n" + p4.stderr
        probs4 = []
        if p4.returncode != 0: probs4.append("rc=%d" % p4.returncode)
        for pat in [r"\[packages\] skipped", r"\[graph\].*binaries", r"\[seeds\]"]:
            if not re.search(pat, blob4): probs4.append("missing /%s/" % pat)
        if probs4:
            bad("sbom: build_sbom.py (no-host)", "; ".join(probs4), blob4[:500])
        else:
            ok("sbom: build_sbom.py (no-host)")

        # verify the built DB has the schema
        con2 = sqlite3.connect(db2)
        t2 = [r[0] for r in con2.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        uassert("sbom: built DB has tables", "binary" in t2 and "cve" in t2)
        con2.close()

        # 5. resolve_and_classify.py refuses without SBOM_HOST (expected)
        expect("sbom: resolve_and_classify requires host",
               [PY, resolve_script], rc=None,
               has=[r"by audit_status"])

        # 6. q.sh runs against a DB
        expect("sbom: q.sh money query", ["bash", q_sh], rc=None)

        # 7. no VMware-specific strings in any skill file
        for dirpath, _, filenames in os.walk(SBOMKB):
            if "__pycache__" in dirpath:
                continue
            for fn in filenames:
                if fn.endswith((".py", ".sql", ".md", ".sh")):
                    content = open(os.path.join(dirpath, fn)).read()
                    for leak in ["vmware", "vcenter", "vcsa", "vmdird", "vmcad", "vmafdd",
                                 "rhttpproxy", "vpxd", "likewise", "photon", "esxi", "vsphere",
                                 "25197330", "25413364", "192.168.0", "phil_notes"]:
                        uassert(f"sbom: no '{leak}' in {fn}",
                                leak not in content.lower(),
                                f"found '{leak}' in {os.path.join(dirpath, fn)}")
        con.close()
    except Exception as e:
        bad("sbom-kb suite", repr(e))
    finally:
        shutil.rmtree(td, ignore_errors=True)


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
    unit_binary_audit()         # always (no BN): ledger->comment builder + ingest caps
    unit_symbolicate()          # always (no BN): sidecar naming + split/combine/ingest helpers
    test_sbom_kb()              # always (no BN/network): schema, build, views, leak-check
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
        test_inspect(); test_hunt(); test_scanners(); test_bin_wrappers(); test_bulkdecompile(); test_binary_audit_live(); test_re_sync_live()
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
