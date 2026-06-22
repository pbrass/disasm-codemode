#!/usr/bin/env python3
"""Bulk-dump a binary to per-function HLIL (+ optional disassembly) files via the
Binary Ninja code-mode MCP.

WHY this exists / why one-function-per-call:
  * `/execute` output is captured stdout and TRUNCATED at ~100 KB, so you cannot print a
    whole large binary's decompilation in one call.
  * A full-binary HLIL iteration inside a single `/execute` can CRASH the BN host (heavy
    iteration on 10-36 MB binaries -> the server starts returning connection-refused).
  * The sandbox forbids `open`/`os`, so the `/execute` side cannot write files itself.
  * Each `/execute` is STATELESS for headless `binaryninja.load()` (a `bv` does not persist
    across calls) -> re-loading a big binary per function would cost ~40 s each.
So: keep the binary OPEN IN THE BN GUI (its BinaryView persists across calls), rebind the
`binja` API object to it, then dump ONE function per `/execute` (each well under 100 KB) and
write each result to disk HERE in this local driver (which has real `open`/`os`).

OUTPUT LAYOUT (standard, to disambiguate which build a decompilation came from -- the
source-vs-shipped-binary confusion is real, cf. D7/D8):
    <root>/<product>/<build>/<binary>/<function>.hlil.c
    <root>/<product>/<build>/<binary>/<function>.asm        (with --asm)
    <root>/<product>/<build>/<binary>/INDEX.{json,txt}
e.g.  decomp/vcenter/24755230/vmdird/ParseFilter.hlil.c

Optionally restrict to the reachable closure from given entry points (e.g. the pre-auth
request handlers) instead of every function.

Prereq: the target binary is open in the BN GUI that hosts the code-mode MCP
(see the binary-ninja skill: `scripts/binja.py`, `bnopen.sh`, or UIContext openFilename).

Usage:
  dump_decompile.py --product vcenter --build 24755230 --bv-match vmdird --root ./decomp --all [--asm]
  dump_decompile.py --product vcenter --build 24755230 --bv-match vmdird --root ./decomp \
                    --entry ParseFilter,VmDirPerformBind [--asm] [--binary vmdird]
Env: BINJA_MCP_URL (default http://127.0.0.1:42069), BINJA_MCP_KEY (default binja-codemode-local)
"""
import json, re, os, argparse, urllib.request

URL = os.environ.get("BINJA_MCP_URL", "http://127.0.0.1:42069").rstrip("/") + "/execute"
KEY = os.environ.get("BINJA_MCP_KEY", "binja-codemode-local")

# Decompiled text/names are attacker-controlled; neutralize terminal-escape bytes so the written
# .hlil.c files (and any cat/grep of them) are safe (see binary-ninja/reference/mcp-codemode-guide.md §F).
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
def _scrub(s):
    return _CTRL.sub(lambda m: "\\x%02x" % ord(m.group(0)), s) if s else s


def execute(code, timeout=300):
    body = json.dumps({"code": code}).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={
        "Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        j = json.loads(r.read())
    if not j.get("success"):
        raise RuntimeError(j.get("error") or j.get("output") or "execute failed")
    # The code-mode executor prefixes output lines with a "[N.Ns] " timing tag; strip it so
    # parsing (NO-MATCH checks, json.loads of the function list) is not corrupted.
    # strip the executor's "[N.Ns] " timing prefix. NOTE: do NOT scrub here — some callers
    # (list_all/list_closure) json.loads() this output, and scrubbing a raw 0x7f-0x9f byte to
    # "\xNN" would be an invalid JSON escape. Scrub the decompilation TEXT in dump_one() instead.
    out = j.get("output", "")
    return "\n".join(re.sub(r'^\[\d+(?:\.\d+)?s\]\s?', '', ln) for ln in out.split("\n"))


def rebind(match):
    """Point binja._bv at the open GUI tab whose name contains `match` (deterministic
    regardless of which tab has focus). Returns the bound binary's filename."""
    code = (
        "from binaryninjaui import UIContext\n"
        "hit=None\n"
        "for ctx in UIContext.allContexts():\n"
        " for bv,name in ctx.getAvailableBinaryViews():\n"
        "  if %s in name:\n"
        "   binja._bv=bv; binja._state._bv=bv; hit=name\n"
        "print((binja.get_binary_status().get('filename') if hit else '') or hit or 'NO-MATCH')" % json.dumps(match))
    return execute(code).strip().splitlines()[-1]


def list_all():
    out = execute("import json as _j; print(_j.dumps(sorted({f.name for f in binja._bv.functions})))")
    return json.loads(out.strip().splitlines()[-1])


def list_closure(entry):
    """BFS the call graph from `entry` over callees, dropping compiler/STL noise."""
    code = (
        "import json as _j\n"
        "bv=binja._bv\n"
        "entry=%s\n"
        "byname={}\n"
        "for f in bv.functions: byname.setdefault(f.name,f)\n"
        "def noise(n): return n.startswith('std::') or n.startswith('_Z') or 'anonymous_namespace' in n or n.startswith('__') or n.startswith('operator')\n"
        "seen=set(); stack=[byname[n] for n in entry if n in byname]\n"
        "while stack:\n"
        " f=stack.pop()\n"
        " if f.start in seen: continue\n"
        " seen.add(f.start)\n"
        " for c in f.callees:\n"
        "  if c.start not in seen and not noise(c.name): stack.append(c)\n"
        "out=[]\n"
        "for a in seen:\n"
        " f=bv.get_function_at(a)\n"
        " if f and not noise(f.name): out.append(f.name)\n"
        "print(_j.dumps(sorted(out)))" % json.dumps(entry))
    return json.loads(execute(code).strip().splitlines()[-1])


def safe(nm):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", nm)[:120]


def dump_one(nm, want_asm):
    nmj = json.dumps(nm)
    hlil = execute(
        "f=next((x for x in binja._bv.functions if x.name==%s),None)\n"
        "callers=sorted({c.name for c in f.callers}) if f else []\n"
        "print('// callers: '+', '.join(callers))\n"
        "print(binja.decompile(%s))" % (nmj, nmj))
    asm = None
    if want_asm:
        try:
            asm = execute("print(binja.get_assembly(%s))" % nmj)
        except Exception as e:
            asm = "// get_assembly(%s) failed: %r\n" % (nm, e)
    # scrub the decompilation TEXT (attacker-controlled) so the written .hlil.c/.asm files are
    # terminal-safe to cat/grep; the function-list JSON paths are left intact (see execute()).
    return _scrub(hlil), (_scrub(asm) if asm is not None else None)


def main():
    ap = argparse.ArgumentParser(description="Bulk-dump a binary to per-function files via BN code-mode.")
    ap.add_argument("--bv-match", required=True, help="substring of the open GUI tab name to bind (e.g. vmdird)")
    ap.add_argument("--out", help="explicit output directory (general use)")
    # OR compose a structured path <root>/<product>/<build>/<binary>/ (disambiguates builds):
    ap.add_argument("--product", help="product, e.g. vcenter / esxi (with --build composes the structured path)")
    ap.add_argument("--build", help="build number, e.g. 24755230 (with --product)")
    ap.add_argument("--root", default="decomp", help="output root for the composed path (default: ./decomp)")
    ap.add_argument("--binary", help="binary name for the composed path (default: basename of the bound BV filename)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true", help="dump every function")
    g.add_argument("--entry", help="comma-separated entry points; dump only their reachable closure")
    ap.add_argument("--asm", action="store_true", help="also write <name>.asm disassembly")
    args = ap.parse_args()

    fname = rebind(args.bv_match)
    print("[*] bound ->", fname)
    if fname == "NO-MATCH":
        raise SystemExit("no open GUI tab matched %r" % args.bv_match)
    binary = args.binary or (os.path.basename(fname) if fname else args.bv_match) or args.bv_match
    if args.out:
        outdir = args.out
    elif args.product and args.build:
        outdir = os.path.join(args.root, safe(args.product), safe(args.build), safe(binary))
    else:
        raise SystemExit("specify --out DIR, or both --product and --build (structured path)")
    os.makedirs(outdir, exist_ok=True)
    print("[*] writing to", outdir)

    names = list_all() if args.all else list_closure([e.strip() for e in args.entry.split(",") if e.strip()])
    print("[*] %d functions to dump (asm=%s)" % (len(names), bool(args.asm)))

    idx = []
    for i, nm in enumerate(names):
        try:
            hlil, asm = dump_one(nm, args.asm)
        except Exception as e:
            print("  [%d/%d] %s: ERR %r" % (i + 1, len(names), nm, e)); continue
        base = safe(nm)
        with open(os.path.join(outdir, base + ".hlil.c"), "w") as fh:
            fh.write(hlil)
        asm_name = None
        if asm is not None:
            asm_name = base + ".asm"
            with open(os.path.join(outdir, asm_name), "w") as fh:
                fh.write(asm)
        idx.append({"name": nm, "hlil": base + ".hlil.c", "asm": asm_name, "bytes": len(hlil)})
        if (i + 1) % 50 == 0:
            print("  ...%d/%d" % (i + 1, len(names)))

    with open(os.path.join(outdir, "INDEX.json"), "w") as fh:
        json.dump({"product": args.product, "build": args.build, "binary": binary,
                   "source_file": fname, "functions": idx}, fh, indent=1)
    with open(os.path.join(outdir, "INDEX.txt"), "w") as fh:
        fh.write("# %s %s %s (%s)\n" % (args.product or "-", args.build or "-", binary, fname))
        for e in idx:
            fh.write("%-55s %7dB  %s\n" % (_scrub(e["name"]), e["bytes"], e["hlil"]))
    print("[+] DONE: wrote %d functions to %s" % (len(idx), outdir))


if __name__ == "__main__":
    main()
