#!/usr/bin/env python3
"""gh-exec — run ARBITRARY Python against the target via ghidra.eval (escape hatch).

Reads code from --code, --code-file, or stdin. Requires a target (--file/--program). In-scope
names inside the code: program, flat_api, decompiler, listing, memory, symbol_table, pyghidra,
ghidra, java, session_id (see the skill's reference guide). Output is SCRUBBED (tainted binary).

  gh-exec --file /tmp/x --code 'print(program.getName())'
  echo 'for b in memory.getBlocks(): print(b.getName())' | gh-exec --file /tmp/x

NOTE: this runs the AGENT's own code as-is (no validation, no try/except wrapper) so you see real
results/tracebacks. Do NOT pass attacker-controlled code here. Because ghidra.eval discards
captured stdout if the code raises, guard your own errors if you need partial output."""
import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghcm


def main():
    ap = argparse.ArgumentParser(description="Run arbitrary Python against the target via ghidra.eval.")
    ghcm.add_target_args(ap)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--code", help="code string to evaluate")
    g.add_argument("--code-file", help="read code from this file (validated path)")
    a = ap.parse_args()

    if a.code is not None:
        code = a.code
    elif a.code_file:
        with open(ghcm.vpath(a.code_file, "code-file")) as f:
            code = f.read()
    else:
        code = sys.stdin.read()
    if not code.strip():
        ghcm.die("no code given (use --code, --code-file, or stdin)")

    client = ghcm.Client()
    try:
        sid = ghcm.ensure_session(client, **ghcm.target_kwargs(a))
        out, err = client.call_tool("ghidra.eval", {"code": code, "session_id": sid})
    finally:
        client.close()

    text = ghcm.scrub(out.get("stdout") or "")
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
    if out.get("result") not in (None, ""):
        sys.stdout.write("=> %s\n" % ghcm.scrub(str(out.get("result"))))
    if out.get("stderr"):
        sys.stderr.write("[ghidra stderr]\n" + ghcm.scrub(out["stderr"]) + "\n")
    if err:
        sys.stderr.write("[ghidra ERROR] " + ghcm.scrub(json.dumps(out))[:600] + "\n")
        sys.exit(ghcm.EXIT_ERROR)


if __name__ == "__main__":
    main()
