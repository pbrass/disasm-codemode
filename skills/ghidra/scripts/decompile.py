#!/usr/bin/env python3
"""gh-decompile — print the decompiled C of one function, by --name or --addr.

The Ghidra sibling of bn-inspect's decompile.py. Uses the pre-opened `decompiler`
(DecompInterface) from the eval context. Output is scrubbed by ghcm.run() (tainted binary)."""
import argparse
import ghcm

BODY = r'''
fm = program.getFunctionManager()
fn = None
if _addr is not None:
    fn = flat_api.getFunctionContaining(_toaddr(_addr))
    if fn is None:
        print("[no function at 0x%x]" % _addr)
        raise SystemExit
else:
    for f in fm.getFunctions(True):
        if f.getName() == _name:
            fn = f
            break
    if fn is None:
        print("[no function named %s]" % _name)
        raise SystemExit
_res = decompiler.decompileFunction(fn, _timeout, pyghidra.task_monitor())
if not _res.decompileCompleted():
    print("[decompile failed for %s: %s]" % (fn.getName(), _res.getErrorMessage()))
    raise SystemExit
print("// %s  entry=%s  size=%d bytes" % (fn.getName(), fn.getEntryPoint(), fn.getBody().getNumAddresses()))
print(_res.getDecompiledFunction().getC())
'''


def main():
    ap = argparse.ArgumentParser(description="Decompile one function (Ghidra code-mode).")
    ghcm.add_target_args(ap)
    sel = ap.add_mutually_exclusive_group(required=True)
    sel.add_argument("--name", help="function name")
    sel.add_argument("--addr", help="address inside the function (0x... or decimal)")
    ap.add_argument("--timeout", type=int, default=30, help="decompiler timeout seconds (1-300)")
    args = ap.parse_args()

    if args.name:
        params = {"_name": ghcm.vsym(args.name), "_addr": None}
    else:
        params = {"_name": None, "_addr": ghcm.vaddr(args.addr)}
    params["_timeout"] = max(1, min(args.timeout, 300))
    ghcm.run(BODY, args, **params)


if __name__ == "__main__":
    main()
