# Binary Ninja code-mode MCP — execution model & gotchas

Practical notes for driving Binary Ninja by sending Python to its code-mode MCP `/execute` endpoint
(the `binja.py` client). Read this before writing non-trivial scripts — the sandbox has sharp edges.

## What it is
A BN **GUI plugin** runs an HTTP server inside the BN process. You don't get granular MCP "tools" — you
**send Python source** that is `exec()`'d inside BN with a `binja` API object in scope (the "code mode"
pattern). Works on Personal edition (runs in the GUI's own Python; no headless license).

- Endpoint `POST /execute {"code": "..."}` → `{"success","output","error","timed_out"}`.
  **`output` is captured stdout — you must `print()` anything you want back.**
- Auth: `Authorization: Bearer <key>`. (For the `akrutsinger` plugin, send *only* the bearer header —
  adding `X-API-Key` too breaks auth with a 401.)
- Server `/execute` timeout is ~600 s; the `binja.py` client waits 900 s (`BINJA_HTTP_TIMEOUT`). Output
  truncates ~100 KB — do heavy work in one call and `print` a compact summary.

## Execution model (the root of most gotchas)
Code runs roughly as `exec(code, {"binja": api, "__builtins__": <restricted>}, {})` — **separate globals
and locals dicts**. Your top-level `x = …` lands in *locals*, but `def`/`lambda`/comprehension bodies
resolve free names via *globals* → **nested scopes can't see your top-level variables.**

## Gotchas catalog (each cost real time at least once)

### A. Sandbox rejections (an AST validator blocks the whole script before it runs)
- **`re.compile` is forbidden** (`Forbidden attribute access: compile`). Keep the pattern as a raw **string**
  and call `re.search(PAT, s)` / `re.finditer(PAT, s)` / `re.sub(PAT, r, s)` each time — never a compiled object.
- **`__import__()` is forbidden.** Use a plain `import binaryninja` statement (import statements are allowed).
- Blocked imports include `os, sys, subprocess, socket, urllib, ctypes, pickle, threading, pathlib, glob,
  shutil, builtins`. Blocked names/dunders: `open, eval, exec, compile, __import__, __subclasses__,
  __globals__, __code__, __builtins__`. Builtins are a **whitelist** (len, list, dict, hex, int, enumerate,
  map, filter, getattr, hasattr, isinstance, range, str, sorted, set, sum, print, … but NOT open/eval/exec).

### B. The scoping trap → NameError swarm (`name 'bv'/'re'/'s' is not defined`)
Because globals≠locals (above), any helper function or comprehension that references your top-level vars
NameErrors. Fixes:
- **Bind via default args** everything a function needs: `def helper(s, _re=re, _bv=bv): …`.
- **Avoid comprehensions/genexprs** that reference top-level vars — use explicit `for` loops.
- **`import` inside the function** if it needs a module.
- **No recursion** — a `def` can't see its own name (it's in locals) → NameError on self-call. Use a worklist.
- Each `/execute` is **stateless**: re-`import` and re-`load` every call (`name 'binaryninja' not defined`
  means you referenced it without importing it *in that call*).

### C. BN API-shape traps (AttributeError at runtime)
- **`f.hlil` can be `None`** (no decompilation) → guard `hl = f.hlil; if hl is None: continue`, and wrap each
  function in `try/except` so one bad function doesn't abort a whole-binary sweep.
- Iterate **`f.hlil.instructions`** — not `.llil_instructions`. There is **no `.instruction_count`** →
  `len(list(f.hlil.instructions))`.
- Know what the API returns (don't call `.name` on a str or `.address` on an int):
  `bv.get_strings()` → StringReference (`.value`, `.start`); `bv.get_code_refs(addr)` → ReferenceSource
  (`.function`, `.address`); `bv.functions` → Function (`.name`, `.start`, `.hlil`, `.total_bytes`, `.callers`).

### D. Addresses: BN REBASES — BN address ≠ on-disk vaddr/offset
BN loads PIE executables and ET_REL relocatable objects at a rebased image base, so a BN-reported address is
**not** the file vaddr/offset. Running capstone on bytes read at a BN address, or `objdump --start-address=
<BNaddr>` on the file, yields garbage. Rule: decompile/disassemble **through BN** for BN addresses; use
**objdump/readelf/capstone on the raw file with file offsets** (for ET_REL, `.symtab` `st_value` *is* the
file offset into `.text`). Don't mix the two coordinate systems.

### E. Stability & concurrency
- **`/execute` is single-threaded and serial** — one query at a time. Don't fire concurrent/background calls;
  they queue or wedge the server. Sweep scripts must serialize (one binary/bndb per call).
- **Heavy iteration can crash BN** → next call returns `connection refused`. Triggers: iterating a binary with
  100k+ functions, or full-binary HLIL sweeps on tens-of-MB binaries. Recover: restart the BN GUI + re-start
  the server. Mitigate: bound every call (cap output, filter functions first, per-func try/except), and prefer
  a cached `.bndb` + `update_analysis=False` so you reuse saved analysis instead of re-analyzing.

## The robust whole-binary scan template
```python
import binaryninja, re                       # re-import every call (stateless); NO re.compile
bv = binaryninja.load("/tmp/x.bndb", update_analysis=False)
PAT = r'...'                                  # pattern as a raw STRING
def classify(s, _re=re):                      # bind re via default arg (scoping trap)
    return _re.search(PAT, s)
hits = []
for f in bv.functions:                        # Function objects
    try:
        hl = f.hlil
        if hl is None:                        # guard: no decompilation
            continue
        for ins in hl.instructions:           # .instructions, NOT .llil_instructions
            s = str(ins)
            ...
    except Exception:
        continue                              # one bad func mustn't kill the sweep
print("candidates:", len(hits))               # print() — output is captured stdout
```

## Cheatsheet
```bash
python3 binja.py 'print(binja.get_binary_status())'
python3 binja.py 'import binaryninja; bv=binaryninja.load("/path",update_analysis=False); print(len(list(bv.functions)))'
curl -s -H 'Authorization: Bearer <key>' http://127.0.0.1:42069/status
```
