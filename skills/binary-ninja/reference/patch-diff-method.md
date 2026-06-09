# Patch-diffing: finding the silently-fixed bug between two builds

When a vendor ships a security fix without details, the patch itself reveals the bug. Diff the **old** and
**new** build of a binary, find the changed function, and read what the new build *adds* — a bound check, a
re-validation after a lock, a size cross-check. **That delta is the vulnerability in the old (still-deployed)
build** — a live n-day on every host that hasn't updated.

## 1. Fast symbol-matched diff for NON-stripped binaries — `symdiff.py`
Decompiler diffs (e.g. ghidriff) are thorough but slow (and flaky on large/odd binaries). For **non-stripped**
ELFs, `symdiff.py` is seconds-not-hours: it disassembles each named function with capstone, **normalizes away
layout noise** (masks branch/call targets, RIP-relative displacements, and `push <imm>` line-number constants —
all of which shift with unrelated edits), hashes the normalized body, and diffs by **symbol name** across the
two builds. What's left is the set of functions whose *logic* genuinely changed.
```bash
python3 symdiff.py old.elf new.elf --demangle --list
```
Function sizes come from the gap to the next symbol (handles `.dynsym` entries with `st_size == 0`). Tune the
normalization if your toolchain emits different layout noise.

## 2. Stripped / library code
No symbol names to match on. Options, cheapest first:
- Diff by **exported** symbol (`.dynsym` FUNC) where present.
- Use BN's built-in function matching / a signature tool (e.g. Signature Libraries) to pair functions, then
  compare HLIL.
- Anchor on **strings/constants**: find a changed function via an xref to a stable log string or magic value.

## 3. ET_REL relocatable objects (kernel modules) are a gift
Relocatable objects (`.o`/kernel modules) are usually **not stripped** and every call site carries a
relocation naming the exact callee (`.rela.text` → `.symtab`). So you can resolve allocator/`memcpy` call
targets *by name without any analysis engine* — which is what `cap_scan.py` exploits to sweep many modules
fast. For diffing, the `.symtab` gives you per-function names directly; `symdiff.py` works as-is.

## 4. The callee-diff technique (when the function body looks "the same")
Sometimes the changed function's own instructions barely differ, but it now **calls something new**. The fix
is often "add a re-validation/lock/bound call." Compare the *set of callees* (resolved names) between old and
new: a new `rw_rlock` / `*_revalidate` / `*_bounds_check` call in the new build, absent in the old, points
straight at a race/UAF or a missing-check bug. Diff the call targets, not just the opcode stream.

## 5. Addressing discipline
`symdiff.py` / objdump / capstone work in **file** coordinates (for ET_REL, `.symtab` `st_value` = file
offset into `.text`). Binary Ninja works in its **rebased** address space. When you pivot from "symdiff says
function X changed" to "read X's HLIL in BN," look X up by **name** in BN (`bv.get_functions_by_name`) — do
not carry the file offset across as a BN address. (See `mcp-codemode-guide.md` §D.)

## 6. Workflow
1. Acquire the two builds (old = deployed/vulnerable, new = patched). Extract matching binaries.
2. `symdiff.py old new --list` → the changed-function set. Triage by name to the security-relevant ones
   (parsers, allocators, auth, anything touching attacker input).
3. For each, read **both** versions' HLIL in BN side-by-side; identify what the new build adds/removes.
4. Confirm the old build genuinely lacks the guard and that the path is attacker-reachable → that's the bug.
5. Cross-check with the bug-class scanners on the old build to confirm the unguarded primitive is live.
