import binaryninja, re
bv = binaryninja.load("BNDBPATH", update_analysis=False)
# DANGEROUS-COPY scanner (DC). Two high-value patterns:
#  (1) UNBOUNDED string ops: strcpy/strcat/sprintf/vsprintf/stpcpy/wcscpy/gets — flag EVERY call
#      (inherently length-unchecked; any hit into a bounded dest from attacker data = overflow).
#  (2) STACK-DEST copy with NON-CONST length: memcpy/memmove/bcopy/_vmk_Memcpy/strncpy/strncat/snprintf
#      whose dst is a stack buffer (&var_ / var_) and whose length arg is variable (not a bare 0x constant)
#      => classic stack buffer overflow (control-flow hijack). Flag-generously; triage every hit.
UNBOUNDED = r'\b(strcpy|strcat|sprintf|vsprintf|vsnprintf|stpcpy|wcscpy|wcscat|gets|strecpy)\s*\('
BOUNDED   = r'\b([A-Za-z_]*[Mm]em(cpy|move)[A-Za-z_]*|bcopy|_vmk_Memcpy|strncpy|strncat|snprintf|memset)\s*\('
# which arg is the length, by callee
LEN_IDX = {'strncpy':2,'strncat':2,'snprintf':1,'memset':2}  # default 2 for mem*/bcopy/_vmk_Memcpy

def args_of(s, start):
    depth = 0; cur = ''; out = []; i = start
    while i < len(s):
        c = s[i]
        if c == '(':
            depth += 1
            if depth == 1:
                i += 1; continue
        if c == ')':
            depth -= 1
            if depth == 0:
                out.append(cur); break
        if c == ',' and depth == 1:
            out.append(cur); cur = ''; i += 1; continue
        cur += c; i += 1
    return out

def is_stack_dst(dst, _re=re):
    # HLIL stack-buffer destination: &var_NN, var_NN (array), or &var_NN[...]
    return bool(_re.search(r'&?\bvar_[0-9a-fA-F]+', dst))

def is_const_len(ln, _re=re):
    # length is a bare numeric constant (0x.. or decimal) => bounded/safe; sizeof(...) also safe-ish
    t = ln.strip()
    if _re.fullmatch(r'(0x[0-9a-fA-F]+|[0-9]+)', t):
        return True
    if 'sizeof' in t:
        return True
    return False

hits = []
for f in bv.functions:
    try:
        hl = f.hlil
        if hl is None:
            continue
        for ins in hl.instructions:
            s = str(ins)
            mu = re.search(UNBOUNDED, s)
            if mu:
                a = args_of(s, mu.end() - 1)
                dst = (a[0].strip()[:30] if a else '')
                hits.append((f.name[:34], hex(ins.address), 'UNBOUNDED', mu.group(1), dst))
                continue
            mb = re.search(BOUNDED, s)
            if mb:
                callee = mb.group(1)
                a = args_of(s, mb.end() - 1)
                li = LEN_IDX.get(callee, 2)
                if len(a) <= li:
                    continue
                ln = a[li].strip()
                dst = a[0].strip()
                # interesting only if dest is a STACK buffer AND length is non-constant
                if is_stack_dst(dst) and not is_const_len(ln):
                    hits.append((f.name[:34], hex(ins.address), 'STACK', callee[:14], (dst[:18] + ' len=' + ln[:24])))
    except Exception:
        continue

seen = set(); uniq = []
for h in hits:
    k = (h[1], h[2], h[4])
    if k not in seen:
        seen.add(k); uniq.append(h)
# unbounded ops first (highest value), then stack-dest variable copies
uniq.sort(key=lambda h: (h[2] != 'UNBOUNDED',))
print("DANGEROUS-COPY candidates:", len(uniq), "(UNBOUNDED:", sum(1 for h in uniq if h[2]=='UNBOUNDED'), "STACK:", sum(1 for h in uniq if h[2]=='STACK'), ")")
for h in uniq[:160]:
    print("  %-36s %-10s %-9s %-14s %s" % (h[0], h[1], h[2], h[3], h[4]))
