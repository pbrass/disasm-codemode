import binaryninja, re
bv = binaryninja.load("BNDBPATH", update_analysis=False)
ALLOC = r'(operator new|\bmalloc|\bcalloc|\brealloc|[A-Za-z_]*Alloc[A-Za-z_]*|_M_default_append)\s*\('
COPY  = r'([A-Za-z_]*[Mm]em(cpy|move)[A-Za-z_]*|bcopy|_vmk_Memcpy)\s*\('

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

def overflowy(expr, _re=re):
    # multiply: a '*' that has a LEFT operand (word/paren/bracket before it) — excludes a leading
    # dereference like *(arg2) / *arg2 where '*' is preceded by '(' or ',' or start-of-expr.
    if _re.search(r'[\w\)\]]\s*\*\s*[A-Za-z0-9_(]', expr):
        return True
    # shift-left by/of a variable (deref-left is fine here: *arg3 << 3 is a real scaling overflow)
    if _re.search(r'[\w\)\]]\s*<<', expr):
        return True
    # addition of two-or-more variable terms (not pure constants)
    if ('+' in expr) and (len(_re.findall(r'[a-zA-Z_]\w*', expr)) >= 2) and ('0x' not in expr):
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
            ma = re.search(ALLOC, s); mc = re.search(COPY, s)
            if ma:
                a = args_of(s, ma.end() - 1); sz = a[0].strip() if a else ''
                if sz and overflowy(sz):
                    hits.append((f.name[:38], hex(ins.address), 'ALLOC', ma.group(1)[:18], sz[:58]))
            elif mc:
                a = args_of(s, mc.end() - 1); sz = (a[2].strip() if len(a) >= 3 else (a[-1].strip() if a else ''))
                if sz and overflowy(sz):
                    hits.append((f.name[:38], hex(ins.address), 'COPY', mc.group(1)[:18], sz[:58]))
    except Exception:
        continue

seen = set(); uniq = []
for h in hits:
    k = (h[1], h[4])
    if k not in seen:
        seen.add(k); uniq.append(h)
print("INTOF candidate hits:", len(uniq))
for h in uniq[:140]:
    print("  %-36s %-10s %-5s %-18s sz=%s" % (h[0], h[1], h[2], h[3], h[4]))
