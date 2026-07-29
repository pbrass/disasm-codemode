import binaryninja, re
bv = binaryninja.load("BNDBPATH", update_analysis=False)
# Heap OOB candidate: within a function, a buffer is allocated with size A (buf = alloc(A)), then a
# copy/write into buf uses size B where B's expression DIFFERS from A (potential B>A => OOB).
# Tune ALLOC/COPY for your target's allocator/copy naming (the catch-all *Alloc*/*Mem*cpy* covers most).
ALLOC = r'=\s*(operator new|malloc|calloc|realloc|kmalloc|kcalloc|vmalloc|kmem_alloc|[A-Za-z_]*[Aa]lloc[A-Za-z_]*)\s*\('
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

def lhs_var(s, _re=re):
    # the variable being assigned: last identifier before the first top-level ' = '
    eq = s.find(' = ')
    if eq < 0:
        return None
    lhs = s[:eq]
    ids = _re.findall(r'[A-Za-z_]\w*', lhs)
    return ids[-1] if ids else None

def size_arg(name, a, _re=re):
    # pick the SIZE argument by allocator calling convention:
    #   Heap_Alloc(heap, size) / vmk_Heap*(heap, size) / realloc(ptr, size) -> arg1
    #   calloc(n, size) -> arg1 (element size; n*size mismatch handled separately)
    #   malloc/operator new/internal *Alloc* wrappers -> arg0
    # returns the size expr string, or None.
    if not a:
        return None
    if (_re.search(r'Heap', name) or 'realloc' in name or 'calloc' in name) and len(a) >= 2:
        return a[1]
    return a[0]

def norm(e, _re=re):
    return _re.sub(r'\s+', '', e or '')

hits = []
for f in bv.functions:
    try:
        hl = f.hlil
        if hl is None:
            continue
        allocs = {}   # var -> (size_expr_norm, addr, raw_size)
        for ins in hl.instructions:
            s = str(ins)
            ma = re.search(ALLOC, s)
            if ma:
                v = lhs_var(s)
                a = args_of(s, ma.end() - 1)
                sz = size_arg(ma.group(1), a)
                if v and sz is not None:
                    allocs[v] = (norm(sz), hex(ins.address), sz.strip()[:40])
            mc = re.search(COPY, s)
            if mc:
                a = args_of(s, mc.end() - 1)
                if len(a) >= 3:
                    dst = a[0]; ln = a[2].strip()
                    dst_ids = re.findall(r'[A-Za-z_]\w*', dst)
                    for v in dst_ids:
                        if v in allocs and norm(ln) != allocs[v][0] and ln and ('0x' not in ln[:3]):
                            hits.append((f.name[:34], hex(ins.address), v[:14], allocs[v][2], ln[:34]))
                            break
    except Exception:
        continue

seen = set(); uniq = []
for h in hits:
    k = (h[1], h[4])
    if k not in seen:
        seen.add(k); uniq.append(h)
print("HEAP alloc/copy size-mismatch candidates:", len(uniq))
for h in uniq[:140]:
    print("  %-32s %-10s buf=%-14s alloc=%-22s copylen=%s" % (h[0], h[1], h[2], h[3], h[4]))
