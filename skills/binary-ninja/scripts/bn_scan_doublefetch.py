import binaryninja, re
bv = binaryninja.load("BNDBPATH", update_analysis=False)
# DOUBLE-FETCH / TOCTOU scanner (RC). Signal: the SAME dereference of attacker memory
# *(argN + off) (or through an attacker pointer) is read 2+ times in one function, with at least
# one read in a CHECK context (comparison/bound) and at least one in a USE context (copy len, index,
# arithmetic, assignment). On a shared/DMA/packet buffer the value can change between the check and the
# use => TOCTOU (F2/F3 class). Heuristic + noisy by nature: flag-generously, triage every hit.
# raw pattern strings (BN sandbox forbids re.compile) — used via re.finditer/re.search
DEREF = r'\*\(\s*((?:\*\([^()]*\)|[A-Za-z_]\w*)(?:\s*\+\s*[A-Za-z0-9_]+(?:\s*[*<]+\s*[A-Za-z0-9_]+)?)?)\s*\)'
CMP   = r'(?:\bif\b|[<>]=?|==|!=|\bu[<>]=?\b)'
# attacker-memory base: an argument, or a read through a pointer (*(*(...)), or arg-derived
def attacker_base(inner, _re=re):
    return ('arg' in inner) or inner.startswith('*(') or bool(_re.search(r'\barg\d', inner))

def norm(e, _re=re):
    e = _re.sub(r'\b(zx|sx)\.[a-z]\b', '', e)   # strip width-extend casts
    return _re.sub(r'\s+', '', e)

hits = []
for f in bv.functions:
    try:
        hl = f.hlil
        if hl is None:
            continue
        # expr -> {'check':[addrs], 'use':[addrs]}
        seen = {}
        for ins in hl.instructions:
            s = str(ins)
            is_check = bool(re.search(CMP, s))
            for m in re.finditer(DEREF, s):
                inner = m.group(1)
                if not attacker_base(inner):
                    continue
                key = norm(inner)
                if key not in seen:
                    seen[key] = {'check': [], 'use': [], 'raw': inner.strip()[:40]}
                # an instruction that is a comparison => the deref participates in a check;
                # otherwise it's a use (copy/index/arith/assign)
                bucket = 'check' if is_check else 'use'
                if hex(ins.address) not in seen[key][bucket]:
                    seen[key][bucket].append(hex(ins.address))
        for key, d in seen.items():
            nchk, nuse = len(d['check']), len(d['use'])
            # require at least one check AND one use, total >=2 reads, of attacker memory
            if nchk >= 1 and nuse >= 1 and (nchk + nuse) >= 2:
                hits.append((f.name[:34], d['raw'], nchk, nuse,
                             (d['check'][:1] + d['use'][:1])))
    except Exception:
        continue

# rank: more total reads first
hits.sort(key=lambda h: -(h[2] + h[3]))
print("DOUBLE-FETCH / TOCTOU candidates:", len(hits))
for h in hits[:160]:
    print("  %-34s deref=%-30s chk=%d use=%d  @ %s" % (h[0], h[1], h[2], h[3], ",".join(h[4])))
