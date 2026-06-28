export const meta = {
  name: 'kernel-fn-review',
  description: 'Contract-inference review of 25 guest-reachable memory corruption/disclosure and v2 race/lifetime candidates -> precondition ledger records',
  phases: [{ title: 'Review', detail: 'one subagent per function: HLIL+asm -> preconditions (self/caller/unguaranteed) + suspected bugs' }],
}

const FNS = []   // filled by prep_batch.py
const TARGET = 'the ESXi 8.0.3i vmkernel (ring-0 hypervisor)'   // swapped by prep_batch from profile.review_target
const ATTACKER = 'malicious guest VM'                            // swapped from profile.review_attacker
const CONTEXT = 'this is in the guest->host virtual-NIC datapath (Vmxnet3 / E1000 / ENS), so its inputs are largely GUEST-CONTROLLED — TX/RX ring descriptors, packet header bytes, lengths, offsets, counts, MSS/IHL/segment fields.'   // swapped from profile.review_context

const SCHEMA = {
  type: 'object',
  required: ['function', 'verdict', 'summary', 'preconditions'],
  additionalProperties: false,
  properties: {
    function: { type: 'string' },
    verdict: { type: 'string', enum: ['clean', 'needs-caller-analysis', 'suspicious', 'bug'] },
    summary: { type: 'string', description: 'what it does + input provenance, 1-3 sentences' },
    preconditions: {
      type: 'array',
      items: {
        type: 'object',
        required: ['text', 'kind', 'klass'],
        additionalProperties: false,
        properties: {
          text: { type: 'string' },
          kind: { type: 'string', enum: ['len-bound', 'no-overflow', 'nonnull', 'range', 'signed', 'lock', 'lifetime', 'state', 'field-consistency', 'init-complete'], description: "init-complete = every byte of a buffer written into ATTACKER-READABLE memory must be defined (zero-filled or fully overwritten) — the uninitialized-disclosure precondition" },
          klass: { type: 'string', enum: ['self', 'caller', 'unguaranteed'] },
          sink: { type: 'string' },
          attack_note: { type: 'string' },
        },
      },
    },
    suspected_bugs: {
      type: 'array',
      items: {
        type: 'object',
        required: ['desc', 'location', 'confidence', 'bug_class'],
        additionalProperties: false,
        properties: {
          desc: { type: 'string' },
          location: { type: 'string' },
          severity: { type: 'string' },
          confidence: { type: 'string', enum: ['low', 'med', 'high'] },
          why: { type: 'string' },
          bug_class: { type: 'string', enum: ['oob', 'int-overflow', 'double-fetch', 'uaf-lifetime', 'uninit-disclosure', 'race', 'type-confusion', 'other'], description: 'the exploited-bug-class taxonomy (v2): oob=plain bounds, int-overflow=size/offset arithmetic wrap, double-fetch=TOCTOU on re-read of attacker memory, uaf-lifetime=use-after-free/dangling, uninit-disclosure=non-zeroed/partially-filled buffer copied to attacker, race=lock/refcount discipline, type-confusion' },
          leak_back: { type: 'string', enum: ['reaches-attacker', 'discarded', 'side-channel', 'n-a', 'unknown'], description: 'DISCLOSURE FILTER (for any read/uninit/over-read): does the disclosed data reach a buffer the attacker can read (reaches-attacker), get used only internally then discarded (discarded — NOT a leak, e.g. drives a validation/checksum), become observable only via timing/error-code (side-channel), or n-a for a write bug. A read/uninit with leak_back=discarded is not an info-leak.' },
          disclosure_source: { type: 'string', enum: ['stack', 'heap', 'register', 'padding', 'adjacent-object', 'n-a'], description: 'for a disclosure: where the leaked bytes come from. stack=return addresses (kASLR/.text), heap/adjacent-object=heap pointers, register=stale reg (often only low-32/opportunistic), padding=struct hole. n-a for non-disclosure.' },
          reachability: { type: 'string', enum: ['guest', 'userworld', 'rogue-peer', 'host-local', 'unknown'], description: 'THREAT-MODEL ORIGIN: which actor BOTH controls the input AND (for a leak) reads the output. guest=VM via device ring/MMIO/hypercall; userworld=the VMX/host process via UW syscall; rogue-peer=malicious remote/storage/network target; host-local=already-privileged host root. confirmed-violable means nothing until this is set — a userworld/host-local leak is not a guest escape.' },
          guarded_by: { type: 'string', description: 'if you judge the candidate GUARDED/refuted at runtime, the EXACT defusing check or instruction (+address): the memset/zero-fill, the exact-size overwrite, the 0xFF tail-fill, the bound clamp, or the copy-to-local that defeats a double-fetch. Record it even on refutation — a sibling path missing the same guard is the next lead.' },
        },
      },
    },
  },
}

const PROMPT = (f) => `You are auditing ONE function of ${TARGET} for guest-reachable memory corruption, disclosure, TOCTOU/race, lifetime/UAF, and type-confusion bugs reachable from a ${ATTACKER}. This is authorized defensive vulnerability research (an active, scoped penetration test / patch-diff assessment).

FUNCTION: ${f.name} @ ${f.addr}
Metrics: cyclomatic complexity ${f.cc}, computed-addressing ops ${f.memidx}, sink calls ${f.sink}, distinct input-offset reads ${f.parse}, ${f.insns} instructions.
Context: ${CONTEXT}
${f.locality ? `Graph/locality context for this stripped-binary target: ${JSON.stringify(f.locality, null, 2)}
Use this as weak orientation evidence only. Nearest named address neighbors and graph-boundary callers/callees can identify a family, but the HLIL/asm and direct caller/callee facts are authoritative for bug claims.` : ''}

READ BOTH (use Read; the asm is authoritative for memory arithmetic):
- HLIL (decompiled, register-agnostic): ${f.hlil}   (NOTE: may be truncated at ~60KB if the function is huge — use the asm for any part the HLIL cuts off)
- ASM (complete disassembly): ${f.asm}

METHODOLOGY — contract inference:
1. ORIENT: what the function does; its parameters/globals and the PROVENANCE of each (guest-controlled vs kernel-internal vs validated-upstream).
2. CONTRACT INFERENCE: for EVERY memory access with a computed index/offset, and EVERY sink call (memcpy/memmove/memset/str*/*_Alloc/Pkt_* with a non-constant size), ask: "what must be TRUE for this to be safe against guest-reachable corruption/disclosure/race/lifetime bugs?" Each answer is a PRECONDITION. Systematically cover: index/length in-bounds; integer overflow/truncation in size or offset arithmetic; signedness (a signed value feeding a size/index); non-NULL; object-still-alive (UAF); lock-held (race/TOCTOU); FIELD-CONSISTENCY (one guest field implying a bound on another — e.g. a length/offset/count/IHL/hdr-len header field used to index without being reconciled against the actual buffer size; the e1000 TSO bug here was exactly that, caller-owed and unchecked); and INITIALIZATION-COMPLETENESS (kind 'init-complete').
   ── THE DISCLOSURE LENS (run this on EVERY write of a struct/buffer into ATTACKER-READABLE memory — a guest RX/CQ/completion ring or descriptor, a response/reply/SG-copy-back buffer, a datagram, a shared page, a CopyOut/SgCopyTo destination): is EVERY byte defined before it becomes attacker-visible? The uninit-disclosure recipe is: a NON-zeroing allocator (Heap_Alloc / *_AllocKernelMem / Mem_Alloc with NO following memset, vs a zeroing Heap_AllocZ/kzalloc) → partial or conditional field population (reserved/padding fields, error/short-path fields left unset, a union only partly written) → copy/DMA/store back to the attacker. ALSO flag a copy whose LENGTH exceeds the initialized portion of the source (a guest-controlled length clamped only against the destination size, not the source's valid-byte count — e.g. SgCopyTo(dst,&stackbuf,guestLen) where stackbuf holds <guestLen valid bytes). Leaked stack bytes = return addresses (.text pointers → kASLR); leaked heap/adjacent-object bytes = heap pointers. A single kernel pointer reaching the guest defeats kASLR and unblocks every write primitive — so disclosure is HIGH value even when it is "only a read."
3. CLASSIFY each precondition: 'self' = the function validates it itself; 'caller' = it is assumed and some caller must establish it; 'unguaranteed' = nothing obviously establishes it. caller + unguaranteed = the attack surface.
4. DESK-CHECK the body for: OOB read/write, integer overflow/truncation, off-by-one, UAF, double-free, TOCTOU/race, uninitialized-disclosure (per the lens above), type confusion, error-path cleanup, unchecked return values. For ANY read / over-read / uninitialized field you flag, you MUST classify two things or it is not actionable: (a) LEAK-BACK — does the data reach the attacker (reaches-attacker) or is it consumed internally and discarded (e.g. it only drives a checksum/validation/length decision → NOT a leak)? An OOB read whose result is discarded is at most a fault/DoS, not an info-leak. (b) REACHABILITY — which actor BOTH supplies the input AND reads the output: a guest VM, the userworld VMX process, a rogue remote/storage peer, or already-privileged host-local root. A leak readable only by the userworld or host-local root is NOT a guest escape.
5. RECORD THE GUARD even on refutation. If a candidate is actually defused at runtime, set guarded_by to the EXACT instruction/address: the memset/zero-fill before populate, the exact-size full overwrite (every byte stored), the deliberate 0xFF/0x00 tail-fill, the bound clamp, or the copy-to-local that kills a double-fetch. (In this codebase the guest-facing completion paths — vmxnet3 RCD, PVRDMA CQE, vmci datagram delivery — are systematically zero-filled / exact-overwritten / 0xFF-tail-padded, so most disclosure candidates on guest device rings refute; confirming that with the guard address is a real deliverable, and a sibling path MISSING the same guard is the next lead.)

RULES:
- Be rigorous and HONEST. Do NOT invent bugs. If a bound is checked upstream-but-not-here, record it as a 'caller' precondition, not a bug. Prefer verdict 'needs-caller-analysis' over a speculative 'bug'.
- Anchor EVERY precondition and suspected bug to a specific HLIL line number or asm address.
- For suspected_bugs include ONLY items with (a) a concrete unsafe operation or primitive (memory operation, disclosure, race/lifetime, or type confusion) and (b) a plausible guest-reachable input that violates a precondition; set confidence honestly, and set bug_class to the exploited-class taxonomy (oob / int-overflow / double-fetch / uaf-lifetime / uninit-disclosure / race / type-confusion / other) — this is not limited to plain bounds errors.
- ALWAYS set 'reachability' on every suspected_bug (guest / userworld / rogue-peer / host-local / unknown) — a finding's threat-model is part of the finding, not an afterthought. For any disclosure/read bug ALSO set 'leak_back' and 'disclosure_source'; a uninit-disclosure with leak_back=discarded or reachability=host-local is downgraded, not a guest escape. If you refute or judge a candidate guarded, still emit it with low confidence + 'guarded_by' set to the defusing address (that record is the honest deliverable and the calibration signal).
- For a giant function, focus on the memory-op / sink / computed-index hotspots rather than narrating every block.

Return the structured record (your StructuredOutput call IS the deliverable).`

phase('Review')
const results = await pipeline(
  FNS,
  (f) => agent(PROMPT(f), { label: `review:${f.name}`, phase: 'Review', schema: SCHEMA, agentType: 'general-purpose' })
)
return results.filter(Boolean)
