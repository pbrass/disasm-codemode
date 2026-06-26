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
          kind: { type: 'string', enum: ['len-bound', 'no-overflow', 'nonnull', 'range', 'signed', 'lock', 'lifetime', 'state', 'field-consistency'] },
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
          bug_class: { type: 'string', enum: ['oob', 'int-overflow', 'double-fetch', 'uaf-lifetime', 'uninit-disclosure', 'race', 'type-confusion', 'other'], description: 'the exploited-bug-class taxonomy (v2): oob=plain bounds, int-overflow=size/offset arithmetic wrap, double-fetch=TOCTOU on re-read of attacker memory, uaf-lifetime=use-after-free/dangling, uninit-disclosure=non-zeroed alloc leaked back, race=lock/refcount discipline, type-confusion' },
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
2. CONTRACT INFERENCE: for EVERY memory access with a computed index/offset, and EVERY sink call (memcpy/memmove/memset/str*/*_Alloc/Pkt_* with a non-constant size), ask: "what must be TRUE for this to be safe against guest-reachable corruption/disclosure/race/lifetime bugs?" Each answer is a PRECONDITION. Systematically cover: index/length in-bounds; integer overflow/truncation in size or offset arithmetic; signedness (a signed value feeding a size/index); non-NULL; object-still-alive (UAF); lock-held (race/TOCTOU); and FIELD-CONSISTENCY (one guest field implying a bound on another — e.g. a length/offset/count/IHL/hdr-len header field used to index without being reconciled against the actual buffer size). The e1000 TSO bug in this same codebase was exactly a field-consistency precondition (guest IHL not reconciled with the descriptor header length) that was caller-owed and unchecked.
3. CLASSIFY each precondition: 'self' = the function validates it itself; 'caller' = it is assumed and some caller must establish it; 'unguaranteed' = nothing obviously establishes it. caller + unguaranteed = the attack surface.
4. DESK-CHECK the body for: OOB read/write, integer overflow/truncation, off-by-one, UAF, double-free, TOCTOU/race, uninitialized read, type confusion, error-path cleanup, unchecked return values.

RULES:
- Be rigorous and HONEST. Do NOT invent bugs. If a bound is checked upstream-but-not-here, record it as a 'caller' precondition, not a bug. Prefer verdict 'needs-caller-analysis' over a speculative 'bug'.
- Anchor EVERY precondition and suspected bug to a specific HLIL line number or asm address.
- For suspected_bugs include ONLY items with (a) a concrete unsafe operation or primitive (memory operation, disclosure, race/lifetime, or type confusion) and (b) a plausible guest-reachable input that violates a precondition; set confidence honestly, and set bug_class to the exploited-class taxonomy (oob / int-overflow / double-fetch / uaf-lifetime / uninit-disclosure / race / type-confusion / other) — this is not limited to plain bounds errors.
- For a giant function, focus on the memory-op / sink / computed-index hotspots rather than narrating every block.

Return the structured record (your StructuredOutput call IS the deliverable).`

phase('Review')
const results = await pipeline(
  FNS,
  (f) => agent(PROMPT(f), { label: `review:${f.name}`, phase: 'Review', schema: SCHEMA, agentType: 'general-purpose' })
)
return results.filter(Boolean)
