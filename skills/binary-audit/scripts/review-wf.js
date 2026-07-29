export const meta = {
  name: 'kernel-fn-review',
  description: 'Contract-inference review: fan out the binary-audit-reviewer agent (one per function) over pre-extracted HLIL+asm -> precondition + suspected-bug records, self-captured to <root>/review-out/*.json',
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
          kind: { type: 'string', enum: ['len-bound', 'no-overflow', 'nonnull', 'range', 'signed', 'lock', 'lifetime', 'state', 'field-consistency', 'init-complete', 'nonzero-divisor'], description: "init-complete = every byte of a buffer written into ATTACKER-READABLE memory must be defined (the uninit-disclosure precondition); nonnull = a callee return / alloc / lookup checked before deref (the null-deref precondition); nonzero-divisor = an attacker-influenced divisor/modulus proven nonzero (the div-zero precondition)" },
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
        required: ['desc', 'location', 'confidence', 'bug_class', 'impact'],
        additionalProperties: false,
        properties: {
          desc: { type: 'string' },
          location: { type: 'string' },
          severity: { type: 'string' },
          confidence: { type: 'string', enum: ['low', 'med', 'high'] },
          why: { type: 'string' },
          bug_class: { type: 'string', enum: ['oob', 'int-overflow', 'double-fetch', 'uaf-lifetime', 'uninit-disclosure', 'uninit-use', 'null-deref', 'div-zero', 'type-confusion', 'race', 'logic', 'other'], description: 'the exploited-bug-class taxonomy: oob=plain bounds; int-overflow=size/offset arithmetic wrap/trunc/sign; double-fetch=TOCTOU re-read of attacker-shared memory; uaf-lifetime=use-after-free/dangling/double-free/refcount; uninit-disclosure=non-zeroed/partial buffer COPIED TO attacker; uninit-use=uninitialized value USED as a size/index/pointer (corruption, not leaked); null-deref=unchecked-NULL/failed-alloc/error-return dereference (controllable→corruption, else PSOD/crash); div-zero=attacker-controlled divisor/modulus, no nonzero guard (#DE); type-confusion=attacker/restored tag/handle/type field selects the wrong struct interpretation or handler; race=lock/refcount/2nd-vCPU concurrency; logic=NON-memory (command/path injection, file-op TOCTOU/symlink, privilege/credential/auth check) — esp. for privileged userworld processes' },
          impact: { type: 'string', enum: ['host-psod', 'host-rce', 'host-mem-corruption', 'guest-readable-leak', 'vmx-rce', 'vmx-crash', 'privesc', 'dos-other', 'none-or-guarded', 'unknown'], description: 'REQUIRED: the CONCRETE attacker-OBSERVABLE outcome if exploited — not the mechanism. State what the attacker actually gets: a host purple-screen (host-psod), ring-0 control (host-rce), a host write primitive (host-mem-corruption), bytes read back into the guest (guest-readable-leak), VMX-process control/corruption (vmx-rce), a VM crash (vmx-crash), privilege/credential gain (privesc), other DoS, or none-or-guarded if a runtime guard defeats it / the over-read is discarded. This is the field that separates a real finding from a static-loose-but-harmless one.' },
          leak_back: { type: 'string', enum: ['reaches-attacker', 'discarded', 'side-channel', 'n-a', 'unknown'], description: 'DISCLOSURE FILTER (for any read/uninit/over-read): does the disclosed data reach a buffer the attacker can read (reaches-attacker), get used only internally then discarded (discarded — NOT a leak, e.g. drives a validation/checksum), become observable only via timing/error-code (side-channel), or n-a for a write bug. A read/uninit with leak_back=discarded is not an info-leak.' },
          disclosure_source: { type: 'string', enum: ['stack', 'heap', 'register', 'padding', 'adjacent-object', 'n-a'], description: 'for a disclosure: where the leaked bytes come from. stack=return addresses (kASLR/.text), heap/adjacent-object=heap pointers, register=stale reg (often only low-32/opportunistic), padding=struct hole. n-a for non-disclosure.' },
          reachability: { type: 'string', enum: ['guest', 'userworld', 'rogue-peer', 'host-local', 'unknown'], description: 'THREAT-MODEL ORIGIN: which actor BOTH controls the input AND (for a leak) reads the output. guest=VM via device ring/MMIO/hypercall; userworld=the VMX/host process via UW syscall; rogue-peer=malicious remote/storage/network target; host-local=already-privileged host root. confirmed-violable means nothing until this is set — a userworld/host-local leak is not a guest escape.' },
          guarded_by: { type: 'string', description: 'if you judge the candidate GUARDED/refuted at runtime, the EXACT defusing check or instruction (+address): the memset/zero-fill, the exact-size overwrite, the 0xFF tail-fill, the bound clamp, or the copy-to-local that defeats a double-fetch. Record it even on refutation — a sibling path missing the same guard is the next lead.' },
        },
      },
    },
  },
}

const outpath = (f) => f.hlil.replace('/hlil/', '/review-out/').replace(/\.hlil\.c$/, '.json')
const PROMPT = (f) => `You are the binary-audit-reviewer. Review ONE function and follow your standard
contract-inference method, disclosure lens, bug-class taxonomy, and impact/reachability discipline.

TARGET: ${TARGET}
ATTACKER: ${ATTACKER}
CONTEXT (input provenance for this run): ${CONTEXT}

FUNCTION: ${f.name} @ ${f.addr}
Metrics: cyclomatic complexity ${f.cc}, computed-addressing ops ${f.memidx}, sink calls ${f.sink}, distinct input-offset reads ${f.parse}, ${f.insns} instructions.
${f.locality ? `Graph/locality (weak orientation only; the HLIL/asm + direct caller/callee facts are authoritative): ${JSON.stringify(f.locality)}` : ''}

READ BOTH with Read (the asm is authoritative for memory arithmetic; HLIL may truncate ~60KB on huge functions):
- HLIL: ${f.hlil}
- ASM:  ${f.asm}

OUT (write your finished record here as one JSON object, creating the dir if missing): ${outpath(f)}

Write the record to OUT AND return the identical object as your StructuredOutput call \u2014 both are required.`

phase('Review')
const results = await pipeline(
  FNS,
  (f) => agent(PROMPT(f), { label: `review:${f.name}`, phase: 'Review', schema: SCHEMA, agentType: 'binary-audit-reviewer' })
)
return results.filter(Boolean)
