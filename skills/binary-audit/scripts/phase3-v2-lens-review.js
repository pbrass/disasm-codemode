export const meta = {
  name: 'phase3-v2-lens-review',
  description: 'Phase-3 kernel re-audit: apply the v2 lens (int-overflow / double-fetch / race / UAF / uninit-disclosure / type-confusion) to the vmxnet3+e1000 datapath and PVSCSI/VSCSI surfaces; adversarially verify candidates.',
  phases: [
    { title: 'Review', detail: 'one agent per target function, v2-class analysis' },
    { title: 'Verify', detail: 'adversarial verification of each candidate finding' },
  ],
}

const BIN = 'binaries/kcore/vmkernel_i' // EXAMPLE — set to your target ELF (see KAUDIT_BIN)
const TARGETS = [
  { name: 'Vmxnet3VMKDev_Tx',          start: '0x42000002b4574', end: '0x42000002b52bb', surface: 'vmxnet3 TX ring' },
  { name: 'Vmxnet3VMKDev_AsyncTx',     start: '0x42000002bdc8c', end: '0x42000002bdee2', surface: 'vmxnet3 TX ring' },
  { name: 'Vmxnet3VMKDevTxComplete',   start: '0x42000002afd94', end: '0x42000002b04a1', surface: 'vmxnet3 TX complete' },
  { name: 'Vmxnet3VMKDevRxFunc',       start: '0x42000002bb1e4', end: '0x42000002bc1ae', surface: 'vmxnet3 RX ring' },
  { name: 'Vmxnet3VMKDevRxWithLock',   start: '0x42000002b7d30', end: '0x42000002ba45e', surface: 'vmxnet3 RX ring (large)' },
  { name: 'E1000DevAsyncTx',           start: '0x420000256114', end: '0x420000258e7b', surface: 'e1000 TX ring parser' },
  { name: 'E1000DevTxCompleteOne',     start: '0x42000024ddf8', end: '0x42000024df80', surface: 'e1000 TX complete' },
  { name: 'PVSCSICompletion',          start: '0x42000065f9a0', end: '0x420000660517', surface: 'pvscsi completion ring' },
  { name: 'PVSCSIProcessRingWork',     start: '0x42000065f828', end: '0x42000065f9a0', surface: 'pvscsi request ring' },
  { name: 'VSCSI_IssueCommandBE',      start: '0x4200006652a0', end: '0x420000665442', surface: 'vscsi command issue' },
  { name: 'VSCSI_IssueIO',             start: '0x420000663fb4', end: '0x4200006640b6', surface: 'vscsi IO issue' },
]

const FIND_SCHEMA = {
  type: 'object',
  properties: {
    findings: { type: 'array', items: { type: 'object', properties: {
      pattern: { type: 'string', enum: ['int-overflow', 'double-fetch', 'race', 'uaf-lifetime', 'uninit-disclosure', 'type-confusion', 'other-oob', 'other'] },
      asm_addr: { type: 'string' }, description: { type: 'string' }, guest_input: { type: 'string' },
      severity: { type: 'string', enum: ['high', 'medium', 'low'] }, guest_reachable: { type: 'boolean' },
      confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    }, required: ['pattern', 'asm_addr', 'description', 'severity', 'confidence'] } },
    summary: { type: 'string' },
  }, required: ['findings', 'summary'],
}
const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['real-candidate', 'guarded', 'not-guest-reachable', 'false-positive'] },
    reasoning: { type: 'string' }, guard: { type: 'string' }, next_step: { type: 'string' },
  }, required: ['verdict', 'reasoning'],
}
const CTX = `You are auditing a single ESXi 8.0.3 vmkernel function for the bug classes that actually escape hypervisors (Pwn2Own 2024-2025: VMXNET3 int-overflow CVE-2025-41236, PVSCSI heap-overflow CVE-2025-41238, VMCI underflow CVE-2025-41237, USB UAF, TOCTOU CVE-2025-22224). Disassemble with: objdump -d --no-show-raw-insn --start-address=<start> --stop-address=<end> ${BIN}
Guest-controlled inputs: the guest writes the DMA ring descriptors (vmxnet3/e1000: per-descriptor buffer PA, length, flags, generation bit) and the PVSCSI/VSCSI SCSI request ring entries (CDB, data length, SG-element count/addresses). A second guest vCPU can MUTATE these in guest memory concurrently with the host reading them.
Analyze ONLY for guest-reachable corruption/disclosure/concurrency/lifetime v2 patterns; report concrete address-anchored findings (do NOT invent; if clean, return empty findings):
 (1) int-overflow: a guest field through imul/shl/add/sub into a Heap_Alloc/memcpy SIZE with the bound check on the wrapped/truncated value or absent => undersized alloc -> OOB write.
 (2) double-fetch/TOCTOU: the function LOADS THE SAME guest-memory location MORE THAN ONCE with a validation/branch between, WITHOUT copying it to a host local first => racing guest changes it between check and use. (Copied-once-to-local = NOT double-fetch.)
 (3) race: missing lock/refcount/serialization lets a concurrent guest-triggerable context mutate/free state across validation/use.
 (4) uaf-lifetime: Heap_Free/*_Destroy/refcount-dec then a use of that object.
 (5) uninit-disclosure: NON-zeroing Heap_Alloc, partial fill, then copy/DMA back to guest.
 (6) type-confusion: guest-controlled selector/state causes an object, descriptor, or command buffer to be interpreted with the wrong layout or handler.
Set guest_reachable precisely (guest ring write / SCSI request vs host-only path).`

phase('Review')
const reviews = await parallel(TARGETS.map(t => () =>
  agent(`${CTX}\n\nFUNCTION: ${t.name}  (${t.surface})\nstart=${t.start} end=${t.end}`,
    { label: `review:${t.name}`, phase: 'Review', schema: FIND_SCHEMA }).then(r => ({ target: t, r }))))

const cands = []
for (const x of reviews.filter(Boolean)) {
  if (!x.r || !x.r.findings) continue
  for (const f of x.r.findings) { if (f.guest_reachable === false) continue; cands.push({ fn: x.target.name, surface: x.target.surface, start: x.target.start, end: x.target.end, ...f }) }
}
log(`Review done: ${cands.length} guest-reachable candidates across ${TARGETS.length} functions`)

phase('Verify')
const verified = await parallel(cands.map(c => () =>
  agent(`You are an adversarial verifier. A prior pass flagged a possible ${c.pattern} bug in ESXi vmkernel ${c.fn} (${c.surface}) @ ${c.asm_addr}: "${c.description}" (guest_input: ${c.guest_input || 'n/a'}).
Re-disassemble: objdump -d --no-show-raw-insn --start-address=${c.start} --stop-address=${c.end} ${BIN}
Default to skepticism. Verdict: GUARDED (give the exact defusing check/clamp/copy-to-local addr — most static looseness here is guarded), NOT-GUEST-REACHABLE, FALSE-POSITIVE, or REAL-CANDIDATE (only if no guard AND guest controls input AND the primitive is genuine; give a concrete confirm/PoC next step).`,
    { label: `verify:${c.fn}:${c.pattern}`, phase: 'Verify', schema: VERDICT_SCHEMA }).then(v => ({ ...c, verdict: v }))))

const real = verified.filter(Boolean).filter(v => v.verdict && v.verdict.verdict === 'real-candidate')
const guarded = verified.filter(Boolean).filter(v => v.verdict && v.verdict.verdict === 'guarded')
return {
  reviewed: TARGETS.length, candidates: cands.length,
  real_candidates: real.map(r => ({ fn: r.fn, pattern: r.pattern, addr: r.asm_addr, sev: r.severity, desc: r.description, next: r.verdict.next_step })),
  guarded_count: guarded.length,
  guarded: guarded.map(g => ({ fn: g.fn, pattern: g.pattern, guard: g.verdict.guard })),
}
