export const meta = {
  name: 'kernel-guestentry-deepdive',
  description: 'Unbounded deep-dive on each exhausted-guest-entry lean: drive to confirmed-violable with an exact unsafe primitive, or refuted',
  phases: [{ title: 'DeepDive', detail: 'resolve each guest-entry residual to a definitive verdict' }],
}
const TASKS = []

const SCHEMA = {
  type:'object', required:['target','verdict','evidence','confidence'], additionalProperties:false, properties:{
    target:{type:'string', description:'echo the task id (the consumer function)'},
    verdict:{type:'string', enum:['confirmed-violable','refuted','needs-live-poc','still-blocked-external'],
      description:'confirmed-violable=nailed the unsafe primitive + guest input; refuted=the residual precondition provably holds; needs-live-poc=unguarded path+guest control confirmed but exact impact needs a live test; still-blocked-external=a genuinely-external (non-this-binary) symbol blocks the call'},
    unsafe_primitive:{type:'string', description:'if violable/needs-poc: the exact primitive, e.g. offset/index math and read/write direction; double-fetch race window; UAF/ref/lock violation; disclosure source/size; or type-confusion object/layout mismatch'},
    oob_primitive:{type:'string', description:'legacy alias for unsafe_primitive; use unsafe_primitive for new results'},
    guest_input:{type:'string', description:'the precise guest/target-controlled field(s) and the values that trigger it'},
    impact:{type:'string', description:'DoS(PSOD) / info-leak / OOB-write->potential-RCE, with reasoning'},
    functions_pulled:{type:'array', items:{type:'string'}},
    external_blocker:{type:'string', description:'if still-blocked-external: the exact symbol + what is needed to resolve'},
    evidence:{type:'string'}, confidence:{type:'string', enum:['low','med','high']},
  },
}

const PROMPT = (t) => `UNBOUNDED DEEP-DIVE (authorized ESXi 8.0.3i vmkernel pentest). This suspected bug already reached a GUEST/target-controlled origin UNCLAMPED through every function examined so far (verdict 'guest-entry' = leans violable). Your job is to CLOSE it: drive it to a DEFINITIVE verdict — confirmed-violable (with the exact unsafe primitive) or refuted (the residual precondition provably holds). NO depth limit — pull and reason about ALL functions needed.

CONSUMER (the flagged op): ${t.consumer.name}  — HLIL ${t.consumer.hlil} | ASM ${t.consumer.asm}
THE OPEN RESIDUAL (what blocks a definitive call): ${t.residual}
GUEST-REACHABLE PATH (from the prior audit): ${t.guest_path}

PROVIDED FUNCTIONS (consumer + chain + the residual functions named by the prior audit; asm authoritative):
${t.funcs.map(x=>`  - ${x.name}: HLIL ${x.hlil} | ASM ${x.asm}`).join('\n')}
${t.external.length? 'NAMED-BUT-NOT-EXTRACTED (likely external/imported — resolve by address with objdump if in-binary, else treat as external): '+t.external.join(', ') : ''}

DO:
1. Resolve the RESIDUAL precisely — read the residual functions; compute the actual bound or guard: backing buffer/allocation size and read/write width; stable-copy vs double-fetch; ref/lock lifetime across use; initialization coverage before copy-out/DMA; or type discriminator/object-layout validation.
2. Compute the UNSAFE PRIMITIVE: max attacker-attainable offset/index vs backing size for OOB; the exact guest-memory re-read race window for double-fetch; the free/ref/drop path and later use for UAF/race; the uninitialized bytes exposed; or the mismatched type/layout used. Confirm the guest fully controls or can trigger the field/state.
3. VERDICT:
   - confirmed-violable: you can state the unsafe primitive, the guest input/state, and the impact. Fill unsafe_primitive + guest_input + impact.
   - refuted: the residual precondition provably holds (e.g. LEN_18>=LEN_2a so the read stays in backing memory; the callee re-bounds; the guest value is copied once to host memory; the ref/lock is held; exposed bytes are initialized; or the type is checked). Show it.
   - needs-live-poc: the unguarded path + guest control are confirmed but the exact magnitude/exploitability genuinely needs a live test — still a real candidate (the e1000-finding 'demonstrated trigger' bar). State what the PoC would do.
   - still-blocked-external: a genuinely-external symbol (not resolvable in this binary) is load-bearing — name it + what's needed.
RULES: rigorous + HONEST; anchor to HLIL lines / asm addrs; verbatim only; this is contract verification / impact-bounding, not weaponization. If you need an in-binary function not provided, you may run objdump on its address; name everything you pulled in functions_pulled.

Return the structured verdict (target = the consumer name).`

phase('DeepDive')
const results = await pipeline(TASKS, (t) => agent(PROMPT(t), { label:`deepdive:${t.consumer.name.slice(0,32)}`, phase:'DeepDive', schema:SCHEMA, agentType:'general-purpose' }))
return results.filter(Boolean)
