export const meta = {
  name: 'kernel-guestentry-deepdive',
  description: 'Unbounded deep-dive on each exhausted-guest-entry lean: drive to confirmed-violable (with exact OOB math) or refuted',
  phases: [{ title: 'DeepDive', detail: 'resolve each guest-entry residual to a definitive verdict' }],
}
const TASKS = []

const SCHEMA = {
  type:'object', required:['target','verdict','evidence','confidence'], additionalProperties:false, properties:{
    target:{type:'string', description:'echo the task id (the consumer function)'},
    verdict:{type:'string', enum:['confirmed-violable','refuted','needs-live-poc','still-blocked-external'],
      description:'confirmed-violable=nailed the OOB op+math+guest input; refuted=the residual bound provably holds; needs-live-poc=unguarded path+guest control confirmed but exact magnitude needs a live test; still-blocked-external=a genuinely-external (non-this-binary) symbol blocks the call'},
    oob_primitive:{type:'string', description:'if violable/needs-poc: the exact unsafe op, the offset/index math, the buffer/allocation size, the max overrun magnitude, and read-vs-write'},
    guest_input:{type:'string', description:'the precise guest/target-controlled field(s) and the values that trigger it'},
    impact:{type:'string', description:'DoS(PSOD) / info-leak / OOB-write->potential-RCE, with reasoning'},
    functions_pulled:{type:'array', items:{type:'string'}},
    external_blocker:{type:'string', description:'if still-blocked-external: the exact symbol + what is needed to resolve'},
    evidence:{type:'string'}, confidence:{type:'string', enum:['low','med','high']},
  },
}

const PROMPT = (t) => `UNBOUNDED DEEP-DIVE (authorized ESXi 8.0.3i vmkernel pentest). This suspected bug already reached a GUEST/target-controlled origin UNCLAMPED through every function examined so far (verdict 'guest-entry' = leans violable). Your job is to CLOSE it: drive it to a DEFINITIVE verdict — confirmed-violable (with the exact OOB primitive) or refuted (the residual bound provably holds). NO depth limit — pull and reason about ALL functions needed.

CONSUMER (the flagged op): ${t.consumer.name}  — HLIL ${t.consumer.hlil} | ASM ${t.consumer.asm}
THE OPEN RESIDUAL (what blocks a definitive call): ${t.residual}
GUEST-REACHABLE PATH (from the prior audit): ${t.guest_path}

PROVIDED FUNCTIONS (consumer + chain + the residual functions named by the prior audit; asm authoritative):
${t.funcs.map(x=>`  - ${x.name}: HLIL ${x.hlil} | ASM ${x.asm}`).join('\n')}
${t.external.length? 'NAMED-BUT-NOT-EXTRACTED (likely external/imported — resolve by address with objdump if in-binary, else treat as external): '+t.external.join(', ') : ''}

DO:
1. Resolve the RESIDUAL precisely — read the residual functions; compute the actual bound (buffer/allocation size, the real length-field relationship e.g. LEN_18 vs LEN_2a, the callee's exact read/write width).
2. Compute the OOB MATH: max attacker-attainable offset/index vs the true backing-buffer size → the exact overrun magnitude and direction (read vs write). Confirm the guest fully controls the triggering field(s).
3. VERDICT:
   - confirmed-violable: you can state the unsafe op, the offset/size math, the max overrun, read/write, the guest input, and the impact. Fill oob_primitive + guest_input + impact.
   - refuted: the residual bound provably holds (e.g. LEN_18>=LEN_2a so the read stays in backing memory; or the callee re-bounds). Show it.
   - needs-live-poc: the unguarded path + guest control are confirmed but the exact magnitude/exploitability genuinely needs a live test — still a real candidate (the e1000-finding 'demonstrated trigger' bar). State what the PoC would do.
   - still-blocked-external: a genuinely-external symbol (not resolvable in this binary) is load-bearing — name it + what's needed.
RULES: rigorous + HONEST; anchor to HLIL lines / asm addrs; verbatim only; this is contract verification / impact-bounding, not weaponization. If you need an in-binary function not provided, you may run objdump on its address; name everything you pulled in functions_pulled.

Return the structured verdict (target = the consumer name).`

phase('DeepDive')
const results = await pipeline(TASKS, (t) => agent(PROMPT(t), { label:`deepdive:${t.consumer.name.slice(0,32)}`, phase:'DeepDive', schema:SCHEMA, agentType:'general-purpose' }))
return results.filter(Boolean)
