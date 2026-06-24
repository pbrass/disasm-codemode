export const meta = {
  name: 'kernel-decider-round',
  description: 'Iterative-deepening decider audit: resolve each uncertain bug by auditing its named upstream decider',
  phases: [{ title: 'Decide', detail: 'one subagent per (bug, decider) pair -> established-safe | violable-bug | partial | uncertain(names next)' }],
}
const TASKS = []

const SCHEMA={type:'object',required:['target','verdict','evidence','confidence'],additionalProperties:false,properties:{
  target:{type:'string',description:'echo the task id verbatim'},lynchpins_examined:{type:'array',items:{type:'string'}},
  verdict:{type:'string',enum:['established-safe','violable-bug','guest-entry','uncertain-continue','uncertain-external','partial']},
  evidence:{type:'string'},guest_reachable_path:{type:'string'},residual_unknowns:{type:'string'},
  recommended_next:{type:'string',description:'ONLY for uncertain-continue: the SINGLE next IN-KERNEL vmkernel function symbol to pull (bare name)'},confidence:{type:'string',enum:['low','med','high']}}}

const PROMPT=(t)=>`PHASE-2 DECIDER audit (authorized ESXi 8.0.3i vmkernel pentest). A prior trace returned UNCERTAIN on a suspected bug and named THIS function as the decider. Determine whether it establishes the bound (established-safe), fails to (violable-bug), or itself defers upstream (uncertain → name the next).

TASK ID (echo as 'target'): ${t.id}
SUSPECTED BUG (consumer ${t.consumer.name}): ${t.bug_desc}
PRECONDITION UNDER TEST: ${t.precondition}
QUESTION: Does ${t.decider.name} establish that precondition for ${t.consumer.name}?

READ (Read tool; asm authoritative):
DECIDER: ${t.decider.name}: HLIL ${t.decider.hlil} | ASM ${t.decider.asm}
CONSUMER (the exact bound that must hold): ${t.consumer.name}: HLIL ${t.consumer.hlil} | ASM ${t.consumer.asm}

Trace the guest/target value through the decider to the consumer's use. Choose the verdict precisely — these are distinguished on purpose:
- established-safe: this function (or one it provably calls) clamps/bounds the value, or it's a fixed constant. The bug cannot fire.
- violable-bug: you can point to the concrete unsafe op AND a guest/target input that reaches it unclamped — a clean confirmed bug. Set guest_reachable_path.
- guest-entry: you traced the value to its GUEST/target-controlled ORIGIN (a guest TX/RX ring descriptor, DMA/bounce buffer, shared-region field, or driver-supplied count/length/offset) and found NO clamp anywhere in the chain you examined. The precondition is owed to the attacker → it leans violable, but you stopped at the input boundary rather than nailing the final exploit primitive. Set guest_reachable_path. DO NOT call this 'uncertain'.
- uncertain-continue: a real IN-KERNEL vmkernel function ABOVE this one might still clamp it — set recommended_next to that SINGLE bare vmkernel symbol. Use this ONLY when the next thing to check is analyzable kernel code, not guest/external code.
- uncertain-external: the deciding code is an EXTERNAL / library / non-vmkernel-symbol function you cannot analyze from this binary (e.g. a *_RA tail-call, an imported routine) — genuinely undecidable here. Name it in residual_unknowns, leave recommended_next empty.
- partial: clamped on some paths only.
Anchor to HLIL lines / asm addrs. Contract verification, not exploit-dev.

Return the structured verdict (set target to the TASK ID above).`

phase('Decide')
const results=await pipeline(TASKS,(t)=>agent(PROMPT(t),{label:`decide:${t.id.slice(0,40)}`,phase:'Decide',schema:SCHEMA,agentType:'general-purpose'}))
return results.filter(Boolean)
