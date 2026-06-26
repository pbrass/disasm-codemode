export const meta = {
  name: 'kernel-phase2-audit',
  description: 'Phase-2 contract audit: trace upstream lynchpins to decide if each suspected corruption/disclosure/race/lifetime bug is established-safe or violable',
  phases: [{ title: 'Audit', detail: 'one subagent per suspected bug -> established-safe | violable-bug | uncertain' }],
}

const TASKS = []

const SCHEMA = {
  type:'object', required:['target','verdict','evidence','confidence'], additionalProperties:false,
  properties:{
    target:{type:'string'},
    lynchpins_examined:{type:'array', items:{type:'string'}},
    verdict:{type:'string', enum:['established-safe','violable-bug','partial','uncertain'],
      description:'established-safe=precondition IS enforced upstream; violable-bug=NOT enforced and a guest can break it; partial=enforced on some paths only; uncertain=chain goes beyond provided functions'},
    evidence:{type:'string', description:'where the cap/reconciliation IS or ISNT, anchored to HLIL lines / asm addrs'},
    guest_reachable_path:{type:'string', description:'if violable: the guest-controlled path that violates the precondition'},
    residual_unknowns:{type:'string', description:'what could not be determined from the provided functions (callers higher up)'},
    recommended_next:{type:'string'},
    confidence:{type:'string', enum:['low','med','high']},
  },
}

const PROMPT = (t) => `You are doing PHASE-2 of an authorized ESXi 8.0.3i vmkernel security audit (active penetration test). Phase-1 flagged a SUSPECTED BUG in a function that ASSUMES a precondition it does not check itself. Your job: TRACE THE UPSTREAM/CALLER functions and decide whether that precondition is actually ESTABLISHED (safe) or VIOLABLE (a real guest->host bug).

SUSPECTED BUG (in ${t.consumer.name}): ${t.bug_desc}
WHY/REACHABILITY (phase-1 note): ${t.bug_why}
LOCATION: ${t.bug_location}
CALLER-OWED PRECONDITION(S) UNDER TEST:
${t.preconditions.map((p,i)=>`  ${i+1}. [${p.kind}] ${p.text}${p.attack_note? '  (attack note: '+p.attack_note+')':''}`).join('\n')}

READ THESE (use Read; asm is authoritative for arithmetic/bounds):
CONSUMER (the flagged function, for exactly what must hold):
  - ${t.consumer.name}: HLIL ${t.consumer.hlil} | ASM ${t.consumer.asm}
LYNCHPIN CALLER(S) — the upstream that must establish the precondition:
${t.lynchpins.length? t.lynchpins.map(x=>`  - ${x.name}: HLIL ${x.hlil} | ASM ${x.asm}`).join('\n') : '  (no direct callers extracted — say uncertain and name the entry point to pull)'}

METHOD:
1. In the consumer, pin down EXACTLY the precondition that must hold: offset/length/index and backing object for bounds bugs; single-fetch/copy-to-local for TOCTOU; ref/lock/lifetime discipline for UAF/race; initialization coverage for disclosure; or type discriminator/object layout for type confusion. Confirm it is genuinely guest-influenced or guest-triggerable, not a hardware-fixed constant.
2. In the caller(s), find where that value/state is produced/validated: clamped/checked, copied to a stable host local, ref-held/locked, initialized, type-checked, derived from a fixed constant, or passed through from guest bytes/state unmodified?
3. Verdict: established-safe / violable-bug / partial / uncertain. If the establishing check lives ABOVE the provided callers, say 'uncertain' and NAME the next function to pull — do NOT assume safe.
4. If violable-bug: state the concrete guest input and the path that breaks the precondition.

RULES: rigorous and HONEST — default for an unproven precondition is 'uncertain', not 'safe' and not 'bug'. Anchor evidence to HLIL lines / asm addrs. This is corruption/disclosure/race/lifetime contract verification, not exploit development.

Return the structured verdict.`

phase('Audit')
const results = await pipeline(TASKS, (t) => agent(PROMPT(t), { label:`audit:${t.id}`, phase:'Audit', schema:SCHEMA, agentType:'general-purpose' }))
return results.filter(Boolean)
