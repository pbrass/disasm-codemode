#!/usr/bin/env python3
"""make_wf.py — turn a prep batch.json into a self-contained naming Workflow script (.wf.js).

Workflow scripts have no filesystem access, so the batch (evidence + HLIL) is embedded as a JSON literal.
One agent per function proposes a VMware-style name + role comment + confidence (+ optional prototype) from
the function's HLIL and evidence. The script returns the array of results; capture it and feed bn-sym-ingest.

  bn-sym-makewf phil_notes/vmx-re/batch1.json --out phil_notes/vmx-re/batch1.wf.js
  # then:  Workflow(scriptPath="phil_notes/vmx-re/batch1.wf.js")  -> save result -> bn-sym-ingest
"""
import sys, os, json, argparse

TEMPLATE = r'''export const meta = {
  name: 'symbolicate-name',
  description: 'Propose VMware-style names + role comments for stripped vmx functions from HLIL + evidence',
  phases: [{ title: 'Name', detail: 'one agent per function' }],
}

const BATCH = __BATCH__;

const NAME_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    name: { type: 'string', description: 'VMware-style identifier: ModuleCamelCase or Module_Verb (e.g. Vmxnet3DoTx, SVGA_LoadConfig). No spaces. Leave EMPTY ("") to ABSTAIN when evidence is insufficient.' },
    comment: { type: 'string', description: '1-3 sentence role/analysis note. Mention guest-controlled input or notable memory ops if visible. If abstaining, briefly say why (e.g. "thin evidence; revisit after callers named").' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low', 'none'], description: 'Use "none" to ABSTAIN (no name yet).' },
    proto: { type: 'string', description: 'Optional C prototype, or empty string.' },
  },
  required: ['name', 'comment', 'confidence'],
}

function buildPrompt(rec) {
  const strings = (rec.strings || []).map(s => '  - ' + s).join('\n') || '  (none)'
  const callees = (rec.named_callees || []).join(', ') || '(none)'
  const callers = (rec.named_callers || []).join(', ') || '(none)'
  const domain = (rec.domain || []).join(', ') || '(none)'
  return [
    'You are reverse-engineering a STRIPPED VMware vmx binary (the userworld VM monitor; ESXi guest->host surface).',
    'Name ONE function from its decompiled HLIL + evidence. Use the VMware C convention: ModuleCamelCase or Module_Verb,',
    'with the module taken from the function\'s own strings/domain when possible. Be precise and concrete; do not invent a',
    'module that the evidence does not support.',
    '',
    'IMPORTANT — work ONLY from the evidence provided below. Do NOT use any tools, run any commands, or investigate',
    'external files/databases; you already have everything you need here. Answer in one step via the structured output.',
    'If the evidence is thin or looks like noise: prefer the upstream library/function name if it resembles vendored',
    'third-party code (libpng/libopus/zlib/Xlib/etc.). If you still cannot determine a real role, it is OK to ABSTAIN:',
    'leave name empty ("") and set confidence to "none". Do NOT fabricate a guess from noise — an abstention is the',
    'correct, fast answer for an unidentifiable function. Abstained functions are revisited in a LATER pass, after their',
    'callers and callees have been named, which usually makes the role obvious. Prefer a real low-confidence name only',
    'when you have an actual signal (a meaningful string, a recognizable call pattern, a vendored-lib match).',
    '',
    'Function: ' + rec.addr,
    'Domain hints: ' + domain,
    'Referenced strings:',
    strings,
    'Calls (named): ' + callees,
    'Called by (named): ' + callers,
    '',
    'Decompiled HLIL:',
    rec.hlil || '(no HLIL)',
    '',
    'Return: name, a 1-3 sentence role comment (note guest-controlled input / memory ops if visible), confidence, optional proto.',
  ].join('\n')
}

phase('Name')
const results = await parallel(BATCH.map(rec => () =>
  agent(buildPrompt(rec), {
    schema: NAME_SCHEMA,
    model: rec.tier || 'sonnet',           // tiered routing: haiku for evidence-rich, sonnet for thin
    label: (rec.tier || 'sonnet') + ':' + rec.addr,
    phase: 'Name',
  }).then(r => r ? Object.assign({ addr: rec.addr, tier: rec.tier }, r) : null)
))
return results.filter(Boolean)
'''


def main():
    ap = argparse.ArgumentParser(description="Generate a self-contained naming Workflow script from a prep batch.")
    ap.add_argument("batch", help="batch JSON from prep_batch.py")
    ap.add_argument("--out", required=True, help="workflow .js to write")
    args = ap.parse_args()
    batch = json.load(open(args.batch))
    if not isinstance(batch, list) or not batch:
        sys.exit("batch is empty or not a list")
    js = TEMPLATE.replace("__BATCH__", json.dumps(batch))
    with open(args.out, "w") as fh:
        fh.write(js)
    print("[make-wf] wrote %s  (%d functions)  -> run: Workflow(scriptPath=%r)" % (args.out, len(batch), os.path.abspath(args.out)))


if __name__ == "__main__":
    main()
