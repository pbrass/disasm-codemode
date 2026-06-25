#!/usr/bin/env python3
"""sync_to_bv.py — write binary-audit ledger findings into the BinaryView as function comments
(+ a `binaudit` tag), optionally persisting to the .bndb. The analysis becomes visible in BN and
travels with the database / to teammates.

REGENERABLE: each comment is wrapped in `[binaudit]…[/binaudit]` markers, so re-running REPLACES the
block (comments never accumulate). Tags are best-effort (may accumulate across runs).

Usage:
  bn-audit-sync LEDGER.db --bv-match <substr>            # annotate the OPEN tab in memory (preview)
  bn-audit-sync LEDGER.db --bv-match <substr> --save     # + persist a snapshot to its .bndb
  bn-audit-sync LEDGER.db --file /abs/path.bndb --save   # load fresh, write, save
  bn-audit-sync LEDGER.db --bv-match <substr> --all      # also annotate functions reviewed 'clean'

Annotates every function that has a bug, a Stage-3/4 audit verdict, or a non-clean review
(`--all` adds the clean ones). Reads review/bug/precondition/audit from the ledger; caller-owed
preconditions (klass in caller/unguaranteed = the attack surface) go into the comment.
"""
import sys, os, json, sqlite3, argparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm  # shared MCP client + injection-safe run()/validators


def _clean(name):
    # ledger func_names may carry a " @ 0xADDR" suffix; BN lookup wants the bare name
    return name.split(" @ ")[0].strip() if name else name


def build_items(db_path, include_all, limit):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    reviews, bugs, preconds, audits = {}, {}, {}, {}
    for r in db.execute("select name, verdict from review"):
        reviews[_clean(r["name"])] = r["verdict"]
    for b in db.execute("select func_name, bug_class, status, desc from bug"):
        bugs.setdefault(_clean(b["func_name"]), []).append(b)
    for p in db.execute("select func_name, kind, klass, text from precondition where klass in ('caller','unguaranteed')"):
        preconds.setdefault(_clean(p["func_name"]), []).append(p)
    for a in db.execute("select func_name, verdict, guest_path from audit"):
        audits.setdefault(_clean(a["func_name"]), []).append(a)
    db.close()

    names = set(bugs) | set(audits)
    for n, v in reviews.items():
        if v != "clean" or include_all:
            names.add(n)

    def tag_for(name):
        st = [b["status"] for b in bugs.get(name, [])]
        if "confirmed-violable" in st: return "violable"
        if "confirmed-latent" in st:   return "latent"
        if "gated" in st:              return "gated"
        if "open" in st:               return "suspected"
        if st and all(x == "refuted" for x in st): return "refuted"
        if reviews.get(name) in ("suspicious", "needs-caller-analysis"): return "review"
        return None

    items = []
    for name in sorted(names):
        if not name:
            continue
        lines = ["[binaudit] %s" % (reviews.get(name) or "reviewed")]
        for b in bugs.get(name, [])[:4]:
            lines.append("bug: %s/%s — %s" % (b["bug_class"] or "?", b["status"] or "open", (b["desc"] or "")[:90]))
        for p in preconds.get(name, [])[:3]:
            lines.append("precond[%s/%s]: %s" % (p["kind"] or "?", p["klass"] or "?", (p["text"] or "")[:100]))
        for a in audits.get(name, [])[:2]:
            lines.append("stage3: %s — %s" % (a["verdict"] or "?", (a["guest_path"] or "")[:90]))
        lines.append("[/binaudit]")
        items.append({"name": name, "comment": "\n".join(lines), "tag": tag_for(name)})
        if limit and len(items) >= limit:
            break
    return items


BODY = r'''
import json, re
_items = json.loads(_items_json)
_set = 0; _miss = 0; _tagged = 0
_tt = None
try:
    _tt = _bv.create_tag_type("binaudit", "B")
except Exception:
    try:
        for _k, _v in _bv.tag_types.items():
            if getattr(_v, "name", _k) == "binaudit": _tt = _v; break
    except Exception:
        _tt = None
for _it in _items:
    _fns = _bv.get_functions_by_name(_it["name"])
    if not _fns:
        _miss += 1; continue
    _f = _fns[0]
    _old = _f.comment or ""
    _new = re.sub(r"\[binaudit\].*?\[/binaudit\]\n?", "", _old, flags=re.S).rstrip()
    _f.comment = ((_new + "\n") if _new else "") + _it["comment"]
    _set += 1
    if _tt is not None and _it.get("tag"):
        try:
            _f.add_tag(_tt, _it["tag"]); _tagged += 1
        except Exception:
            pass
if _save:
    try:
        _bv.file.save_auto_snapshot(); print("[binaudit] saved snapshot to the .bndb")
    except Exception as _e:
        print("[binaudit] SAVE FAILED: %r -- for an open tab the GUI owns the db; save in the GUI, or use --file /abs/copy.bndb --save" % _e)
print("[binaudit] annotated %d function(s); %d not found in BV; %d tagged.%s" % (_set, _miss, _tagged, "" if _save else "  (preview -- pass --save to persist)"))
'''


def main():
    ap = argparse.ArgumentParser(description="Write binary-audit ledger findings into a BinaryView as comments + a binaudit tag.")
    ap.add_argument("ledger", help="path to the binary-audit ledger (kreview.db)")
    bncm.add_target_args(ap)  # --file / --bv-match (one required)
    ap.add_argument("--save", action="store_true", help="persist a snapshot to the .bndb (else preview in memory)")
    ap.add_argument("--all", action="store_true", help="also annotate functions reviewed 'clean'")
    ap.add_argument("--limit", type=int, default=0, help="cap how many functions are annotated")
    args = ap.parse_args()
    if not os.path.exists(args.ledger):
        bncm.die("ledger not found: %s" % args.ledger)
    items = build_items(os.path.abspath(args.ledger), args.all, args.limit)
    if not items:
        print("[binaudit] nothing to annotate (no bugs/audits/non-clean reviews; try --all)"); return
    params = bncm.target_params(args)
    params["_items_json"] = json.dumps(items)
    params["_save"] = bool(args.save)
    bncm.run(BODY, **params)


if __name__ == "__main__":
    main()
