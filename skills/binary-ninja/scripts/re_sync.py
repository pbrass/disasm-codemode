#!/usr/bin/env python3
"""re_sync.py — apply a git-tracked RE "sidecar" (renames / prototypes / struct & type decls / variable
names+types / comments / data vars) into a Binary Ninja BinaryView, idempotently. The sidecar is the
durable, reviewable source of truth; the .bndb is the live artifact you re-hydrate from it.

Why a sidecar: a .bndb is a 100s-of-MB binary blob — useless in git diffs and easy to lose to a re-analysis
or an un-saved session. Keeping the analysis (every name/type/struct) in a small JSON+C file makes the work
reviewable, diff-able, and re-appliable to a fresh database in one command.

Idempotent by construction: types are (re)defined, functions are matched by ADDRESS, variables by their
stable IDENTIFIER — so re-running converges to the same state (never duplicates, never drifts).

Usage:
  bn-re-apply SIDECAR.json --bv-match <substr>          # apply into the OPEN tab (preview; Ctrl+S to persist)
  bn-re-apply SIDECAR.json --file /abs/copy.bndb --save # load fresh, apply, save tool-side

Sidecar schema (see skills/binary-ninja/reference or the vmx-re README):
{
  "binary":  "i_vmx_full",                       # informational
  "types_c": "struct VmxState { uint32_t hdr_len; uint64_t flags; void *payload; };\\n typedef ...;",
  "functions": {
    "0x140001000": {
      "name":  "Vmx_HandleFoo",
      "proto": "int64_t Vmx_HandleFoo(struct VmxState* ctx, uint32_t len)",   # optional full C prototype
      "comment": "entry for ...",                                             # optional function comment
      "vars": { "<identifier-int>": {"name": "ctx", "type": "struct VmxState*"} },   # bn-re-vars lists ids
      "line_comments": { "0x140001020": "loop over rings" }
    }
  },
  "data_vars": { "0x140050000": {"name": "g_vmxTable", "type": "struct VmxState[16]"} }
}
Every field is optional; apply only touches what's present. types_c is applied FIRST so prototypes/var types
that reference the new structs resolve.
"""
import sys, os, json, argparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bn-inspect", "scripts"))
import bncm  # shared MCP client + injection-safe run()/validators


BODY = r'''
import json, re as _re, binaryninja as _bn
_spec = json.loads(_spec_json)
_n = {"types": 0, "funcs": 0, "protos": 0, "vars": 0, "fcomments": 0, "lcomments": 0, "data": 0, "typestubs": 0}
_miss = []
_errs = []
_stubbed = set()

# 1) TYPES FIRST -- structs/enums/typedefs, so later prototypes & var types can reference them.
_tc = (_spec.get("types_c") or "").strip()
if _tc:
    try:
        _res = _bv.parse_types_from_string(_tc)
        for _qn, _t in _res.types.items():
            _bv.define_user_type(_qn, _t)
            _n["types"] += 1
    except Exception as _e:
        _errs.append("types_c: %r" % _e)

# 2) FUNCTIONS -- matched by address (stable across renames).
_funcs = _spec.get("functions") or {}
for _addr_s in _funcs:
    _fd = _funcs[_addr_s]
    try:
        _addr = int(_addr_s, 16) if isinstance(_addr_s, str) else int(_addr_s)
    except Exception:
        _errs.append("bad func addr %r" % _addr_s); continue
    _f = _bv.get_function_at(_addr)
    if _f is None:
        _cont = _bv.get_functions_containing(_addr) or []
        _f = _cont[0] if _cont else None
    if _f is None:
        _miss.append(_addr_s); continue
    if _fd.get("name"):
        try: _f.name = _fd["name"]; _n["funcs"] += 1
        except Exception as _e: _errs.append("%s name: %r" % (_addr_s, _e))
    if _fd.get("proto"):
        _proto = _fd["proto"]
        try:
            _pt = _bv.parse_type_string(_proto)
            _f.type = _pt[0]; _n["protos"] += 1
        except Exception as _e:
            # a prototype often names inferred struct types that aren't declared yet -> forward-declare them
            # as opaque structs (captures the type intel for later) and retry once.
            _unk = _re.findall(r"unknown type name '([^']+)'", str(_e)) + _re.findall(r"[Rr]eference to unknown type (\w+)", str(_e))
            for _ut in _unk:
                if _ut in _stubbed:
                    continue
                try:
                    _r2 = _bv.parse_types_from_string("struct %s; typedef struct %s %s;" % (_ut, _ut, _ut))
                    for _qn2, _t2 in _r2.types.items():
                        _bv.define_user_type(_qn2, _t2)
                    _stubbed.add(_ut); _n["typestubs"] += 1
                except Exception:
                    pass
            if _unk:
                try:
                    _pt = _bv.parse_type_string(_proto)
                    _f.type = _pt[0]; _n["protos"] += 1
                except Exception as _e2:
                    _errs.append("%s proto: %r" % (_addr_s, _e2))
            else:
                _errs.append("%s proto: %r" % (_addr_s, _e))
    if _fd.get("comment"):
        try: _f.comment = _fd["comment"]; _n["fcomments"] += 1
        except Exception as _e: _errs.append("%s comment: %r" % (_addr_s, _e))
    # variables keyed by stable identifier; build an id->var map from the live function
    _vmap = {}
    for _vv in _f.vars:
        _vmap[_vv.identifier] = _vv
    _vspec = _fd.get("vars") or {}
    for _vid_s in _vspec:
        _vinfo = _vspec[_vid_s]
        try: _vid = int(_vid_s)
        except Exception: _errs.append("%s bad var id %r" % (_addr_s, _vid_s)); continue
        _var = _vmap.get(_vid)
        if _var is None:
            _errs.append("%s var id %s not present" % (_addr_s, _vid_s)); continue
        _vt = _var.type
        if _vinfo.get("type"):
            try: _vt = _bv.parse_type_string(_vinfo["type"])[0]
            except Exception as _e: _errs.append("%s var %s type: %r" % (_addr_s, _vid_s, _e))
        try:
            _f.create_user_var(_var, _vt, _vinfo.get("name") or _var.name)
            _n["vars"] += 1
        except Exception as _e:
            _errs.append("%s var %s: %r" % (_addr_s, _vid_s, _e))
    _lc = _fd.get("line_comments") or {}
    for _ca_s in _lc:
        try:
            _f.set_comment_at(int(_ca_s, 16), _lc[_ca_s]); _n["lcomments"] += 1
        except Exception as _e:
            _errs.append("%s linecmt %s: %r" % (_addr_s, _ca_s, _e))
    _f.reanalyze()

# 3) DATA VARS
_dv = _spec.get("data_vars") or {}
for _da_s in _dv:
    _dd = _dv[_da_s]
    try:
        _da = int(_da_s, 16) if isinstance(_da_s, str) else int(_da_s)
    except Exception:
        _errs.append("bad data addr %r" % _da_s); continue
    try:
        if _dd.get("type"):
            _bv.define_user_data_var(_da, _bv.parse_type_string(_dd["type"])[0])
        if _dd.get("name"):
            _bv.define_user_symbol(_bn.Symbol(_bn.SymbolType.DataSymbol, _da, _dd["name"]))
        _n["data"] += 1
    except Exception as _e:
        _errs.append("data %s: %r" % (_da_s, _e))

_parts = []
for _k in _n:
    _parts.append("%s=%d" % (_k, _n[_k]))
print("[re-sync] applied: %s" % ", ".join(_parts))
if _miss:
    print("[re-sync] %d function address(es) not found: %s" % (len(_miss), ", ".join(map(str, _miss[:12]))))
if _errs:
    print("[re-sync] %d item error(s):" % len(_errs))
    for _em in _errs[:20]:
        print("   - " + _em)

# ---- persist (same model as bn-audit-sync: the GUI owns an open tab's .bndb) ----
if _save and not _file:
    print("[re-sync] applied to the live tab (visible now). To PERSIST: save in the GUI (Ctrl+S) — it owns "
          "this database. For a tool-side save, run on a copy: --file /abs/copy.bndb --save.")
elif _save:
    _tgt = _file if _file.endswith(".bndb") else (_file + ".bndb")
    try:
        if _file.endswith(".bndb"):
            _bv.file.save_auto_snapshot()
        else:
            _bv.create_database(_tgt)
        print("[re-sync] saved -> %s" % _tgt)
    except Exception as _e:
        print("[re-sync] SAVE FAILED: %r" % _e)
'''


def main():
    ap = argparse.ArgumentParser(description="Apply an RE sidecar (names/types/structs/vars/comments) into a BinaryView, idempotently.")
    ap.add_argument("sidecar", help="path to the RE sidecar JSON")
    bncm.add_target_args(ap)  # --file / --bv-match (one required)
    ap.add_argument("--save", action="store_true", help="persist a snapshot to the .bndb (else preview in memory)")
    args = ap.parse_args()
    if not os.path.exists(args.sidecar):
        bncm.die("sidecar not found: %s" % args.sidecar)
    try:
        spec = json.load(open(args.sidecar))
    except Exception as e:
        bncm.die("sidecar is not valid JSON: %r" % e)
    if not isinstance(spec, dict):
        bncm.die("sidecar must be a JSON object")
    params = bncm.target_params(args)
    params["_spec_json"] = json.dumps(spec)
    params["_save"] = bool(args.save)
    bncm.run(BODY, **params)


if __name__ == "__main__":
    main()
