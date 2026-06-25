#!/usr/bin/env python3
"""Reachability + BugScore over kreview.db.
Reach(f)=gamma^dist(seed->f) along call edges (broad 'everything reachable' seed set).
BugScore = Reach * sum(w_i * percentile(feature_i)). Writes reach/dist/score back; prints top-N + anchors.
"""
import sys, re, sqlite3, json
import os
from collections import deque, defaultdict

DB = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("KAUDIT_ROOT",".")+"/kreview.db"
PROFILE = sys.argv[2] if len(sys.argv) > 2 else None

# defaults = ESXi 'everything reachable' seed set; override via a profile JSON (seed_regex/weights/gamma/floor).
_DEF_SEED = (r'((E1000|Vmxnet[23]|Pvscsi|PVSCSI|Ahci|AHCI|Xhci|Ehci|Uhci|XHCI|EHCI|UHCI|Usb|USB|Svga|SVGA|HdAudio|Hbr|'
  r'Pvrdma|PVRDMA|Vrdma|vRDMA|Sata|SATA|Lsilogic|LSILogic|Vmxnet|VMKDev|VDev|Vusb)\w*(Tx|Rx|Io|IO|Mmio|MMIO|Pio|'
  r'Reg|Ring|Dma|DMA|Cmd|Handle|Dispatch|Process|Recv|Send|Async|Backend|Read|Write|Doorbell|Kick)'
  r'|(Backdoor|BDOOR|Bdoor|Vmci|VMCI|Rpci|RPCI|Vix|Hostif)\w*'
  r'|(Hypercall|VMKCall|Vmkcall|VMMCall|UWVMK|Uwvmk|UserVMK|VMKLinuxSys|VMKLinux\w*Sys)\w*'
  r'|(Tcpip|Tcp|Ip4|Ip6|Udp|Ether|Eth|Arp|ARP|Icmp|Pkt|Uplink|Netq|ENS|Ens)\w*(Input|Recv|Rx|Rcv|Process|Handle|Parse|Demux|Reass|Frag)'
  r'|(Psa|Nvme|NVMF|Nvmf|Iscsi|ISCSI|ScsiTarget|FCoE|Fcoe|Vmkfc|Fc)\w*(Complete|Recv|Process|Cmd|Resp|Response|Identify|Parse|Handle|CB)'
  r'|\w*Vsi\w*(Set|Write|Add)|\w*(Ioctl|IOCTL)\w*)')
_DEF_W = dict(cc=1.0, n_memidx=1.2, sink=1.0, parse=0.7, loops=0.6, state=0.5, n_arith=0.4, n_insns=0.3, fanin=0.5)
_prof = json.load(open(PROFILE)) if PROFILE else {}
GAMMA   = _prof.get('gamma', 0.72)
FLOOR   = _prof.get('floor', 0.03)   # floor for direct-edge-unreachable funcs (call graph is incomplete: indirect dispatch)
SEED_RE = re.compile(_prof.get('seed_regex', _DEF_SEED))
WEIGHTS = _prof.get('weights', _DEF_W)

def main():
    con = sqlite3.connect(DB); cur = con.cursor()
    rows = cur.execute("SELECT addr,name,size,n_insns,cc,loops,n_mem,n_memidx,n_arith,n_call,n_callind,sink_calls,state_calls,parse_off FROM func").fetchall()
    cols = ['addr','name','size','n_insns','cc','loops','n_mem','n_memidx','n_arith','n_call','n_callind','sink','state','parse']
    F = {r[0]: dict(zip(cols, r)) for r in rows}
    g = defaultdict(list); fanin = defaultdict(int)
    for c,t in cur.execute("SELECT caller,callee FROM edge"):
        g[c].append(t); fanin[t]+=1
    for a in F: F[a]['fanin']=fanin.get(a,0)
    print(f"loops: max={max(F[a]['loops'] for a in F)} nonzero={sum(1 for a in F if F[a]['loops']>0)}", file=sys.stderr)
    seeds = [a for a in F if SEED_RE.search(F[a]['name'])]
    print(f"seeds={len(seeds)} (of {len(F)})", file=sys.stderr)
    # BFS distance seed->f
    dist = {a: 0 for a in seeds}; q = deque(seeds)
    while q:
        u = q.popleft()
        for v in g.get(u, ()):
            if v in F and v not in dist:
                dist[v] = dist[u]+1; q.append(v)
    reach_cnt = len(dist)
    print(f"reachable={reach_cnt} ({100*reach_cnt//len(F)}%)", file=sys.stderr)
    # percentile normalize features
    def pctl(key):
        vals = sorted(F[a][key] for a in F)
        import bisect
        n = len(vals)
        return lambda x: bisect.bisect_right(vals, x)/n
    P = {k: pctl(k) for k in ['cc','loops','n_memidx','n_arith','sink','state','parse','n_insns','fanin']}
    W = WEIGHTS
    for a in F:
        d = dist.get(a)
        reach = GAMMA**d if d is not None else FLOOR
        intrinsic = sum(W[k]*P[k](F[a][k]) for k in W)
        F[a]['reach']=reach; F[a]['dist']=d if d is not None else -1
        F[a]['score']=reach*intrinsic
    # write back
    cur.execute("ALTER TABLE func ADD COLUMN reach REAL") if not _has(cur,'reach') else None
    cur.execute("ALTER TABLE func ADD COLUMN dist INT") if not _has(cur,'dist') else None
    cur.execute("ALTER TABLE func ADD COLUMN score REAL") if not _has(cur,'score') else None
    for a in F:
        cur.execute("UPDATE func SET reach=?,dist=?,score=? WHERE addr=?",(F[a]['reach'],F[a]['dist'],F[a]['score'],a))
    con.commit()
    ranked = sorted(F.values(), key=lambda r:-r['score'])
    rankmap = {r['name']:i+1 for i,r in enumerate(ranked)}
    print("\n=== TOP 40 ===")
    print(f"{'#':>3} {'score':>6} {'reach':>5} {'cc':>4} {'memidx':>6} {'sink':>4} {'parse':>5} {'size':>5}  name")
    for i,r in enumerate(ranked[:40]):
        print(f"{i+1:>3} {r['score']:>6.2f} {r['reach']:>5.2f} {r['cc']:>4} {r['n_memidx']:>6} {r['sink']:>4} {r['parse']:>5} {r['n_insns']:>5}  {r['name']}")
    print("\n=== CALIBRATION: known/interesting anchors ===")
    _anchors = _prof.get('anchors', ['E1000ValidateTsoHdrs','Vmxnet3EnsDev_RxWithPerQBuffer','PsaNvmeAddControllerInt','E1000TxTSOSend','E1000DevAsyncTx'])
    for nm in _anchors:
        if nm in rankmap:
            r=[x for x in ranked if x['name']==nm][0]
            print(f"  #{rankmap[nm]:>5}/{len(ranked)}  score={r['score']:.2f} dist={r['dist']} cc={r['cc']}  {nm}")
    con.close()

def _has(cur,col):
    return col in [r[1] for r in cur.execute("PRAGMA table_info(func)")]

if __name__=="__main__":
    main()
