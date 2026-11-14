#!/usr/bin/env bash
# Prints the interop matrix of docs/INTEROP.md (Markdown) from the rows the
# m1_*.sh runners wrote: the row.json of each case directory under the given
# results directories (a later directory's row for a case replaces an
# earlier one), in the order of the runners' case lists (a name ending in
# '?' is printed only if it ran), then the Linux->Linux reference rows of
# m1_linux_ref.sh as a second table.
#
# Usage: tests/interop/m1_matrix.sh RESULTS_DIR...
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
order=$(
  "$here/m1_bulk.sh" list
  "$here/m1_httpd.sh" list
  "$here/m1_http_get.sh" list
  "$here/m1_udp_icmp.sh" list
)
ref_order=$("$here/m1_linux_ref.sh" list)
python3 -I - "$order" "$ref_order" "$@" <<'PY'
import json, os, sys

order = sys.argv[1].split()
ref_order = sys.argv[2].split()
rows = {}
for d in sys.argv[3:]:
    for c in os.listdir(d):
        p = os.path.join(d, c, "row.json")
        if os.path.isfile(p):
            rows[c] = json.load(open(p))

def size(n):
    if n is None or n == "":
        return ""
    n = int(n)
    for unit, v in (("GB", 10**9), ("MB", 10**6)):
        if n >= v and n % v == 0:
            return f"{n // v} {unit}"
    return f"{n} B"

keys = [("TcpExtTCPSACKDiscard", "SACKDiscard"), ("TcpExtTCPSACKReneging", "SACKReneging"),
        ("TcpExtTCPSackRecovery", "SackRecovery"), ("TcpExtTCPDSACKRecv", "DSACKRecv"),
        ("TcpExtTCPDSACKIgnoredNoUndo", "DSACKIgnoredNoUndo"),
        ("TcpExtTCPToZeroWindowAdv", "ToZeroWindowAdv"), ("TcpExtTCPTimeouts", "Timeouts")]

print("| Case | Direction | Options | Impairment | Bytes | SHA-256 equal | Duration s (non-timing) "
      "| Goodput Mbit/s (non-timing) | Retransmissions (sender total_retrans / peer TcpRetransSegs) "
      "| Peer nstat deltas | utcp0 drops (rx/tx) | Result |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|")
for c in order:
    optional = c.endswith("?")
    c = c.rstrip("?")
    r = rows.get(c)
    if r is None and optional:
        continue
    if r is None:
        print(f"| {c} | | | | | | | | | not run | | NOT RUN |")
        continue
    test = r.get("test")
    ns = r.get("nstat", {})
    if test in ("A", "B", "C", "D", "E") and not r.get("direction", "").startswith("Internet"):
        nst = ", ".join(f"{short} {ns.get(k, 0)}" for k, short in keys
                        if k in ns or k in ("TcpExtTCPSACKDiscard", "TcpExtTCPSACKReneging"))
        ds = r.get("dsack")
        if ds and ns.get("TcpExtTCPSACKDiscard", 0):
            nst += (f" (SACKDiscard = {ds['pred_discard']} predicted from the capture, all D-SACKs"
                    f" for segments the stack received twice; see TCPSACKDiscard below)")
    else:
        nst = "n/a"
    sha_checks = [x["ok"] for x in r.get("checks", []) if "sha" in x["check"]]
    sha = "yes" if sha_checks and all(sha_checks) else "no"
    if test == "H":
        sha = "n/a"
    public = r.get("direction", "").startswith("Internet")
    dur = "" if public or r.get("duration_s") in (None, 0) else r["duration_s"]
    gp = "" if public or not r.get("goodput_mbps") else r["goodput_mbps"]
    rt = ""
    if r.get("sender_total_retrans") is not None:
        rt = f"{r['sender_total_retrans']} / {r.get('peer_TcpRetransSegs', '')}"
    elif test == "D":
        # The stack (utcp-httpd) sends: its TcpRetransSegs.
        rt = f"stack {r.get('stack_TcpRetransSegs', '')} / {r.get('peer_TcpRetransSegs', '')}"
    elif not public and test != "H":
        rt = f"- / {r.get('peer_TcpRetransSegs', '')}"
    failed = [x["check"] for x in r.get("checks", []) if not x["ok"]]
    res = "pass" if r.get("pass") else "FAIL: " + "; ".join(f"`{f}`" for f in failed)
    if r.get("replaced_by"):
        res = f"replaced by {r['replaced_by']} (kernel curl precheck failed; not a stack result)"
    drops = "" if public else f"{r.get('tun_rx_dropped', '')}/{r.get('tun_tx_dropped', '')}"
    print(f"| {c} | {r.get('direction', '')} | {r.get('options', '')} | {r.get('impairment', '')} "
          f"| {size(r.get('bytes_n'))} | {sha} | {dur} | {gp} | {rt} | {nst} | {drops} | {res} |")

print()
print("Linux->Linux reference (tests/interop/m1_linux_ref.sh; not acceptance cases):")
print()
print("| Case | Options | Impairment | Bytes | SHA-256 equal | Duration s (non-timing) "
      "| Retransmissions (sender total_retrans / TcpRetransSegs) | Sender nstat deltas "
      "| D-SACK replay (predicted SACKDiscard / dubious, D-SACK ACKs, of them older than snd_una) | Result |")
print("|---|---|---|---|---|---|---|---|---|---|")
for c in ref_order:
    r = rows.get(c)
    if r is None:
        print(f"| {c} | | | | | | | | | NOT RUN |")
        continue
    ns = r.get("nstat", {})
    nst = ", ".join(f"{short} {ns.get(k, 0)}" for k, short in keys
                    if k in ns or k in ("TcpExtTCPSACKDiscard", "TcpExtTCPSACKReneging"))
    ds = r.get("dsack")
    dss = (f"{ds['pred_discard']} / {ds['pred_dubious']}, {ds['dsack_acks']}, {ds['dsack_acks_old']}"
           if ds else "")
    failed = [x["check"] for x in r.get("checks", []) if not x["ok"]]
    res = "pass" if r.get("pass") else "FAIL: " + "; ".join(f"`{f}`" for f in failed)
    print(f"| {c} | {r.get('options', '')} | {r.get('impairment', '')} | {size(r.get('bytes_n'))} "
          f"| {'yes' if r.get('sha_ok') else 'no'} | {r.get('duration_s') or ''} "
          f"| {r.get('sender_total_retrans')} / {r.get('peer_TcpRetransSegs', '')} | {nst} | {dss} | {res} |")
PY
