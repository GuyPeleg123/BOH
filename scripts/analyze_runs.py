#!/usr/bin/env python3
"""
analyze_runs.py <phase> — re-derive reliable per-run metrics straight from each
run's pcap + sniffer.log (independent of the GUI metrics bus, which can freeze
across start/stop cycles). Reads run-dirs from /tmp/lna_exp_<phase>.json.

Reliable, pcap-sourced metrics (work for every run, both phases):
  DL communication caught : DLSCH PDUs, DL bytes (framed), distinct RNTIs (UEs)
  full content            : total MAC frames, UL-SCH PDUs, UL bytes
  quality                 : overflow/error hits grepped from sniffer.log
Writes /tmp/lna_reliable_<phase>.json and prints SUM/MEAN table.
"""
import json
import subprocess
import sys

MAC_MAP = 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'


def tsh(pcap, *args):
    cmd = ["sudo", "-n", "tshark", "-r", pcap, "-o", MAC_MAP, *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
    except Exception:
        return ""


def lines(txt):
    return [x for x in txt.splitlines() if x.strip()]


def pcap_metrics(run_dir):
    pcap = f"{run_dir}/ltesniffer_dual_mode.pcap"
    m = {}
    m["mac_frames"] = len(lines(tsh(pcap, "-Y", "mac-lte", "-T", "fields", "-e", "frame.number")))
    dl = lines(tsh(pcap, "-Y", "mac-lte.dlsch", "-T", "fields", "-e", "frame.len"))
    ul = lines(tsh(pcap, "-Y", "mac-lte.ulsch", "-T", "fields", "-e", "frame.len"))
    m["dlsch"] = len(dl)
    m["ulsch"] = len(ul)
    m["dl_bytes"] = sum(int(x) for x in dl if x.isdigit())
    m["ul_bytes"] = sum(int(x) for x in ul if x.isdigit())
    rs = set()
    for v in tsh(pcap, "-Y", "mac-lte", "-T", "fields", "-e", "mac-lte.rnti").split():
        if v.strip():
            rs.add(v.strip())
    m["rntis"] = len(rs)
    # quality from sniffer.log
    log = f"{run_dir}/sniffer.log"
    try:
        txt = subprocess.run(["sudo", "-n", "grep", "-icE", "overflow|error|out of sync",
                              log], capture_output=True, text=True).stdout.strip()
        m["log_warn"] = int(txt) if txt.isdigit() else 0
    except Exception:
        m["log_warn"] = 0
    return m


def main():
    phase = sys.argv[1]
    data = json.load(open(f"/tmp/lna_exp_{phase}.json"))
    rows = []
    for r in data["runs"]:
        m = pcap_metrics(r["run_dir"])
        m["run"] = r["run"]
        rows.append(m)
        print(f"[run {r['run']:2d}] dlsch={m['dlsch']:5d} dl_bytes={m['dl_bytes']:8d} "
              f"frames={m['mac_frames']:5d} rntis={m['rntis']:4d} ulsch={m['ulsch']:3d} "
              f"warn={m['log_warn']}", flush=True)
    json.dump({"phase": phase, "rows": rows}, open(f"/tmp/lna_reliable_{phase}.json", "w"), indent=2)

    cols = [("run", "run"), ("dlsch", "DLSCH"), ("dl_bytes", "DL_bytes"),
            ("rntis", "RNTIs"), ("mac_frames", "MACfrm"),
            ("ulsch", "ULSCH"), ("ul_bytes", "UL_bytes"), ("log_warn", "warn")]
    hdr = " ".join(f"{h:>10}" for _, h in cols)
    print("\n" + hdr); print("-" * len(hdr))
    for r in rows:
        print(" ".join(f"{int(r.get(k, 0)):>10}" for k, _ in cols))
    print("-" * len(hdr))
    tot = {k: sum(r.get(k, 0) for r in rows) for k, _ in cols}
    n = len(rows)
    print(" ".join(f"{('SUM' if k == 'run' else int(tot[k])):>10}" for k, _ in cols))
    print(" ".join(f"{('MEAN' if k == 'run' else round(tot[k] / n, 1)):>10}" for k, _ in cols))


if __name__ == "__main__":
    main()
