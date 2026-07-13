#!/usr/bin/env python3
"""
lna_ab_experiment.py — run N independent fixed-duration sniffs via the GUI API,
aggregate per-run quality/efficiency + DL-communication metrics into a table.

Usage:  ./lna_ab_experiment.py <phase-label>   e.g. before  /  after

Per run it:
  1. POST /api/capture/start (uses the saved SnifferConfig — keep it identical
     across phases so the ONLY变 variable is the LNA hardware).
  2. snapshots cumulative /metrics counters (they're monotonic, never reset),
  3. sleeps RUN_SECONDS,
  4. POST /api/capture/stop, snapshots /metrics again -> per-run delta,
  5. records the run-dir; its pcap is analysed (MAC-LTE) after all runs.

Outputs /tmp/lna_exp_<phase>.json (machine) + prints a formatted table (log).
"""
import http.cookiejar
import json
import re
import ssl
import subprocess
import sys
import time
import urllib.request

BASE = "https://192.168.0.107:8443"
USER, PASSWORD = "admin", "buchris"
N_RUNS = 10
RUN_SECONDS = 180
SETTLE = 5          # seconds after stop before next start / before pcap is final
MAC_MAP = 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'

# counters we diff per run (monotonic totals)
COUNTERS = {
    "sf_processed": 'ltesniffer_sf_processed_total ',
    "sf_skipped":   'ltesniffer_sf_skipped_total ',
    "overflow":     'ltesniffer_overflow_total ',
    "dci_dl":       'ltesniffer_dci_decoded_total{direction="dl"}',
    "dci_ul":       'ltesniffer_dci_decoded_total{direction="ul"}',
    "tbs_dl":       'ltesniffer_tbs_bits_total{direction="dl"}',
    "tbs_ul":       'ltesniffer_tbs_bits_total{direction="ul"}',
    "rb_dl":        'ltesniffer_rb_total{direction="dl"}',
    "rb_ul":        'ltesniffer_rb_total{direction="ul"}',
}

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_jar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ctx),
    urllib.request.HTTPCookieProcessor(_jar),
)


def http(path, body=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    m = method or ("POST" if data is not None else "GET")
    req = urllib.request.Request(BASE + path, data=data, method=m)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with _opener.open(req, timeout=30) as r:
        raw = r.read().decode()
    return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw


def get_metrics():
    req = urllib.request.Request(BASE + "/metrics")
    with _opener.open(req, timeout=30) as r:
        txt = r.read().decode()
    out = {}
    for key, needle in COUNTERS.items():
        val = 0.0
        for line in txt.splitlines():
            if line.startswith("#"):
                continue
            if needle in line:
                try:
                    val = float(line.rsplit(" ", 1)[1])
                except (ValueError, IndexError):
                    pass
                break
        out[key] = val
    return out


def tsh(pcap, *args):
    cmd = ["sudo", "-n", "tshark", "-r", pcap, "-o", MAC_MAP, *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return ""


def pcap_stats(run_dir):
    pcap = f"{run_dir}/ltesniffer_dual_mode.pcap"
    s = {"mac_frames": 0, "dlsch": 0, "ulsch": 0, "rntis": 0, "pcap": pcap}
    # total MAC frames
    out = tsh(pcap, "-Y", "mac-lte", "-T", "fields", "-e", "frame.number")
    s["mac_frames"] = sum(1 for _ in out.splitlines() if _.strip())
    s["dlsch"] = sum(1 for _ in tsh(pcap, "-Y", "mac-lte.dlsch", "-T", "fields",
                                    "-e", "frame.number").splitlines() if _.strip())
    s["ulsch"] = sum(1 for _ in tsh(pcap, "-Y", "mac-lte.ulsch", "-T", "fields",
                                    "-e", "frame.number").splitlines() if _.strip())
    rs = set()
    for fld in ("mac-lte.rnti", "mac-lte.context.rnti"):
        for v in tsh(pcap, "-Y", "mac-lte", "-T", "fields", "-e", fld).split():
            if v.strip():
                rs.add(v.strip())
        if rs:
            break
    s["rntis"] = len(rs)
    return s


def wait_state(running, timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            st = http("/api/status")["state"]
            if st["running"] == running:
                return st
        except Exception:
            pass
        time.sleep(1)
    return http("/api/status")["state"]


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "phase"
    print(f"=== LNA A/B experiment — phase '{phase}' — {N_RUNS}x{RUN_SECONDS}s ===",
          flush=True)
    http("/api/login", {"username": USER, "password": PASSWORD})
    wait_state(False)                       # make sure nothing is running

    runs = []
    for i in range(1, N_RUNS + 1):
        pre = get_metrics()
        # start with NO body so the backend uses the saved SnifferConfig
        # (sending {} would parse to a default config and clobber it).
        st = http("/api/capture/start", method="POST")
        run_dir = st["state"]["run_dir"]
        st = wait_state(True)
        print(f"[run {i:2d}] started pid={st.get('pid')} dir={run_dir}", flush=True)
        time.sleep(RUN_SECONDS)
        http("/api/capture/stop", method="POST")
        wait_state(False)
        time.sleep(SETTLE)
        post = get_metrics()
        delta = {k: post[k] - pre[k] for k in COUNTERS}
        delta["run"] = i
        delta["run_dir"] = run_dir
        print(f"[run {i:2d}] done  dci_dl={int(delta['dci_dl'])} "
              f"tbs_dl={int(delta['tbs_dl'])} ovfl={int(delta['overflow'])} "
              f"skip={int(delta['sf_skipped'])}", flush=True)
        runs.append(delta)

    print("=== analysing pcaps ===", flush=True)
    for r in runs:
        r.update(pcap_stats(r["run_dir"]))
        print(f"[run {r['run']:2d}] pcap dlsch={r['dlsch']} ulsch={r['ulsch']} "
              f"frames={r['mac_frames']} rntis={r['rntis']}", flush=True)

    out = {"phase": phase, "n_runs": N_RUNS, "run_seconds": RUN_SECONDS, "runs": runs}
    path = f"/tmp/lna_exp_{phase}.json"
    json.dump(out, open(path, "w"), indent=2)
    print(f"\nsaved -> {path}", flush=True)
    print_table(out)


def print_table(out):
    runs = out["runs"]
    cols = [("run", "run"), ("dci_dl", "DCI_DL"), ("dci_ul", "DCI_UL"),
            ("tbs_dl", "TBSbits_DL"), ("tbs_ul", "TBSbits_UL"),
            ("rb_dl", "RB_DL"), ("dlsch", "DLSCH"), ("ulsch", "ULSCH"),
            ("mac_frames", "MACfrm"), ("rntis", "RNTIs"),
            ("sf_processed", "SF"), ("sf_skipped", "skip"), ("overflow", "ovfl")]
    hdr = " ".join(f"{h:>10}" for _, h in cols)
    print("\n" + hdr)
    print("-" * len(hdr))
    for r in runs:
        print(" ".join(f"{int(r.get(k,0)):>10}" for k, _ in cols))
    print("-" * len(hdr))
    tot = {k: sum(r.get(k, 0) for r in runs) for k, _ in cols}
    print(" ".join(f"{('SUM' if k=='run' else int(tot[k])):>10}" for k, _ in cols))
    n = len(runs)
    print(" ".join(f"{('MEAN' if k=='run' else round(tot[k]/n,1)):>10}" for k, _ in cols))


if __name__ == "__main__":
    main()
