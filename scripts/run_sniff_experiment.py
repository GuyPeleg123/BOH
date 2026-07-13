#!/usr/bin/env python3
"""
run_sniff_experiment.py <phase> — 10x3min sniffs (same interval structure as
'part A'), but each run's pcap is analysed IMMEDIATELY and the experiment ABORTS
+ alerts on RF-sequence problems instead of wasting time on a broken chain.

Abort conditions (RF sequence looks broken):
  * any run decodes 0 DL-SCH PDUs            -> "NO DL SIGNAL"
  * 3 consecutive runs decode 0 UL-SCH PDUs  -> "NO UL" (baseline always had UL)

Metrics come straight from each run's pcap (the GUI counter bus can freeze across
start/stop cycles, so we don't trust it). Results stream to
/tmp/lna_reliable_<phase>.json so partial data survives an abort.
"""
import http.cookiejar
import json
import ssl
import subprocess
import sys
import time
import urllib.request

BASE = "https://192.168.0.107:8443"
USER, PASSWORD = "admin", "buchris"
N_RUNS, RUN_SECONDS, SETTLE = 10, 180, 5
MAC_MAP = 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_jar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ctx),
    urllib.request.HTTPCookieProcessor(_jar))


def http(path, body=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data,
                                 method=method or ("POST" if data else "GET"))
    if data:
        req.add_header("Content-Type", "application/json")
    with _opener.open(req, timeout=30) as r:
        raw = r.read().decode()
    return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw


def tsh(pcap, *a):
    try:
        return subprocess.run(["sudo", "-n", "tshark", "-r", pcap, "-o", MAC_MAP, *a],
                              capture_output=True, text=True, timeout=180).stdout
    except Exception:
        return ""


def nlines(t):
    return sum(1 for x in t.splitlines() if x.strip())


def pcap_metrics(run_dir):
    p = f"{run_dir}/ltesniffer_dual_mode.pcap"
    dl = [x for x in tsh(p, "-Y", "mac-lte.dlsch", "-T", "fields", "-e", "frame.len").split() if x.isdigit()]
    ul = [x for x in tsh(p, "-Y", "mac-lte.ulsch", "-T", "fields", "-e", "frame.len").split() if x.isdigit()]
    rs = {v for v in tsh(p, "-Y", "mac-lte", "-T", "fields", "-e", "mac-lte.rnti").split() if v.strip()}
    return {"mac_frames": nlines(tsh(p, "-Y", "mac-lte", "-T", "fields", "-e", "frame.number")),
            "dlsch": len(dl), "ulsch": len(ul),
            "dl_bytes": sum(map(int, dl)), "ul_bytes": sum(map(int, ul)),
            "rntis": len(rs)}


def wait_state(running, timeout=30):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if http("/api/status")["state"]["running"] == running:
                return
        except Exception:
            pass
        time.sleep(1)


def save(phase, rows, aborted=None):
    json.dump({"phase": phase, "rows": rows, "aborted": aborted},
              open(f"/tmp/lna_reliable_{phase}.json", "w"), indent=2)


def main():
    phase = sys.argv[1]
    print(f"=== sniff experiment '{phase}' — {N_RUNS}x{RUN_SECONDS}s, RF-monitored ===", flush=True)
    http("/api/login", {"username": USER, "password": PASSWORD})
    wait_state(False)
    rows, ul_zero_streak = [], 0
    for i in range(1, N_RUNS + 1):
        st = http("/api/capture/start", method="POST")
        run_dir = st["state"]["run_dir"]
        wait_state(True)
        print(f"[run {i:2d}] started {run_dir}", flush=True)
        time.sleep(RUN_SECONDS)
        http("/api/capture/stop", method="POST")
        wait_state(False)
        time.sleep(SETTLE)
        m = pcap_metrics(run_dir)
        m["run"], m["run_dir"] = i, run_dir
        rows.append(m)
        save(phase, rows)
        print(f"[run {i:2d}] dlsch={m['dlsch']} dl_bytes={m['dl_bytes']} "
              f"ulsch={m['ulsch']} frames={m['mac_frames']} rntis={m['rntis']}", flush=True)

        # ---- RF-sequence health gates ----
        if m["dlsch"] == 0:
            msg = f"NO DL SIGNAL — run {i} decoded 0 DL-SCH. RF chain looks broken."
            print(f"\n!!! RF ALERT: {msg}\n!!! ABORTING after {i} run(s).", flush=True)
            save(phase, rows, aborted=msg)
            return
        ul_zero_streak = ul_zero_streak + 1 if m["ulsch"] == 0 else 0
        if ul_zero_streak >= 3:
            msg = (f"NO UL — {ul_zero_streak} consecutive runs with 0 UL-SCH "
                   f"(baseline always had UL). UL chain (LNA/pad/port) likely broken.")
            print(f"\n!!! RF ALERT: {msg}\n!!! ABORTING after {i} run(s).", flush=True)
            save(phase, rows, aborted=msg)
            return

    print("\n=== all runs healthy ===", flush=True)
    table(rows)


def table(rows):
    cols = [("run", "run"), ("dlsch", "DLSCH"), ("dl_bytes", "DL_bytes"),
            ("rntis", "RNTIs"), ("mac_frames", "MACfrm"),
            ("ulsch", "ULSCH"), ("ul_bytes", "UL_bytes")]
    hdr = " ".join(f"{h:>10}" for _, h in cols)
    print("\n" + hdr + "\n" + "-" * len(hdr))
    for r in rows:
        print(" ".join(f"{int(r.get(k, 0)):>10}" for k, _ in cols))
    print("-" * len(hdr))
    tot = {k: sum(r.get(k, 0) for r in rows) for k, _ in cols}
    n = len(rows)
    print(" ".join(f"{('SUM' if k == 'run' else int(tot[k])):>10}" for k, _ in cols))
    print(" ".join(f"{('MEAN' if k == 'run' else round(tot[k] / n, 1)):>10}" for k, _ in cols))


if __name__ == "__main__":
    main()
