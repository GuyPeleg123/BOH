#!/usr/bin/env python3
"""
ul_antenna_ab.py — A/B harness for issue #7: second UL RX antenna (decoder_b)
as a per-grant fallback in PUSCH_Decoder::decode().

PREREQUISITES
-------------
1. Both B210 USRPs are connected and enumerated (USB3, speed=5000).
2. The GUI backend is running at https://192.168.0.107:8443 (admin/buchris).
3. A valid SnifferConfig is saved with sniffer_mode=DUAL (2).
   For -A 1 (antenna A only): saved config must have rf_nof_rx_ant=1 OR the
   fallback_decoder pointer will be null (no decoder_b constructed) — verify
   by checking SubframeWorker constructor: decoder_b is only constructed when
   rf_nof_rx_ant >= 2.
4. clock=internal recommended (EF9 GPSDO fault; see project memory).

WHAT ISSUE #7 DOES
-------------------
Before #7: decoder_b (USRP RX antenna port 1) was constructed but its
decode() was commented out — antenna B was dead weight.

After #7 (current working tree, NOT yet committed):
  - decoder_a runs its grant loop (nominal + offset-retry via PR #4).
  - For any grant that FAILS on antenna A, decoder_a calls
    fallback_decoder->try_grant_fallback(), which lazily prepares antenna B's
    FFT (first call per subframe only) and runs the same nominal+retry unit.
  - Side effects (pcap write, key store, MCS update) fire inside decode_run
    exactly once, regardless of which antenna succeeds.
  - Statistics are counted by decoder_a's update_statistic_ul — one entry per
    grant, not two.

HOW TO A/B WITHOUT A REBUILD
------------------------------
The fallback is gated on fallback_decoder != nullptr.
  Phase A (-A 1 / single antenna): set rf_nof_rx_ant=1 in the saved
    SnifferConfig. SubframeWorker only constructs puschdecoder_b when
    rf_nof_rx_ant >= 2, so set_fallback_decoder is never called and
    fallback_decoder stays nullptr.
  Phase B (-A 2 / dual antenna fallback): set rf_nof_rx_ant=2.

Update the GUI's saved SnifferConfig between phases (change "ul_rx_antennas"
or the equivalent rf_nof_rx_ant field) and re-run this script with a different
--phase label. The saved config is used unchanged (no body in start POST).

Alternatively verify in config.py:
    grep rf_nof_rx_ant gui/backend/config.py

USAGE
-----
  # Phase A: single UL antenna (verify SnifferConfig has rf_nof_rx_ant=1)
  python3 ul_antenna_ab.py --phase ant1 --runs 10 --seconds 180

  # Phase B: dual UL antenna fallback (set rf_nof_rx_ant=2 in SnifferConfig)
  python3 ul_antenna_ab.py --phase ant2 --runs 10 --seconds 180

  # Compare:
  python3 ul_antenna_ab.py compare ant1 ant2

METRICS (all sourced from pcap + sniffer.log — not the GUI metrics bus)
-------
  ulsch        : UL-SCH MAC PDU count (mac-lte.direction==0)
  dlsch        : DL-SCH MAC PDU count
  ul_active    : total Active grant attempts (from sniffer.log UL stats table)
  ul_success   : total Success decodes (same source)
  yield_pct    : ul_success / ul_active * 100
  rntis        : distinct RNTIs seen in the run
  dup_count    : duplicate (RNTI, SFN, SF) tuples in the UL pcap — MUST be 0.
                 A nonzero value means decoder_a and decoder_b both wrote a
                 pcap entry for the same grant, breaking the count-once
                 invariant. This is the critical regression check for #7.
  dup_rntis    : list of RNTIs that contributed duplicate frames (for triage)

PASS criteria
-------------
  1. dup_count == 0 in BOTH phases. Any nonzero value is an immediate FAIL
     for #7 — the fallback path is double-writing to the pcap.
  2. yield_pct must be HIGHER for phase ant2 than ant1 (antenna B fallback
     should recover grants that A missed).
  3. dlsch counts must be statistically equivalent (DL path is unchanged).
  4. ul_active counts should be comparable (same cell, same traffic load);
     a big difference suggests the config was not equivalent between phases.

OUTPUTS
-------
  /tmp/ul_antenna_<phase>.json   — per-run raw data
  /tmp/ul_antenna_compare.json   — side-by-side summary (compare mode)
  stdout                         — formatted table + SUM/MEAN rows
"""

import argparse
import http.cookiejar
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.request

BASE = "https://192.168.0.107:8443"
USER, PASSWORD = "admin", "buchris"
DEFAULT_RUNS = 10
DEFAULT_SECONDS = 180
SETTLE = 5
MAC_MAP = 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'

# ---------- HTTP helpers ----------

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_jar = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_ctx),
    urllib.request.HTTPCookieProcessor(_jar),
)


def http_req(path, body=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    m = method or ("POST" if data is not None else "GET")
    req = urllib.request.Request(BASE + path, data=data, method=m)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with _opener.open(req, timeout=30) as r:
        raw = r.read().decode()
    return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw


def wait_state(running, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if http_req("/api/status")["state"]["running"] == running:
                return
        except Exception:
            pass
        time.sleep(1)


# ---------- tshark helpers ----------

def tsh(pcap, *args):
    cmd = ["sudo", "-n", "tshark", "-r", pcap, "-o", MAC_MAP, *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
    except Exception:
        return ""


def find_pcap(run_dir):
    for name in ("ltesniffer_dual_mode.pcap", "ltesniffer_ul_mode.pcap"):
        path = os.path.join(run_dir, name)
        if os.path.exists(path) and os.path.getsize(path) > 24:
            return path
    return None


def duplicate_check(pcap):
    """
    Check for duplicate (RNTI, SFN, SF) tuples in UL frames.
    These would indicate a double-write from decoder_a and decoder_b for the
    same grant — the critical regression for issue #7.

    Returns: (dup_count: int, dup_rntis: list[str])
    """
    raw = tsh(pcap, "-Y", "mac-lte.direction==0",
              "-T", "fields",
              "-e", "mac-lte.rnti",
              "-e", "mac-lte.context.sysframe",
              "-e", "mac-lte.context.subframe").splitlines()
    seen = set()
    dups = 0
    dup_rntis = set()
    for line in raw:
        parts = line.strip().split("\t")
        if len(parts) == 3 and all(p.strip() for p in parts):
            key = tuple(p.strip() for p in parts)
            if key in seen:
                dups += 1
                dup_rntis.add(parts[0].strip())
            else:
                seen.add(key)
    return dups, sorted(dup_rntis)


def pcap_metrics(run_dir):
    pcap = find_pcap(run_dir)
    if pcap is None:
        return {"pcap": "MISSING", "ulsch": 0, "dlsch": 0,
                "ul_bytes": 0, "dl_bytes": 0, "rntis": 0,
                "dup_count": 0, "dup_rntis": []}

    ul_raw = tsh(pcap, "-Y", "mac-lte.direction==0", "-T", "fields",
                 "-e", "frame.len").split()
    ul_lens = [int(x) for x in ul_raw if x.isdigit()]

    dl_raw = tsh(pcap, "-Y", "mac-lte.direction==1", "-T", "fields",
                 "-e", "frame.len").split()
    dl_lens = [int(x) for x in dl_raw if x.isdigit()]

    rnti_set = {v.strip() for v in
                tsh(pcap, "-Y", "mac-lte", "-T", "fields",
                    "-e", "mac-lte.rnti").split()
                if v.strip()}

    dup_count, dup_rntis = duplicate_check(pcap)

    return {
        "pcap": pcap,
        "ulsch": len(ul_lens),
        "dlsch": len(dl_lens),
        "ul_bytes": sum(ul_lens),
        "dl_bytes": sum(dl_lens),
        "rntis": len(rnti_set),
        "dup_count": dup_count,
        "dup_rntis": dup_rntis,
    }


def parse_sniffer_log_ul_stats(run_dir):
    """
    Parse per-RNTI Active + Success from sniffer.log UL stats table.
    Format (after stripping ANSI):
      Num  RNTI  Max Mod  Active  Success  SNR(dB)  DL-UL_delay  Other_Info
       1   70   64QAM    3142    287      12.3     +0.123       0
    Returns {"total_active": N, "total_success": N, "per_rnti": {...}}
    """
    log_path = os.path.join(run_dir, "sniffer.log")
    if not os.path.exists(log_path):
        return {"total_active": 0, "total_success": 0, "per_rnti": {}}

    per_rnti = {}
    in_ul_table = False

    with open(log_path, errors="replace") as fh:
        for line in fh:
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line).rstrip()

            if "Active" in clean and "Success" in clean and "Max Mod" in clean:
                in_ul_table = True
                continue

            if in_ul_table:
                m = re.match(
                    r'^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)',
                    clean
                )
                if m:
                    rnti = int(m.group(2))
                    active = int(m.group(4))
                    success = int(m.group(5))
                    if rnti not in per_rnti:
                        per_rnti[rnti] = {"active": 0, "success": 0}
                    per_rnti[rnti]["active"] += active
                    per_rnti[rnti]["success"] += success
                elif clean.strip() == "" or clean.startswith("#"):
                    pass
                else:
                    in_ul_table = False

    total_active = sum(v["active"] for v in per_rnti.values())
    total_success = sum(v["success"] for v in per_rnti.values())
    return {
        "total_active": total_active,
        "total_success": total_success,
        "per_rnti": {str(r): v for r, v in per_rnti.items()},
    }


# ---------- Main run loop ----------

def run_phase(phase, n_runs, run_seconds):
    print(f"\n=== ul_antenna_ab — phase '{phase}' — {n_runs}x{run_seconds}s ===", flush=True)
    print("CRITICAL: verify SnifferConfig rf_nof_rx_ant matches this phase.", flush=True)
    print("  ant1 phase: rf_nof_rx_ant=1 (no fallback_decoder)", flush=True)
    print("  ant2 phase: rf_nof_rx_ant=2 (fallback_decoder active)", flush=True)
    http_req("/api/login", {"username": USER, "password": PASSWORD})
    wait_state(False)

    rows = []
    abort_msg = None
    for i in range(1, n_runs + 1):
        # No body -> backend uses saved SnifferConfig.
        st = http_req("/api/capture/start", method="POST")
        run_dir = st["state"]["run_dir"]
        wait_state(True)
        print(f"[run {i:2d}] started dir={run_dir}", flush=True)

        time.sleep(run_seconds)

        http_req("/api/capture/stop", method="POST")
        wait_state(False)
        time.sleep(SETTLE)

        m = pcap_metrics(run_dir)
        ul_stats = parse_sniffer_log_ul_stats(run_dir)
        m["run"] = i
        m["run_dir"] = run_dir
        m["ul_active"] = ul_stats["total_active"]
        m["ul_success"] = ul_stats["total_success"]
        m["yield_pct"] = (
            round(ul_stats["total_success"] / ul_stats["total_active"] * 100, 1)
            if ul_stats["total_active"] > 0 else 0.0
        )

        rows.append(m)

        dup_flag = " *** DUP ALERT ***" if m["dup_count"] > 0 else ""
        print(
            f"[run {i:2d}] ulsch={m['ulsch']:5d} dlsch={m['dlsch']:5d} "
            f"active={m['ul_active']:5d} success={m['ul_success']:5d} "
            f"yield={m['yield_pct']:5.1f}% rntis={m['rntis']:3d} "
            f"dup={m['dup_count']}{dup_flag}",
            flush=True,
        )
        if m["dup_rntis"]:
            print(f"         dup RNTIs: {m['dup_rntis']}", flush=True)

        # Hard abort if DL disappears — RF chain broken
        if m["dlsch"] == 0:
            abort_msg = f"0 DL-SCH on run {i} — RF chain broken"
            print(f"\n!!! ABORT: {abort_msg}. Saving partial data.", flush=True)
            break

    out = {
        "phase": phase,
        "n_runs": len(rows),
        "run_seconds": run_seconds,
        "rows": rows,
        "aborted": abort_msg,
    }
    path = f"/tmp/ul_antenna_{phase}.json"
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nSaved -> {path}", flush=True)
    print_table(rows)
    return out


def print_table(rows):
    cols = [
        ("run",        "run"),
        ("ulsch",      "ULsch"),
        ("dlsch",      "DLsch"),
        ("ul_active",  "Active"),
        ("ul_success", "Success"),
        ("yield_pct",  "Yield%"),
        ("rntis",      "RNTIs"),
        ("dup_count",  "Dups"),
    ]
    hdr = " ".join(f"{h:>10}" for _, h in cols)
    print("\n" + hdr)
    print("-" * len(hdr))
    for r in rows:
        vals = []
        for k, _ in cols:
            v = r.get(k, 0)
            vals.append(f"{v:>10.1f}" if isinstance(v, float) else f"{int(v):>10}")
        print("".join(vals))
    print("-" * len(hdr))
    n = len(rows)
    if n == 0:
        return
    tot = {k: sum(r.get(k, 0) for r in rows) for k, _ in cols}
    print(" ".join(
        f"{'SUM':>10}" if k == "run" else
        f"{tot[k]:>10.1f}" if isinstance(rows[0].get(k, 0), float) else
        f"{int(tot[k]):>10}"
        for k, _ in cols
    ))
    print(" ".join(
        f"{'MEAN':>10}" if k == "run" else
        f"{tot[k]/n:>10.1f}"
        for k, _ in cols
    ))


def compare_phases(phase_a, phase_b):
    paths = {p: f"/tmp/ul_antenna_{p}.json" for p in (phase_a, phase_b)}
    data = {}
    for ph, path in paths.items():
        if not os.path.exists(path):
            print(f"ERROR: {path} not found.", file=sys.stderr)
            sys.exit(1)
        with open(path) as fh:
            data[ph] = json.load(fh)

    summary = {}
    for ph in (phase_a, phase_b):
        rows = data[ph]["rows"]
        n = len(rows)
        if n == 0:
            summary[ph] = {}
            continue
        keys = ["ulsch", "dlsch", "ul_active", "ul_success", "rntis", "dup_count"]
        agg = {k: sum(r.get(k, 0) for r in rows) / n for k in keys}
        agg["yield_pct"] = (
            round(agg["ul_success"] / agg["ul_active"] * 100, 1)
            if agg["ul_active"] > 0 else 0.0
        )
        summary[ph] = agg

    print(f"\n=== COMPARISON: {phase_a} vs {phase_b} ===")
    metrics = [
        ("ulsch",      "Mean ULsch/run"),
        ("dlsch",      "Mean DLsch/run"),
        ("ul_active",  "Mean Active/run"),
        ("ul_success", "Mean Success/run"),
        ("yield_pct",  "Yield % (mean)"),
        ("rntis",      "Mean RNTIs/run"),
        ("dup_count",  "Mean Dups/run"),
    ]
    w = max(len(label) for _, label in metrics) + 2
    print(f"  {'Metric':<{w}}  {phase_a:>12}  {phase_b:>12}  {'Delta':>10}")
    print("  " + "-" * (w + 40))
    for k, label in metrics:
        a = summary[phase_a].get(k, 0)
        b = summary[phase_b].get(k, 0)
        delta = b - a
        print(f"  {label:<{w}}  {a:>12.1f}  {b:>12.1f}  {delta:>+10.1f}")

    out_path = "/tmp/ul_antenna_compare.json"
    with open(out_path, "w") as fh:
        json.dump({"phases": [phase_a, phase_b], "summary": summary}, fh, indent=2)
    print(f"\nComparison saved -> {out_path}")

    # Verdict
    a_dup = summary[phase_a].get("dup_count", 0)
    b_dup = summary[phase_b].get("dup_count", 0)
    a_yield = summary[phase_a].get("yield_pct", 0)
    b_yield = summary[phase_b].get("yield_pct", 0)

    print("\n=== VERDICT GUIDANCE ===")
    # Dup check is the primary gate
    if a_dup > 0 or b_dup > 0:
        print(f"FAIL (count-once): duplicate RNTI+TTI frames found — "
              f"{phase_a}: {a_dup:.1f}/run, {phase_b}: {b_dup:.1f}/run. "
              f"decoder_b is double-writing pcap entries. "
              f"Check try_grant_fallback / decode_run call path.")
    else:
        print("Count-once check: PASS — 0 duplicate RNTI+TTI frames in both phases.")

    if b_yield > a_yield:
        print(f"Yield: {phase_b} ({b_yield:.1f}%) > {phase_a} ({a_yield:.1f}%) "
              f"— antenna B fallback IMPROVED UL yield.")
    elif b_yield < a_yield:
        print(f"Yield: {phase_b} ({b_yield:.1f}%) < {phase_a} ({a_yield:.1f}%) "
              f"— unexpected regression; check RF setup equivalence.")
    else:
        print(f"Yield: unchanged ({a_yield:.1f}% both phases).")

    dl_a = summary[phase_a].get("dlsch", 0)
    dl_b = summary[phase_b].get("dlsch", 0)
    if max(dl_a, dl_b, 1) > 0:
        dl_delta_pct = abs(dl_b - dl_a) / max(dl_a, 1) * 100
        if dl_delta_pct > 20:
            print(f"WARNING: DL-SCH counts differ by {dl_delta_pct:.0f}% between phases "
                  f"({phase_a}: {dl_a:.0f}, {phase_b}: {dl_b:.0f}/run). "
                  f"RF state or traffic load may not have been equivalent.")


def main():
    parser = argparse.ArgumentParser(
        description="A/B harness for issue #7: decoder_b per-grant UL fallback.")
    sub = parser.add_subparsers(dest="cmd")

    run_p = sub.add_parser("run", help="Run a phase")
    run_p.add_argument("--phase", required=True)
    run_p.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    run_p.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)

    cmp_p = sub.add_parser("compare", help="Compare two phases")
    cmp_p.add_argument("phase_a")
    cmp_p.add_argument("phase_b")

    # Legacy positional shortcut
    parser.add_argument("phase_pos", nargs="?")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)

    args = parser.parse_args()

    if args.cmd == "compare":
        compare_phases(args.phase_a, args.phase_b)
    elif args.cmd == "run":
        run_phase(args.phase, args.runs, args.seconds)
    elif args.phase_pos:
        run_phase(args.phase_pos, args.runs, args.seconds)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
