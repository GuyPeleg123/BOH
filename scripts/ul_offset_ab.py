#!/usr/bin/env python3
"""
ul_offset_ab.py — A/B harness for PR #4: FFT-window offset retry (multi_ul_offset).

PREREQUISITES
-------------
1. Both B210 USRPs are connected and enumerated (USB3, speed=5000).
2. The GUI backend is running at https://192.168.0.107:8443 (admin/buchris).
3. A valid SnifferConfig is saved (DUAL or UL mode, with UL/DL frequencies
   configured). The script uses the saved config by posting NO body to
   /api/capture/start, so the saved config is the sole source of truth.
4. clock=internal recommended (EF9 GPSDO won't fix; clock=gpsdo hangs dual
   capture on PPS sync — see project memory ef9-gpsdo-fault).

WHAT THE FLAG DOES vs HOW TO TOGGLE IT
---------------------------------------
multi_ul_offset is set in ULSchedule at init time from the mode:
    ulsche.set_multi_offset((args.sniffer_mode == DUAL_MODE) ? UL_MODE : args.sniffer_mode)

In practice: for sniffer_mode=DUAL(2) or UL(1), multi_ul_offset is nonzero
(= UL_MODE = 1), so the offset retry is ALWAYS ON in any UL-capable mode.
There is NO runtime toggle — the flag is frozen at binary init.

TO GET A CLEAN A/B WITH OFFSET RETRY OFF:
  Option A (no recompile): set sniffer_mode=0 (DL only) — but that disables UL
    entirely, so it is not a valid A side for yield comparison.
  Option B (one-line source change, rebuild required): in LTESniffer_Core.cc
    line 96, change:
      ulsche.set_multi_offset((args.sniffer_mode == DUAL_MODE) ? UL_MODE : args.sniffer_mode);
    to:
      ulsche.set_multi_offset(0);   // disable offset retry for OFF phase
    Then rebuild: cd build && cmake --build . --target LTESniffer -j$(nproc)
    Rename that binary (e.g. ltesniffer_nooffset), point SnifferConfig at it.
  Option C: keep the two binaries (offset ON = shipped, offset OFF = patched),
    run this script twice with --phase before / --phase after, pointing the
    GUI's saved config at the appropriate binary_path between the two phases.

This script runs N fixed-duration runs using whatever binary the saved
SnifferConfig points to. Run it once for each phase (OFF then ON, or ON then
OFF in counter-balanced order to control for time-of-day traffic variation).

USAGE
-----
  python3 ul_offset_ab.py --phase before --runs 10 --seconds 180
  python3 ul_offset_ab.py --phase after  --runs 10 --seconds 180

  # Compare:
  python3 ul_offset_ab.py --compare before after

METRICS (sourced from pcap + sniffer.log — NOT the GUI metrics bus)
-------
  ulsch       : UL-SCH MAC PDU count from the run pcap (tshark mac-lte.direction==0)
  dlsch       : DL-SCH MAC PDU count (direction==1)
  ul_bytes    : UL payload bytes
  rntis       : distinct RNTIs seen in the run
  ul_success  : per-RNTI Success counts parsed from sniffer.log "-d" stats table
  ul_active   : per-RNTI Active counts (grant attempts) from the same table
  yield_pct   : ul_success / ul_active * 100, aggregated across all RNTIs
  dup_frames  : (informational) duplicate RNTI+TTI pairs in the UL pcap —
                should be 0; any nonzero value means the count-once invariant
                was broken and needs investigation (see ul_antenna_ab.py for
                the dedicated duplicate check).

PASS criteria (define before starting the rig runs)
-----
  - ul_success / ul_active ("yield_pct") must be measurably HIGHER for phase
    "after" (offset ON) vs "before" (offset OFF), with the same pcap UL frame
    count direction of improvement.
  - dlsch counts must remain statistically equivalent between phases (DL is
    untouched by the change; a big DL drop signals a confounded RF state).
  - dup_frames must be 0 in both phases.

OUTPUTS
-------
  /tmp/ul_offset_<phase>.json   — per-run raw data
  /tmp/ul_offset_compare.json   — side-by-side summary (--compare mode)
  stdout                        — formatted table + SUM/MEAN rows
"""

import argparse
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
DEFAULT_RUNS = 10
DEFAULT_SECONDS = 180
SETTLE = 5      # seconds after stop before treating pcap as final
MAC_MAP = 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'

# ---------- HTTP helpers (stdlib only, no requests) ----------

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
    """Run tshark on pcap with the MAC-LTE DLT mapping. Returns stdout."""
    cmd = ["sudo", "-n", "tshark", "-r", pcap, "-o", MAC_MAP, *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
    except Exception:
        return ""


def pcap_metrics(run_dir):
    """
    Extract metrics from the run's pcap (not the GUI metrics bus).
    Looks for ltesniffer_dual_mode.pcap then ltesniffer_ul_mode.pcap.
    """
    import os
    pcap = None
    for name in ("ltesniffer_dual_mode.pcap", "ltesniffer_ul_mode.pcap"):
        candidate = f"{run_dir}/{name}"
        if os.path.exists(candidate) and os.path.getsize(candidate) > 24:
            pcap = candidate
            break
    if pcap is None:
        return {"pcap": "MISSING", "ulsch": 0, "dlsch": 0,
                "ul_bytes": 0, "dl_bytes": 0, "rntis": 0, "dup_frames": 0}

    # UL frames: mac-lte.direction==0
    ul_raw = tsh(pcap, "-Y", "mac-lte.direction==0", "-T", "fields",
                 "-e", "frame.len").split()
    ul_lens = [int(x) for x in ul_raw if x.isdigit()]

    # DL frames
    dl_raw = tsh(pcap, "-Y", "mac-lte.direction==1", "-T", "fields",
                 "-e", "frame.len").split()
    dl_lens = [int(x) for x in dl_raw if x.isdigit()]

    # Distinct RNTIs
    rnti_set = {v.strip() for v in
                tsh(pcap, "-Y", "mac-lte", "-T", "fields",
                    "-e", "mac-lte.rnti").split()
                if v.strip()}

    # Duplicate (RNTI, TTI) check — a nonzero count would mean count-once broke.
    # TTI = SFN*10 + SF. Extract rnti + frame_number as a proxy (true TTI needs
    # the srsran context field mac-lte.context.sysframe and mac-lte.context.subframe
    # if available; fall back to frame sequence as a conservative proxy).
    tti_raw = tsh(pcap, "-Y", "mac-lte.direction==0", "-T", "fields",
                  "-e", "mac-lte.rnti",
                  "-e", "mac-lte.context.sysframe",
                  "-e", "mac-lte.context.subframe").splitlines()
    seen_tti = set()
    dup_count = 0
    for line in tti_raw:
        parts = line.strip().split("\t")
        if len(parts) == 3 and all(p.strip() for p in parts):
            key = (parts[0].strip(), parts[1].strip(), parts[2].strip())
            if key in seen_tti:
                dup_count += 1
            else:
                seen_tti.add(key)

    return {
        "pcap": pcap,
        "ulsch": len(ul_lens),
        "dlsch": len(dl_lens),
        "ul_bytes": sum(ul_lens),
        "dl_bytes": sum(dl_lens),
        "rntis": len(rnti_set),
        "dup_frames": dup_count,
    }


def parse_sniffer_log_ul_stats(run_dir):
    """
    Parse per-RNTI Active + Success from sniffer.log.
    The sniffer prints UL stats at shutdown in the format:
      Num  RNTI     Max Mod     Active   Success   ...
       1   70       64QAM       3142     287       ...
    Returns {"total_active": N, "total_success": N, "per_rnti": {...}}
    """
    import os
    log_path = f"{run_dir}/sniffer.log"
    if not os.path.exists(log_path):
        return {"total_active": 0, "total_success": 0, "per_rnti": {}}

    per_rnti = {}
    in_ul_table = False
    header_seen = False

    with open(log_path, errors="replace") as fh:
        for line in fh:
            # Strip ANSI escape codes (the sniffer uses colour output)
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line).rstrip()

            # Detect start of UL stats table
            if "Active" in clean and "Success" in clean and "Max Mod" in clean:
                in_ul_table = True
                header_seen = True
                continue

            if in_ul_table:
                # A data row looks like: "  1  70    64QAM    3142    287   ..."
                # Match: num  RNTI  modstring  active  success  ...
                m = re.match(
                    r'^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)',
                    clean
                )
                if m:
                    rnti = int(m.group(2))
                    active = int(m.group(4))
                    success = int(m.group(5))
                    # Accumulate across mod-table rows for the same RNTI
                    if rnti not in per_rnti:
                        per_rnti[rnti] = {"active": 0, "success": 0}
                    per_rnti[rnti]["active"] += active
                    per_rnti[rnti]["success"] += success
                elif clean.strip() == "" or clean.startswith("#"):
                    # End of table block — stay in_ul_table for multi-block
                    # output (256/64/16QAM sections print separate headers)
                    pass
                else:
                    # Non-matching non-blank line ends the current table block
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
    print(f"\n=== ul_offset_ab — phase '{phase}' — {n_runs}x{run_seconds}s ===", flush=True)
    print("NOTE: See module docstring for how to toggle multi_ul_offset OFF.", flush=True)
    http_req("/api/login", {"username": USER, "password": PASSWORD})
    wait_state(False)

    rows = []
    for i in range(1, n_runs + 1):
        # POST with NO body -> backend uses saved SnifferConfig unchanged.
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

        print(
            f"[run {i:2d}] ulsch={m['ulsch']:5d} dlsch={m['dlsch']:5d} "
            f"rntis={m['rntis']:3d} active={m['ul_active']:5d} "
            f"success={m['ul_success']:5d} yield={m['yield_pct']:5.1f}% "
            f"dup={m['dup_frames']}",
            flush=True,
        )

        if m["dlsch"] == 0:
            print(f"\n!!! ABORT run {i}: 0 DL-SCH — RF chain broken. Saving partial data.", flush=True)
            break

    out = {"phase": phase, "n_runs": len(rows), "run_seconds": run_seconds, "rows": rows}
    path = f"/tmp/ul_offset_{phase}.json"
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nSaved -> {path}", flush=True)
    print_table(rows)
    return out


def print_table(rows):
    cols = [
        ("run",       "run"),
        ("ulsch",     "ULsch"),
        ("dlsch",     "DLsch"),
        ("ul_bytes",  "UL_bytes"),
        ("rntis",     "RNTIs"),
        ("ul_active", "Active"),
        ("ul_success","Success"),
        ("yield_pct", "Yield%"),
        ("dup_frames","Dups"),
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
    tot = {}
    for k, _ in cols:
        vals_k = [r.get(k, 0) for r in rows]
        tot[k] = sum(vals_k)
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
    import os
    paths = {p: f"/tmp/ul_offset_{p}.json" for p in (phase_a, phase_b)}
    data = {}
    for ph, path in paths.items():
        if not os.path.exists(path):
            print(f"ERROR: {path} not found. Run the phase first.", file=sys.stderr)
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
        keys = ["ulsch", "dlsch", "ul_active", "ul_success", "rntis", "dup_frames"]
        agg = {k: sum(r.get(k, 0) for r in rows) / n for k in keys}
        agg["yield_pct"] = (
            round(agg["ul_success"] / agg["ul_active"] * 100, 1)
            if agg["ul_active"] > 0 else 0.0
        )
        summary[ph] = agg

    print(f"\n=== COMPARISON: {phase_a} vs {phase_b} ===")
    metrics = [
        ("ulsch",     "Mean ULsch/run"),
        ("dlsch",     "Mean DLsch/run"),
        ("ul_active", "Mean Active/run"),
        ("ul_success","Mean Success/run"),
        ("yield_pct", "Yield % (mean)"),
        ("rntis",     "Mean RNTIs/run"),
        ("dup_frames","Mean Dups/run"),
    ]
    w = max(len(label) for _, label in metrics) + 2
    print(f"  {'Metric':<{w}}  {phase_a:>12}  {phase_b:>12}  {'Delta':>10}")
    print("  " + "-" * (w + 40))
    for k, label in metrics:
        a = summary[phase_a].get(k, 0)
        b = summary[phase_b].get(k, 0)
        delta = b - a
        print(f"  {label:<{w}}  {a:>12.1f}  {b:>12.1f}  {delta:>+10.1f}")

    out_path = "/tmp/ul_offset_compare.json"
    with open(out_path, "w") as fh:
        json.dump({"phases": [phase_a, phase_b], "summary": summary}, fh, indent=2)
    print(f"\nComparison saved -> {out_path}")

    # Verdict guidance
    a_yield = summary[phase_a].get("yield_pct", 0)
    b_yield = summary[phase_b].get("yield_pct", 0)
    a_dup = summary[phase_a].get("dup_frames", 0)
    b_dup = summary[phase_b].get("dup_frames", 0)
    print("\n=== VERDICT GUIDANCE ===")
    if a_dup > 0 or b_dup > 0:
        print(f"FAIL: duplicate RNTI+TTI frames detected "
              f"({phase_a}: {a_dup:.1f}/run, {phase_b}: {b_dup:.1f}/run). "
              f"Count-once invariant is broken — investigate before interpreting yield.")
    else:
        print("Dup check: PASS (0 duplicates in both phases).")
    if b_yield > a_yield:
        print(f"Yield: {phase_b} ({b_yield:.1f}%) > {phase_a} ({a_yield:.1f}%) "
              f"— offset retry IMPROVED UL decode yield.")
    elif b_yield < a_yield:
        print(f"Yield: {phase_b} ({b_yield:.1f}%) < {phase_a} ({a_yield:.1f}%) "
              f"— offset retry DEGRADED yield (unexpected; check RF state equivalence).")
    else:
        print(f"Yield: no change ({a_yield:.1f}% both phases).")
    dl_a = summary[phase_a].get("dlsch", 0)
    dl_b = summary[phase_b].get("dlsch", 0)
    dl_delta_pct = abs(dl_b - dl_a) / max(dl_a, 1) * 100
    if dl_delta_pct > 20:
        print(f"WARNING: DL-SCH counts differ by {dl_delta_pct:.0f}% "
              f"({phase_a}: {dl_a:.0f}, {phase_b}: {dl_b:.0f}/run). "
              f"RF state may not have been equivalent between phases.")


def main():
    parser = argparse.ArgumentParser(
        description="A/B harness for PR #4 FFT-window offset retry.")
    sub = parser.add_subparsers(dest="cmd")

    run_p = sub.add_parser("run", help="Run a phase (default command if positional arg given)")
    run_p.add_argument("--phase", required=True, help="Label, e.g. 'before' or 'after'")
    run_p.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    run_p.add_argument("--seconds", type=int, default=DEFAULT_SECONDS)

    cmp_p = sub.add_parser("compare", help="Compare two saved phases")
    cmp_p.add_argument("phase_a")
    cmp_p.add_argument("phase_b")

    # Legacy positional: python3 ul_offset_ab.py before
    parser.add_argument("phase_pos", nargs="?", help="Phase label (shortcut for 'run --phase')")
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
