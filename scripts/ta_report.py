#!/usr/bin/env python3
"""ta_report.py — derive per-UE distance-from-cell from Timing Advance in a
LTESniffer MAC-LTE pcap.

TA is a *range*, not a position: it gives the round-trip propagation delay
between the cell and the UE, i.e. a ring around the eNB. One TA step ≈ 78.07 m
(one-way). Without the cell's GPS location + angle-of-arrival you cannot get a
lat/lon — this reports distance only.

Two sources:
  * RAR Timing Advance (mac-lte.rar.ta): the 11-bit *absolute* TA the network
    hands a UE during random access. range_m = ta * 78.07. This is the primary
    location signal and is present even in DL-only captures.
  * TA Command MAC CE (mac-lte.control.timing-advance.command): a 6-bit
    *relative* adjustment in connected mode (31 = no change). Summed per RNTI it
    tracks how a UE's range drifts; 31-only means the UE stayed put / aligned.

Usage: ta_report.py <pcap> [--csv out.csv]
"""
import argparse
import subprocess
import sys
from collections import defaultdict

# One TA step = 16 * Ts, Ts = 1/(15000*2048) s. Round-trip; halve for one-way.
TS = 1.0 / (15000 * 2048)
C = 299_792_458.0
METERS_PER_TA = 16 * TS * C / 2.0  # ≈ 78.07 m


def _tshark(pcap, dfilter, fields):
    cmd = ["tshark", "-r", pcap, "-Y", dfilter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    rows = []
    for line in out.stdout.splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--csv", help="write per-RAR rows to this CSV")
    args = ap.parse_args()

    # --- RAR absolute TA -> range -------------------------------------------
    # RAR has no dissected Temp C-RNTI field; the RAPID (preamble id) is the
    # only per-access discriminator tshark exposes here.
    rar = _tshark(args.pcap,
                  "mac-lte.rar.ta",
                  ["frame.number", "frame.time_relative",
                   "mac-lte.rar.rapid", "mac-lte.rar.ta"])
    samples = []
    for r in rar:
        r = (r + ["", "", "", ""])[:4]
        fn, t, rapid, ta = r
        # a frame can carry several RAR TAs (comma-joined by tshark)
        tas = [x for x in ta.split(",") if x.strip()]
        rapids = rapid.split(",") if rapid else []
        for i, tav in enumerate(tas):
            try:
                tav = int(tav)
            except ValueError:
                continue
            rp = rapids[i] if i < len(rapids) else (rapids[0] if rapids else "")
            samples.append({
                "frame": fn,
                "t": float(t) if t else 0.0,
                "rapid": rp,
                "ta": tav,
                "range_m": tav * METERS_PER_TA,
            })

    # --- connected-mode TA Command CEs (relative drift per RNTI) ------------
    cmds = _tshark(args.pcap,
                   "mac-lte.control.timing-advance.command",
                   ["mac-lte.rnti", "mac-lte.control.timing-advance.command"])
    drift = defaultdict(lambda: {"n": 0, "nonzero": 0, "net_steps": 0})
    for r in cmds:
        if len(r) < 2 or not r[1]:
            continue
        rnti = r[0]
        for cv in r[1].split(","):
            try:
                cv = int(cv)
            except ValueError:
                continue
            d = drift[rnti]
            d["n"] += 1
            if cv != 31:           # 31 = no correction needed
                d["nonzero"] += 1
                d["net_steps"] += (cv - 31)

    # --- report -------------------------------------------------------------
    print(f"pcap: {args.pcap}")
    print(f"TA step = {METERS_PER_TA:.2f} m (one-way)\n")

    if not samples:
        print("No RAR Timing Advance found — no UE performed random access in "
              "this capture (or RACH/RAR wasn't decoded). Nothing to range.")
    else:
        ranges = sorted(s["range_m"] for s in samples)
        n = len(ranges)
        print(f"=== RAR-based UE ranges (absolute distance from cell) — {n} access events ===")
        print(f"  closest : {ranges[0]:8.0f} m  (TA {round(ranges[0]/METERS_PER_TA)})")
        print(f"  median  : {ranges[n//2]:8.0f} m")
        print(f"  farthest: {ranges[-1]:8.0f} m  (TA {round(ranges[-1]/METERS_PER_TA)})")
        print(f"  mean    : {sum(ranges)/n:8.0f} m\n")

        # coarse histogram by 500 m bins
        print("  distance histogram (500 m bins):")
        bins = defaultdict(int)
        for rm in ranges:
            bins[int(rm // 500)] += 1
        for b in sorted(bins):
            lo, hi = b * 500, (b + 1) * 500
            bar = "#" * min(60, bins[b])
            print(f"    {lo:5d}-{hi:5d} m | {bins[b]:4d} {bar}")

        # distinct UEs by temp C-RNTI, with their first-seen range
        by_ue = {}
        for s in sorted(samples, key=lambda s: s["t"]):
            key = s["rapid"] or f"frame{s['frame']}"
            by_ue.setdefault(key, s)
        print(f"\n  distinct access events by RAPID (preamble id): {len(by_ue)}")
        print(f"\n  {'rapid':>10}  {'t(s)':>8}  {'TA':>4}  {'range(m)':>9}")
        for key, s in sorted(by_ue.items(), key=lambda kv: kv[1]["range_m"])[:40]:
            print(f"  {key:>10}  {s['t']:8.2f}  {s['ta']:4d}  {s['range_m']:9.0f}")
        if len(by_ue) > 40:
            print(f"    … {len(by_ue)-40} more")

    if drift:
        moved = {r: d for r, d in drift.items() if d["nonzero"] > 0}
        print(f"\n=== connected-mode TA drift — {len(drift)} RNTIs sent TA commands, "
              f"{len(moved)} actually corrected ===")
        if moved:
            print(f"  {'RNTI':>6}  {'cmds':>5}  {'corrected':>9}  {'net drift(m)':>12}")
            for rnti, d in sorted(moved.items(), key=lambda kv: -abs(kv[1]["net_steps"]))[:20]:
                print(f"  {rnti:>6}  {d['n']:5d}  {d['nonzero']:9d}  {d['net_steps']*METERS_PER_TA:12.0f}")
        else:
            print("  all commands were 31 (no correction) — UEs stayed range-aligned.")

    if args.csv and samples:
        with open(args.csv, "w") as f:
            f.write("frame,t_rel_s,rapid,ta,range_m\n")
            for s in samples:
                f.write(f"{s['frame']},{s['t']:.4f},{s['rapid']},{s['ta']},{s['range_m']:.1f}\n")
        print(f"\nwrote {len(samples)} rows to {args.csv}")


if __name__ == "__main__":
    sys.exit(main())
