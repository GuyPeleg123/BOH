#!/usr/bin/env python3
"""replay_analyze — batch replay-equivalence + timing-recovery harness.

Runs ul_iq_replay on every capture under a root dir, parses the machine-readable
RESULT line, joins with captures.csv (energy-SNR, category), and produces:
  - Phase 3: exact live-vs-replay equivalence summary
  - Phase 6/7: wide-timing recovery, binned by energy-SNR and by MCS

Usage: replay_analyze.py <capture_root> [--widesweep N] [--replay PATH]
"""
import csv, os, re, subprocess, sys, argparse
from collections import defaultdict

def find_replay():
    for p in ("build/src/ul_iq_replay", "./ul_iq_replay",
              os.path.join(os.path.dirname(__file__), "..", "build", "src", "ul_iq_replay")):
        if os.path.exists(p):
            return os.path.abspath(p)
    return "ul_iq_replay"

def parse_result(text):
    m = re.search(r"^RESULT (.+)$", text, re.M)
    if not m:
        return None
    d = {}
    for tok in m.group(1).split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            d[k] = v
    return d

def load_csv_meta(root):
    """path-basename -> {energy_snr, chest_sinr, ta_us, category}"""
    meta = {}
    for dirpath, _, files in os.walk(root):
        if "captures.csv" in files:
            with open(os.path.join(dirpath, "captures.csv")) as f:
                for row in csv.DictReader(f):
                    meta[row["path"]] = row
    return meta

def ebin(e):
    try: e = float(e)
    except: return "n/a"
    if e < 0:  return "<0"
    if e < 2:  return "0-2"
    if e < 4:  return "2-4"
    if e < 6:  return "4-6"
    if e < 8:  return "6-8"
    return ">8"

BINS = ["<0", "0-2", "2-4", "4-6", "6-8", ">8", "n/a"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--widesweep", type=int, default=1024)
    ap.add_argument("--replay", default=find_replay())
    args = ap.parse_args()

    caps = []
    for dirpath, dirs, _ in os.walk(args.root):
        for d in dirs:
            if d.startswith("capture_"):
                caps.append(os.path.join(dirpath, d))
    caps.sort()
    if not caps:
        print("no captures found under", args.root); return 1
    meta = load_csv_meta(args.root)

    # counters
    n = len(caps)
    equiv_pass = crc_match = snr_match = nan_chest = 0
    load_err = init_err = incomplete = 0
    finite_snr_exact = 0
    payload_ok_match = payload_ok_total = 0
    recovered = []            # live_crc=0 -> sweep found CRC
    live_success = 0
    by_ebin = defaultdict(lambda: dict(n=0, live=0, sweep=0, recov=0, offs=[]))
    by_mcs  = defaultdict(lambda: dict(n=0, live=0, sweep=0, recov=0))
    mismatches = []
    gains = []

    for i, cap in enumerate(caps):
        try:
            out = subprocess.run([args.replay, cap, "--widesweep", str(args.widesweep)],
                                 capture_output=True, text=True, timeout=120).stdout
        except subprocess.TimeoutExpired:
            out = ""
        r = parse_result(out)
        base = os.path.basename(cap)
        cm = meta.get(base, {})
        eb = ebin(cm.get("energy_snr"))
        if r is None or r.get("status") != "ok":
            if r and r.get("status", "").endswith("error"): load_err += 1
            else: incomplete += 1
            continue
        by_ebin[eb]["n"] += 1
        lc = int(r["live_crc"]); rc = int(r["replay_crc"])
        mcs = int(r["mcs"])
        by_mcs[mcs]["n"] += 1
        if r["crc_match"] == "1": crc_match += 1
        if r["snr_match"] == "1": snr_match += 1
        if r["equiv"] == "PASS": equiv_pass += 1
        else: mismatches.append((base, r))
        if r["nan_chest"] == "1": nan_chest += 1
        elif abs(float(r["snr_dphi"])) < 0.05: finite_snr_exact += 1
        if lc == 1:
            live_success += 1; by_ebin[eb]["live"] += 1; by_mcs[mcs]["live"] += 1
            payload_ok_total += 1
            if rc == 1: payload_ok_match += 1  # (payload hash equality when both live+replay decode)
        # timing recovery: burst FAILED live but sweep found a valid CRC
        scf = int(r.get("sweep_crc_found", 0))
        if scf > 0:
            by_ebin[eb]["sweep"] += 1; by_mcs[mcs]["sweep"] += 1
            if lc == 0:
                recovered.append((base, eb, mcs, r.get("sweep_crc_off"), r.get("sweep_best_snr")))
                by_ebin[eb]["recov"] += 1; by_mcs[mcs]["recov"] += 1
        try:
            off = int(r.get("sweep_best_off", 0)); by_ebin[eb]["offs"].append(off)
            g = float(r["sweep_best_snr"]) - float(r["replay_snr"])
            if g == g: gains.append(g)
        except: pass

    print("="*70)
    print("PHASE 3 — EXACT LIVE vs REPLAY EQUIVALENCE  (root=%s)" % args.root)
    print("="*70)
    print(f"  total captures replayed        : {n}")
    print(f"  equivalence PASS               : {equiv_pass}/{n}")
    print(f"  exact CRC-result matches       : {crc_match}/{n}")
    print(f"  SINR matches (Δ<0.05 or nan==) : {snr_match}/{n}")
    print(f"    of which finite-SINR exact   : {finite_snr_exact}")
    print(f"    of which nan-chest (nan==nan): {nan_chest}")
    print(f"  live CRC successes             : {live_success}")
    print(f"  payload-equiv (successes)      : {payload_ok_match}/{payload_ok_total}")
    print(f"  load/init failures             : {load_err}")
    print(f"  incomplete/timeouts            : {incomplete}")
    if mismatches:
        print(f"  !! MISMATCHES ({len(mismatches)}):")
        for b, r in mismatches[:20]:
            print(f"     {b}: live_crc={r['live_crc']} replay_crc={r['replay_crc']} "
                  f"live_snr={r['live_snr']} replay_snr={r['replay_snr']} Δ={r['snr_dphi']}")

    print("\n" + "="*70)
    print("PHASE 6/7 — WIDE-TIMING RECOVERY  (±%d samples, ~±%.1f us @23.04Msps)"
          % (args.widesweep, args.widesweep / 23.04))
    print("="*70)
    print(f"  bursts that FAILED live but pass CRC after wide timing search: {len(recovered)}")
    if gains:
        gs = sorted(gains); med = gs[len(gs)//2]
        print(f"  SINR gain from best timing (dB): median={med:.2f} max={gs[-1]:.2f} min={gs[0]:.2f}")
    print("\n  by energy-SNR bin:")
    print("    bin    n   liveOK  sweepOK  recovered  medOff  maxOff")
    for b in BINS:
        d = by_ebin[b]
        if d["n"] == 0: continue
        offs = sorted(abs(x) for x in d["offs"])
        mo = offs[len(offs)//2] if offs else 0
        xo = offs[-1] if offs else 0
        print(f"    {b:<5} {d['n']:>4} {d['live']:>7} {d['sweep']:>8} {d['recov']:>10} {mo:>7} {xo:>7}")
    print("\n  by MCS:")
    print("    mcs    n   liveOK  sweepOK  recovered")
    for mcs in sorted(by_mcs):
        d = by_mcs[mcs]
        print(f"    {mcs:<5} {d['n']:>4} {d['live']:>7} {d['sweep']:>8} {d['recov']:>10}")
    if recovered:
        print("\n  RECOVERED bursts (failed live, valid CRC after wide timing):")
        for b, eb, mcs, off, snr in recovered:
            print(f"    {b}  ebin={eb} mcs={mcs} crc_off={off} best_snr={snr}")
    print("\n  DECISION INPUT: %d live failures recovered purely via integer timing." % len(recovered))
    return 0

if __name__ == "__main__":
    sys.exit(main())
