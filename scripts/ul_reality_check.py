#!/usr/bin/env python3
"""ul_reality_check — the decisive "is there real decodable UL?" analysis.

For a directory of grant-keyed UL-IQ captures (UL_IQ_REC), runs each through
`ul_iq_replay --adapter` (wide DMRS search) and classifies every grant by whether
a REAL uplink signal is present, using the DMRS coherence (norm_corr + slot
agreement) as the ground-truth "a real UE is there" detector — independent of CRC.

Answers the hypothesis differential:
  H1 no real UL reaches us        -> ~no grants with coherent DMRS
  H2 real UL but MCS too high     -> coherent grants are high-MCS
  H3 real UL but mistimed         -> coherent DMRS only at large adapter offset
  H4 DCI0 grants wrong            -> coherent grants have implausible RB/MCS

Usage: ul_reality_check.py <iq_dir> [--replay ./ul_iq_replay]
"""
import sys, os, glob, subprocess, csv, re, json, statistics as st, collections

def main():
    if len(sys.argv) < 2: print(__doc__); sys.exit(2)
    d = sys.argv[1]
    replay = "./ul_iq_replay"
    for i,a in enumerate(sys.argv):
        if a == "--replay": replay = sys.argv[i+1]
    caps = sorted(glob.glob(os.path.join(d, "capture_*")))
    if not caps: print("no captures in", d); sys.exit(1)

    # A grant has a REAL coherent UL DMRS when both slots correlate strongly AND
    # agree — the same criterion that separated real UE 24947 (0.96/0.96) from
    # noise peaks (0.23/0.00) in prior analysis.
    REAL_NC = 0.50      # combined normalized DMRS correlation threshold
    rows = []
    for c in caps:
        try:
            out = subprocess.run([replay, c, "--adapter"], capture_output=True,
                                 text=True, env=dict(os.environ, UL_ADAPT_RANGE="1024"),
                                 timeout=120).stdout
        except subprocess.TimeoutExpired:
            continue
        m = re.search(r"ADAPTER_RESULT (.+)", out)
        a = re.search(r"ADAPTER: class=(\S+).*?off=([+-]?\d+).*?norm_corr=([\d.]+).*?"
                      r"slot0=([\d.]+) slot1=([\d.]+) slotdiff=([\d.]+)", out)
        cap = re.search(r"cell=\d+ nof_prb=\d+ rnti=0x(\w+) tti=\d+ mcs=(\d+).*?L_prb=(\d+)", out)
        live = re.search(r"LIVE: crc=(\d+) snr_db=([-\d.eE]+) ta_us=([-\d.]+)", out)
        if not (m and a and cap): continue
        kv = dict(t.split("=",1) for t in m.group(1).split() if "=" in t)
        rows.append(dict(
            rnti=cap.group(1), mcs=int(cap.group(2)), L_prb=int(cap.group(3)),
            nc=float(a.group(3)), slot0=float(a.group(4)), slot1=float(a.group(5)),
            slotdiff=float(a.group(6)), off=int(a.group(2)), cls=a.group(1),
            live_crc=int(live.group(1)) if live else 0,
            live_snr=float(live.group(2)) if live and live.group(2) not in ("nan","-nan") else float('nan'),
            adapter_crc=int(kv.get("adapter_crc",0)),
        ))
    n = len(rows)
    if not n: print("no parseable results"); sys.exit(1)

    real = [r for r in rows if r["nc"] >= REAL_NC and r["slotdiff"] < 24]
    coh_off = [r for r in real if abs(r["off"]) > 40]     # coherent but mistimed
    print(f"# analyzed {n} captured grants (recorder-sampled, biased toward strong)")
    print(f"# grants with REAL coherent UL DMRS (nc>={REAL_NC}, slots agree): {len(real)} ({100*len(real)/n:.0f}%)")
    print(f"#   of those, mistimed beyond ~CP (|off|>40 samp): {len(coh_off)}")
    print(f"# nc distribution: " + " ".join(
        f"{lo:.1f}-{lo+0.2:.1f}:{sum(1 for r in rows if lo<=r['nc']<lo+0.2)}" for lo in [x/10 for x in range(0,10,2)]))
    if real:
        mcs = collections.Counter(r["mcs"] for r in real)
        print(f"# MCS of REAL grants: {dict(sorted(mcs.items()))}")
        snrs = [r["live_snr"] for r in real if r["live_snr"]==r["live_snr"]]
        if snrs: print(f"# REAL-grant nominal chest SNR: med={st.median(snrs):.1f} max={max(snrs):.1f} dB")
        dec = sum(1 for r in real if r["adapter_crc"])
        print(f"# REAL grants that DECODE (adapter): {dec}/{len(real)}")
        print("# --- REAL grants detail (rnti mcs L_prb nc slot0/1 off snr adpCRC) ---")
        for r in sorted(real, key=lambda r:-r["nc"])[:25]:
            print(f"  rnti={r['rnti']:>5} mcs={r['mcs']:>2} L={r['L_prb']:>2} nc={r['nc']:.2f} "
                  f"s={r['slot0']:.2f}/{r['slot1']:.2f} off={r['off']:+5d} snr={r['live_snr']:5.1f} crc={r['adapter_crc']}")
    print("\n# VERDICT:")
    if len(real) == 0:
        print("#  H1 — no coherent UL present. Purely reception/geometry limited.")
    else:
        hi = sum(1 for r in real if r["mcs"] > 10)
        print(f"#  Real coherent UL DOES reach us ({len(real)} grants).")
        print(f"#  {hi}/{len(real)} are high-MCS (>10) — undecodable at monitor SNR (H2).")
        print(f"#  {len(coh_off)}/{len(real)} are mistimed >CP (H3, adapter-recoverable).")

if __name__ == "__main__": main()
