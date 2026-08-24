#!/usr/bin/env python3
"""Run the UplinkSyncAdapter over a directory of grant-keyed UL-IQ captures
(Dataset A) and aggregate the classification + recovery outcome.

Usage: run_adapter_dataset_a.py <captures_dir> [--replay ./ul_iq_replay] [--range 1024]

Parses the "ADAPTER_RESULT ..." line emitted by `ul_iq_replay <dir> --adapter`
and reports, over all captures:
  - class histogram (validated / plausible / noise_peak / invalid)
  - nominal vs adapter CRC totals, and NET recoveries (nominal=0 -> adapter=1)
  - recoveries vs energy, to show whether any recovery correlates with real energy
This is the honest Dataset-A scorecard: on weak OTA it should show near-zero
recoveries and heavy noise-peak/plausible rejection, NOT false CRCs.
"""
import sys, os, glob, subprocess, csv, collections, re

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    cdir = sys.argv[1]
    replay = "./ul_iq_replay"
    rng = "1024"
    for i, a in enumerate(sys.argv):
        if a == "--replay": replay = sys.argv[i+1]
        if a == "--range":  rng = sys.argv[i+1]
    caps = sorted(glob.glob(os.path.join(cdir, "capture_*")))
    if not caps:
        print("no captures found in", cdir); sys.exit(1)

    # energy_snr per seq from captures.csv, if present (for the correlation view)
    esnr = {}
    csvp = os.path.join(cdir, "captures.csv")
    if os.path.exists(csvp):
        for r in csv.DictReader(open(csvp)):
            try: esnr[r["path"]] = float(r["energy_snr"])
            except (KeyError, ValueError): pass

    env = dict(os.environ, UL_ADAPT_RANGE=rng)
    cls = collections.Counter()
    n = nom_ok = adp_ok = recovered = broke = 0
    rec_rows = []
    for c in caps:
        try:
            out = subprocess.run([replay, c, "--adapter"], capture_output=True,
                                 text=True, env=env, timeout=120).stdout
        except subprocess.TimeoutExpired:
            continue
        m = re.search(r"ADAPTER_RESULT (.+)", out)
        if not m: continue
        kv = dict(t.split("=", 1) for t in m.group(1).split() if "=" in t)
        n += 1
        cls[kv.get("class", "?")] += 1
        nc = int(kv.get("nominal_crc", 0)); ac = int(kv.get("adapter_crc", 0))
        nom_ok += nc; adp_ok += ac
        rec = (nc == 0 and ac == 1); brk = (nc == 1 and ac == 0)
        recovered += rec; broke += brk
        if rec:
            base = os.path.basename(c)
            rec_rows.append((base, esnr.get(base, float("nan")), kv.get("off"), kv.get("cfo"),
                             kv.get("norm_corr"), kv.get("conf")))

    print(f"# Dataset A adapter scorecard: {n} captures, search_range=±{rng}")
    print(f"# class histogram: " + ", ".join(f"{k}={v}" for k, v in cls.most_common()))
    print(f"# nominal CRC ok      : {nom_ok}")
    print(f"# adapter CRC ok       : {adp_ok}")
    print(f"# NET recovered (nom0->adp1): {recovered}")
    print(f"# broke  (nom1->adp0, should be 0 in fallback use): {broke}")
    if rec_rows:
        print("# recovered captures (seq, energy_snr, off, cfo, norm_corr, conf):")
        for r in sorted(rec_rows, key=lambda x: -(x[1] if x[1] == x[1] else -1e9)):
            print("   ", *r)
    else:
        print("# no captures recovered by per-grant sync — consistent with sub-CP-energy RF limit")

if __name__ == "__main__":
    main()
