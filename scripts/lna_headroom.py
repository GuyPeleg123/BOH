#!/usr/bin/env python3
"""
lna_headroom.py — measure received power on the B210 and tell you whether an
external LNA is safe to insert, and what (if any) inline pad you need.

WHY: the USRP's internal gain / AGC cannot protect the front end from damage.
Power at the SMA = (signal at antenna) + (LNA gain), independent of any gain
setting. This tool measures the antenna power WITHOUT the LNA, then computes the
post-LNA power and compares it to the B210 damage threshold.

HOW IT WORKS:
  1. Captures a short window of IQ at a *fixed* RX gain via `uhd_rx_cfile`.
  2. Computes peak level in dBFS (exact) and an *approximate* absolute dBm.
  3. Adds your LNA gain and checks against the safe limit, with margin.
  4. Prints a pad recommendation per band.

RUN THIS WITH THE ANTENNA STRAIGHT INTO RX (no LNA in line yet).

Examples:
  # Your setup: DL 1845 MHz (30 dB LNA), UL 1750 MHz (16 dB LNA)
  ./lna_headroom.py --dl 1845e6:30 --ul 1750e6:16

  # single band
  ./lna_headroom.py --dl 1845e6:30

ABSOLUTE-dBm CAVEAT: the B210 is NOT factory power-calibrated. The dBm figure is
approximate (assume +/-5 dB). That is why the pad recommendation carries a safety
margin (default 6 dB). The dBFS / clipping figures ARE exact.
"""
import argparse
import os
import subprocess
import sys
import tempfile

import numpy as np

# --- B210 constants (conservative) ---------------------------------------
DAMAGE_DBM = 0.0        # absolute max RX input before damage (datasheet ~0 dBm)
SAFE_DBM = -15.0        # recommended max for clean/linear operation
MIN_USRP_GAIN = 0.0     # AGC floor on the B210 (dB)
MAX_USRP_GAIN = 76.0
# Input power (dBm) that produces 0 dBFS at 0 dB RX gain. The B210 is uncalibrated;
# empirical reports land ~ -6..-15 dBm. -10 is a middle, slightly conservative
# anchor. Override with --fs0 if you have a calibrated reference.
FS0_DBM_AT_0GAIN = -10.0


def capture(freq, gain, rate, nsamps, args):
    """Capture IQ to a temp file via uhd_rx_cfile, return complex64 array."""
    fd, path = tempfile.mkstemp(suffix=".cf32")
    os.close(fd)
    cmd = [
        "uhd_rx_cfile",
        "-f", str(freq),
        "-g", str(gain),
        "-r", str(rate),
        "-N", str(nsamps),
    ]
    if args:
        cmd += ["-a", args]
    cmd += [path]
    print(f"  capturing {nsamps} samples @ {freq/1e6:.1f} MHz, gain {gain} dB ...",
          flush=True)
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
    except subprocess.CalledProcessError as e:
        os.path.exists(path) and os.unlink(path)
        err = (e.stderr or "").strip().splitlines()
        tail = err[-1] if err else "(no stderr)"
        if "No devices found" in (e.stderr or "") or "no UHD" in (e.stderr or "").lower():
            sys.exit("ERROR: no USRP detected. Plug in the B210 and confirm with "
                     "`uhd_find_devices`, then re-run.")
        sys.exit(f"ERROR: capture failed @ {freq/1e6:.1f} MHz: {tail}")
    iq = np.fromfile(path, dtype=np.complex64)
    os.unlink(path)
    # Drop the first few thousand samples — front-end/AGC settling transients.
    return iq[5000:] if iq.size > 10000 else iq


def analyze(label, freq, lna_gain, gain, rate, nsamps, fs0, margin, dev_args):
    iq = capture(freq, gain, rate, nsamps, dev_args)
    if iq.size == 0:
        print(f"[{label}] NO SAMPLES — capture failed.")
        return

    mag = np.abs(iq)
    peak = mag.max()
    rms = np.sqrt(np.mean(mag ** 2))
    # fc32 wire format: full scale magnitude = 1.0  ->  0 dBFS
    peak_dbfs = 20 * np.log10(peak) if peak > 0 else -120.0
    rms_dbfs = 20 * np.log10(rms) if rms > 0 else -120.0

    # Absolute dBm at the antenna (approx). full-scale input at this gain:
    #   P_fs(gain) = fs0 - gain      (more gain -> less input saturates)
    #   P_in       = P_fs(gain) + peak_dBFS
    p_ant = fs0 - gain + peak_dbfs

    print(f"\n[{label}]  {freq/1e6:.1f} MHz   (capture gain {gain} dB)")
    print(f"  peak  : {peak_dbfs:6.1f} dBFS   "
          f"({'CLIPPING' if peak_dbfs > -0.5 else 'ok'}, headroom {-peak_dbfs:.1f} dB)")
    print(f"  rms   : {rms_dbfs:6.1f} dBFS")
    print(f"  ~antenna power : {p_ant:6.1f} dBm  (approx, +/-5 dB)")

    if peak_dbfs > -1.0:
        print("  !! ADC was clipping at this gain — antenna power is HIGHER than "
              "estimated. Re-run with a lower --gain for a valid number.")

    # Post-LNA power into the USRP, and pad sizing.
    p_into_usrp = p_ant + lna_gain
    print(f"  with {lna_gain} dB LNA -> {p_into_usrp:.1f} dBm into the USRP "
          f"(damage {DAMAGE_DBM:.0f} dBm, safe < {SAFE_DBM:.0f} dBm)")

    needed = p_into_usrp - SAFE_DBM + margin   # how far over safe (with margin)
    if needed <= 0:
        print(f"  => SAFE. No pad needed (>= {-needed:.0f} dB headroom incl. "
              f"{margin:.0f} dB margin).")
    else:
        pad = next(p for p in (3, 6, 10, 20, 30, 40)
                   if p >= needed) if needed <= 40 else int(np.ceil(needed))
        print(f"  => ADD A PAD: ~{pad} dB attenuator before the LNA "
              f"(need {needed:.0f} dB incl. {margin:.0f} dB margin).")

    # AGC-floor note: with the LNA always adding gain, can AGC still back off
    # enough to avoid ADC clipping on the strongest bursts?
    min_total = MIN_USRP_GAIN + lna_gain
    print(f"  AGC note: min total front-end gain becomes {min_total:.0f} dB "
          f"(USRP floor {MIN_USRP_GAIN:.0f} + LNA {lna_gain:.0f}). If the band is "
          f"strong, AGC may not back off enough -> watch for clipping.")


def band_arg(s):
    """Parse 'FREQ:LNAGAIN' e.g. '1845e6:30'."""
    f, g = s.split(":")
    return float(f), float(g)


def main():
    ap = argparse.ArgumentParser(description="B210 LNA headroom / pad calculator")
    ap.add_argument("--dl", type=band_arg, metavar="FREQ:LNAGAIN",
                    help="downlink, e.g. 1845e6:30")
    ap.add_argument("--ul", type=band_arg, metavar="FREQ:LNAGAIN",
                    help="uplink, e.g. 1750e6:16")
    ap.add_argument("--gain", type=float, default=30.0,
                    help="fixed RX capture gain in dB (default 30; keep < 76)")
    ap.add_argument("--rate", type=float, default=5e6, help="sample rate (default 5e6)")
    ap.add_argument("--nsamps", type=int, default=2_000_000,
                    help="samples per capture (default 2e6 ~ 0.4 s)")
    ap.add_argument("--fs0", type=float, default=FS0_DBM_AT_0GAIN,
                    help=f"dBm giving 0 dBFS at 0 dB gain (default {FS0_DBM_AT_0GAIN})")
    ap.add_argument("--margin", type=float, default=6.0,
                    help="safety margin dB added to pad calc (default 6)")
    ap.add_argument("--args", default="", help="UHD device args, e.g. serial=3367EF9")
    a = ap.parse_args()

    if not a.dl and not a.ul:
        ap.error("give at least one of --dl / --ul (FREQ:LNAGAIN)")
    if a.gain >= MAX_USRP_GAIN:
        ap.error(f"--gain must be < {MAX_USRP_GAIN}")

    print("=" * 64)
    print("B210 LNA headroom check  —  ANTENNA MUST BE STRAIGHT INTO RX (no LNA)")
    print("=" * 64)
    if a.dl:
        analyze("DL", a.dl[0], a.dl[1], a.gain, a.rate, a.nsamps,
                a.fs0, a.margin, a.args)
    if a.ul:
        analyze("UL", a.ul[0], a.ul[1], a.gain, a.rate, a.nsamps,
                a.fs0, a.margin, a.args)
    print("\nReminder: re-check UL with a phone transmitting NEAR the antenna —")
    print("that burst, not the idle level, is what can burn the front end.")


if __name__ == "__main__":
    main()
