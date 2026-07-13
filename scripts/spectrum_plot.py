#!/usr/bin/env python3
"""
spectrum_plot.py <freq_hz> <serial> <label> <out.png> — capture IQ via
uhd_rx_cfile, compute Welch PSD, save a labelled spectrum PNG, and print a
channel-flatness analysis over the LTE 20 MHz channel (+/-10 MHz).

A clean LTE channel = flat-ish plateau across +/-10 MHz. A filter problem shows
as roll-off / tilt / notch inside that band; an unstable LNA shows as spurs.
"""
import subprocess
import sys
import os
import tempfile

import numpy as np
from scipy.signal import welch
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

freq = float(sys.argv[1]); serial = sys.argv[2]; label = sys.argv[3]; out = sys.argv[4]
RATE = 30.72e6
N = 8_000_000
GAIN = 30

fd, path = tempfile.mkstemp(suffix=".cf32"); os.close(fd)
subprocess.run(["uhd_rx_cfile", "-f", str(freq), "-r", str(RATE), "-g", str(GAIN),
                "-N", str(N), "-a", f"serial={serial}", path],
               check=True, capture_output=True, text=True, timeout=90)
iq = np.fromfile(path, dtype=np.complex64)[20000:]
os.unlink(path)

f, pxx = welch(iq, fs=RATE, nperseg=4096, return_onesided=False)
f = np.fft.fftshift(f) / 1e6           # MHz offset from centre
psd = 10 * np.log10(np.fft.fftshift(pxx) + 1e-20)

# channel analysis over +/-9 MHz (inside the 20 MHz channel, away from edges)
inb = np.abs(f) <= 9.0
band = psd[inb]; bf = f[inb]
tilt = np.polyfit(bf, band, 1)[0]                     # dB per MHz
ripple = float(band.max() - band.min())
# noise reference from far out-of-band (|f| 13..15 MHz)
oob = (np.abs(f) > 13) & (np.abs(f) < 15)
noise = float(np.median(psd[oob]))
inband_med = float(np.median(band))
print(f"[{label}] {freq/1e6:.1f} MHz")
print(f"  in-band median : {inband_med:6.1f} dB")
print(f"  out-of-band    : {noise:6.1f} dB   (channel sits {inband_med-noise:.1f} dB above noise)")
print(f"  in-band tilt   : {tilt:+.2f} dB/MHz")
print(f"  in-band ripple : {ripple:.1f} dB  (peak-to-trough across +/-9 MHz)")
# crude verdict
if inband_med - noise < 6:
    print("  VERDICT: channel barely above noise -> weak/blocked or wrong band")
elif ripple > 12 or abs(tilt) > 0.8:
    print("  VERDICT: strong but DISTORTED (ripple/tilt) -> filter or connector problem")
else:
    print("  VERDICT: channel looks reasonably flat -> filter passband OK")

plt.figure(figsize=(10, 5))
plt.plot(f, psd, lw=0.6, color="tab:blue")
plt.axvspan(-10, 10, color="tab:green", alpha=0.08, label="LTE 20 MHz channel")
plt.axvline(-10, color="g", ls="--", lw=0.8); plt.axvline(10, color="g", ls="--", lw=0.8)
plt.axhline(noise, color="r", ls=":", lw=0.8, label=f"noise ~{noise:.0f} dB")
plt.title(f"Spectrum — {label} @ {freq/1e6:.1f} MHz "
          f"(tilt {tilt:+.2f} dB/MHz, ripple {ripple:.1f} dB, {inband_med-noise:.1f} dB over noise)")
plt.xlabel("offset from centre (MHz)"); plt.ylabel("PSD (dB)")
plt.xlim(-15, 15); plt.grid(alpha=0.3); plt.legend(loc="upper right", fontsize=8)
plt.tight_layout(); plt.savefig(out, dpi=110)
print(f"  saved -> {out}")
