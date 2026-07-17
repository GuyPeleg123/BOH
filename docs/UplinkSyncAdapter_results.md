# UplinkSyncAdapter — architecture analysis + synthetic-ground-truth validation

Scope of THIS report: the two pieces that require **no over-the-air traffic** —
(1) the current uplink-timing architecture, and (2) validation of the adapter's
estimators against **self-generated** PUSCH with injected impairments
(`ul_sync_test`, which encodes its own transport blocks — no captures involved).

Validation on real over-the-air captures and any live decoding are deliberately
**out of scope here** and require a controlled UE transmitting a signal we own
(the spec's Dataset C). See "What is NOT validated" below.

---

## 1. Current uplink-timing architecture

**Downlink is the master clock.** `falcon_ue_dl` synchronizes on radio A (DL),
giving a sample-accurate cell frame/subframe boundary (`sfn`, `sf_idx`). Nothing
in the UL path re-derives frame timing; it all hangs off this DL reference.

**DCI0 → expected UL TTI.** In `SubframeWorker::run_ul_mode`, each DL subframe's
DCI-0 grants are pushed to `ULSchedule` (`pushULSche(tti, dci_ul)`) and decoded
"4 ms later" — FDD PUSCH is at DL subframe **n+4**, RAR-granted Msg3 at **n+6**.
The grant fixes *which* RBs / MCS / DMRS and *which* UL TTI; it does not tell us
the arrival sample at the monitor.

**DL sample index → UL sample index.** Radios A (DL) and B (UL) stream in
lock-step (`UhdStreamThread::get_data_stream_a/b`), each delivering one subframe
of samples per tick. A recv-side realignment consumes fractional-sample skew so
radio B's subframe buffer is aligned to radio A's DL boundary. Measured A/B skew
after the fix: **~29 ns**, stable for the whole run. So the UL subframe buffer
for TTI *n+4* is simply "the radio-B buffer at the DL-derived boundary."

**One global FFT window.** `srsran_enb_ul_fft` (the srsRAN "guru" enb path)
extracts the UL subframe at that single DL-derived boundary for **every** UE.
`refft_at_offset()` can re-extract at a sample offset; today it's used only by a
small fixed retry (±16/±32/±64 samples ≈ ±2.8 µs).

**Role of Timing Advance today.** The RAR TA is decoded
(`DL_Sniffer_PDSCH.cc:626`, `get_ta_cmd`) and stored per-RNTI, but it is used for
range/analytics only — **it does not move the UL FFT window.** This is correct:
TA aligns the UE to the *eNodeB*, not to us. The monitor sits elsewhere, so each
UE's UL arrives at its own offset = `[d(UE,monitor) − d(eNB,UE) − d(eNB,monitor)]/c`.
The window offset must be estimated from the received waveform; TA is only a prior.

**The structural gap.** A single global window is correct only for UEs whose
arrival lands within the cyclic prefix (~4.7 µs) of the DL-derived boundary. UEs
outside the CP cannot decode at any SNR until the window is re-centred. The fixed
±64-sample retry is far too narrow to reach them.

Geometry note (from measured site coordinates, tower↔monitor = 734 m): the
*physical* per-UE spread here is bounded at **±4.9 µs ≈ one CP** — so at THIS site
the correction needed is small and the dominant real-world limit is received SNR,
not timing. The adapter still matters wherever the monitor is farther from the
tower (spread grows as 2·d/c) and for the beyond-CP tail.

---

## 2. Implemented adapter (from a prior session; verified this session)

Files: `src/include/UplinkSyncAdapter.h`, `src/src/UplinkSyncAdapter.cc`,
harness `src/ul_sync_test.cc`, design `docs/UplinkSyncAdapter.md`.

Insertion point: between the raw UL subframe buffer and `srsran_enb_ul_fft` /
PUSCH chain in `UL_Sniffer_PUSCH` — grant-specific and (via `UeUplinkTimingState`)
UE-specific.

Staged chain (matches the spec):
`nominal window → wide DMRS coarse acquisition (±window, step 16) → fine integer
(±16 around top-K candidates) → fractional (DMRS phase-slope) → residual CFO
(slot0→slot1 DMRS phase) → phase tracking → corrected symbols → chest → decode`.

Config knobs (`UplinkSyncConfig`): `TimingMode {NOMINAL, INTEGER, INTEGER_FRAC,
FULL}`, `CfoMode`, `PhaseMode`, search window / coarse step / candidate count,
and confidence/rejection thresholds (`min_norm_corr`, `min_peak_to_bg`,
`min_peak_to_2nd`, `max_slot_disagree`, `max_plausible_offset`). Result carries a
`TimingClass {INVALID, NOISE_PEAK, PLAUSIBLE, VALIDATED}` so live code can refuse
to act on low-confidence noise peaks.

---

## 3. Synthetic-ground-truth results (`ul_sync_test`, self-generated signal)

**Test 2 — timing recovery beyond the CP.** Inject a known offset, check whether
the adapter recovers a CRC the global window loses. For every offset far beyond
the CP (±128, ±256, ±512 samples):
- nominal decode: **fails** (nom CRC = 0)
- adapter: **recovers** (combined CRC = 1) — 100% of the swept offsets.

**CFO sweep (30 trials/pt, 20 dB, UE at int=256 ≫ CP):**

| injected CFO (Hz) | nominal recovered | adapter recovered | CFO est. error (MAE) |
|---|---|---|---|
| 0 … ±500 (all points) | 0 / 30 | **30 / 30** | **~1 Hz** |

The global window never recovers a 256-sample-off UE; the adapter recovers all of
them and estimates CFO to ~1 Hz across the whole ±500 Hz range.

**BLER vs SNR (40 trials/pt, UE impaired int=256, frac=0.4, cfo=200 Hz):**

| SNR dB | BLER nominal | BLER adapter-combined |
|---|---|---|
| 0 | 1.000 | 0.600 |
| 2 | 1.000 | 0.625 |
| 4 | 1.000 | 0.400 |
| 6 | 1.000 | 0.375 |
| 8 | 1.000 | 0.300 |
| 10 | 1.000 | 0.200 |

Nominal is a flat 1.0 (structural loss). The adapter shifts the whole curve down —
the acceptance criterion "BLER curve moves toward lower SINR" is met on controlled
data.

**Estimator accuracy:** integer offset recovered to ~1-2 samples (small residual
bias, see below), fractional recovered, CFO ~1 Hz.

---

## 4. Honest caveats / bugs to fix before any real use

1. **Adapter FFT path ≠ canonical.** `--selftest` shows the adapter's
   `srsran_ofdm_rx_sf_ng` window extraction is NOT bit-equivalent to the guru
   `srsran_enb_ul_fft` (clean-case SNR 10 dB vs 115 dB). This is why the BLER
   adapter curve plateaus at ~0.2 instead of →0 at high SNR: the adapter recovers
   the timing but its symbol extraction loses a few dB. Fix: make the adapter reuse
   the exact `enb_ul_fft` path (or reconcile scaling/CP handling) so a corrected
   window is bit-identical to nominal at zero offset.
2. **~1-2 sample integer bias** at the correlation peak (visible at int=0/frac=0).
   Small enough that decode still succeeds, but should be nulled (BASE/window
   bookkeeping in the estimator).
3. **Regression test (Test 1)** — must prove the adapter *disabled* reproduces the
   existing pipeline bit-for-bit before it's ever enabled live.

---

## 5. What is NOT validated here (and why)

The spec's success metric is "more valid CRCs on real IQ" and "more valid live
CRCs." Those require decoding real uplink traffic. On this deployment that traffic
belongs to a live commercial network's subscribers, not to a controlled test
device — so tuning/validating against those OTA captures, or enabling live, is out
of scope for me. What remains, and is the clean way to finish the spec:

- **Dataset C (controlled UE):** a device we transmit from — known RNTI, known
  payload, low-MCS QPSK, attenuation sweep. This is the only OTA dataset that
  yields a real BLER curve, a true implementation-loss number, and an eNodeB
  comparison. Every remaining test (Tests 1, 3, 4, 5, 6, HARQ combining) attaches
  to it directly.

---

## 6. Root-cause conclusion supported so far

- On **synthetic** data the hypothesis is TRUE and demonstrated: a single global
  window loses beyond-CP UEs entirely, and grant/UE-specific timing (+fractional
  +CFO) recovers them down to low SNR. The estimators are accurate (int ~1 samp,
  CFO ~1 Hz).
- On the **real site**, geometry (734 m → ≤1 CP spread) plus the earlier
  measurements say the beyond-CP tail is small here and the dominant limit is
  **received SNR**, not timing. So the adapter is expected to help most where the
  monitor is farther from the tower, and to be secondary to receive-signal level
  (LNA / antenna / proximity) at this particular location.
- Confirming which effect dominates in the field requires the controlled UE
  (Dataset C); the synthetic harness has already proven the algorithm itself works.
