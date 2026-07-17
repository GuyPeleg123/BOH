# UlDenseDecoder — calibrated-window uplink decode (from-scratch path)

A clean, self-contained uplink PUSCH decode path written beside (not replacing)
the legacy `PUSCH_Decoder`. Its single novel responsibility is **correct UL FFT
window placement for a passive monitor**; it reuses srsRAN's canonical decode
primitives unchanged.

Gated by env `UL_DENSE2=1` (set by the GUI **Dense Test** button). When off, the
binary behaves exactly as before. The legacy path is untouched.

## Why this exists (the measured problem)

A passive monitor inherits UL timing from the DL clock (radio A, PSS/SSS-locked)
because the uplink has no sync beacon. Radio B (UL) therefore has a **fixed,
uncalibrated group-delay/pipeline offset** relative to the DL-derived subframe
boundary — there is no UL beacon to remove it. Measured on 102 strong grants of
`2026-07-15_21-03-04` (canonical replay), the best UL FFT window sits at a median
**−725 samples** with the tightest locks at −725 ± 106. Physics bounds *per-UE
geometry* at ±113 samples (tower↔monitor = 734 m), so an offset centered at −725
is **not** geometry — it is a fixed calibration error. It decomposes exactly:

    UL window error = C_fixed (~ -725 samp)  +  delta_ue (in [-113, +113] samp)
                      \__ shared, calibrate __/   \__ per-UE geometry, search __/

The legacy path centers its FFT and its narrow retry on offset **0**, so it never
reaches C_fixed and decodes essentially every grant ~23–31 µs off-window. That
also biases its channel-SNR measurements low (they are taken at the wrong window),
which is why the airlink looked "1–2 dB limited". Re-centering recovers a median
+4.1 dB (max +11.5 dB) that was being discarded.

## Design

Per subframe, the decoder holds a private clean snapshot of radio-B's pre-FFT
samples and re-FFTs at chosen offsets (same mechanism as the legacy
`refft_at_offset`). For each scheduled grant:

1. **Energy gate.** Compute chest-free allocated-RB power vs the sub-band noise
   floor. Grants below `min_energy_db` are noise/other-UE/false-DCI — skip the
   expensive search (spends CPU only on the ~1% that carry signal).
2. **Window origin.** Start from `C_fixed + delta_ue`, where `delta_ue` is the
   per-RNTI EMA (seeded from the RAR Timing-Advance prior when first seen).
3. **Bootstrap (C_fixed unknown).** Until enough clean locks exist, strong grants
   get a WIDE coarse chest-SNR scan (±`boot_range`, step 16) to find their peak;
   the peak offsets feed the C_fixed estimator (robust running median of the
   strong-lock cluster). Once seeded, the wide scan is retired.
4. **Fine search.** Around the origin, scan ±`fine_range` (step `fine_step`) using
   `chest_res.snr_db` as the metric; decode at the argmax.
5. **Accept.** Only a real CRC pass (with the all-zero-TB noise guard) is written
   to the pcap. A strong, distinct, slot-consistent lock updates `C_fixed` and the
   UE's `delta_ue`; noise peaks never update state.

Reused srsRAN calls (identical to the legacy path, so results are comparable):
`srsran_enb_ul_fft` / `srsran_ofdm_rx_sf_ng` (shifted window),
`srsran_chest_ul_estimate_pusch`, `srsran_pusch_decode`. v1 handles the standard
MCS table (QPSK/16QAM, mcs_idx ≤ 20) — the low-MCS messages a passive monitor can
actually recover (identities, CCCH, low-rate user data). High-MCS 64/256QAM grants
are SNR-wall-limited regardless and are left to the legacy path.

## Config (env)

| env | default | meaning |
|-----|---------|---------|
| `UL_DENSE2`            | off  | enable this decoder in place of the legacy UL decode |
| `UL_DENSE2_MINDB`      | 3.0  | energy gate: min allocated-RB power over noise floor (dB) |
| `UL_DENSE2_BOOT`       | 900  | bootstrap wide coarse-scan half-range (samples) |
| `UL_DENSE2_FINE`       | 150  | per-UE fine-search half-range around the origin (samples) |
| `UL_DENSE2_FINE_STEP`  | 6    | fine-search step (samples) |
| `UL_DENSE2_CAL`        | auto | force C_fixed to a fixed value (samples); skip online calibration |
| `UL_DENSE2_LOCKDB`     | 6.0  | min chest SNR for a lock to update C_fixed / delta_ue |

## Validation plan

- **Offline (done):** the −725 offset + per-UE decomposition confirmed on the 600
  captures via `ul_iq_replay` widesweep — this decoder productizes that recovery.
- **Live controlled UE (next):** transmit a known strong QPSK PUSCH from a spare
  USRP TX port at the UL frequency; confirm `UlDenseDecoder` recovers the exact TB.
  A strong + low-MCS source proves the windowed chain decodes, separating the
  calibration fix from the residual airlink SNR wall on distant subscribers.
