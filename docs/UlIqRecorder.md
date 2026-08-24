# UL raw-IQ recorder + offline replay

Grant-keyed capture of the exact pre-FFT uplink samples the live decoder used,
plus an offline tool that replays them bit-for-bit and reprocesses them with
alternate timing/estimator hypotheses. Purpose: measure how much of the low UL
yield is residual *software* loss vs true RF/geometry limitation, on identical
bursts, without the radio — and make RF experiments reproducible offline.

## Recording (live)

Env-gated; zero cost when off. Runs in DUAL/UL mode (needs `multi_ul_offset`,
set automatically in DUAL mode). From `build/src`:

```
UL_IQ_REC=1 ./LTESniffer <normal dual-UL args>
```

| env | default | meaning |
|-----|---------|---------|
| `UL_IQ_REC`  | (unset) | set to any value to enable |
| `UL_IQ_DIR`  | `~/ltesniffer-captures/iq_<timestamp>` | output directory |
| `UL_IQ_MAX`  | `500`   | hard cap on captures per run (disk bound) |
| `UL_IQ_QUEUE`| `64`    | writer backlog bound; excess is dropped (counted) |

The recorder is non-blocking to the realtime path: the decode thread only copies
a burst into a bounded queue; a writer thread serializes files. It captures the
**nominal-window** decode of each grant (before offset-retry), so the stored IQ,
config and result are self-consistent. A bounded policy keeps all CRC successes,
retransmissions, timing outliers and strong/NaN-chest failures, and subsamples
the RF-weak bulk. On shutdown it prints `requested/written/dropped/disk_err`.

### Per-capture layout

```
capture_<runid>_<seq>/
  uplink_cf32.iq   interleaved little-endian f32 I,Q  (== numpy complex64)
  metadata.json    50 fields: rf, timing, cell, dmrs, grant, live measurements
  decode_ctx.bin   POD DecodeCtxBlob: EXACT grant/dmrs/hopping/uci + live result
captures.csv       run index (one row per capture)
```

Load the IQ in Python with `numpy.fromfile(path, dtype=numpy.complex64)`.

## Replaying (offline)

```
./ul_iq_replay <capture_dir> [--sweep N]
```

Rebuilds the decoder exactly as the live path did (from `decode_ctx.bin`),
reruns FFT → channel estimation → PUSCH decode on the stored samples, and asserts
the replay reproduces the live channel SINR and CRC:

```
EQUIVALENCE: crc MATCH (live=1 replay=1) | snr MATCH (Δ=0.0000) => PASS
```

`--sweep N` then runs an offline FFT-window **timing sweep** over ±N samples
(same mechanism as the live offset-retry), printing per-offset SINR / residual
TA / CRC and the best offset. This is where channel-estimator, noise-estimator
and LLR variants plug in next — always **after** exact replay equivalence is
proven on real captures.

Exit code: `0` = equivalence PASS, `1` = mismatch/decode-fail, `>1` = load error.
