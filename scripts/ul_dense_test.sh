#!/usr/bin/env bash
# UL dense-area diagnostic capture.
# Runs LTESniffer in dual mode with the env-gated UL diagnostics ON, and saves
# BOTH the console log (per-second UL rate + DMRS/time-offset sweeps) and the
# pcap to a timestamped folder. Bring that folder back for offline analysis.
#
# Usage:  scripts/ul_dense_test.sh [duration_seconds]   (default 240 = 4 min)
#
# Notes:
#  - Run this DIRECTLY (not via the GUI): the GUI discards stdout, which is
#    where the diagnostics print. This script captures them.
#  - It uses cell search (-C) so it locks whatever real cell is strongest where
#    you are standing — you do NOT need to know the PCI in advance.
#  - Hold the UL antenna toward the crowd / where phones are physically closest.
set -euo pipefail

DUR="${1:-240}"
BIN="/home/project44/work/LTESniffer/build/src/LTESniffer"
OUT="$HOME/ltesniffer-captures/uldiag_$(date +%Y-%m-%d_%H-%M-%S)"
mkdir -p "$OUT"

# Diagnostics: per-second UL attempts/success + SNR/timing, and time-offset +
# cyclic-shift SNR sweeps on any grant whose raw RB power clears 2 dB.
export UL_RATE_DIAG=1 UL_DMRS_DIAG=1 UL_TOFF_DIAG=1 UL_DMRS_DIAG_PWR=2

echo "[ul_dense_test] running ${DUR}s, saving to $OUT"
cd "$(dirname "$BIN")"
timeout "$DUR" "$BIN" \
  -f 1825000000 -u 1730000000 \
  -X clock=external,type=b200,serial=32FCD4C \
  -Z clock=external,type=b200,serial=3367EF9 \
  -m 2 -C -W 4 -S 0.5 -T 100 -q 1 \
  > "$OUT/console.log" 2>&1 || true

# Preserve the pcap this run produced (the binary writes a fixed filename).
cp -f "$(dirname "$BIN")/ltesniffer_dual_mode.pcap" "$OUT/capture.pcap" 2>/dev/null || true

echo "[ul_dense_test] done."
echo "  log : $OUT/console.log"
echo "  pcap: $OUT/capture.pcap"
echo "  quick UL summary:"
grep -c ULTOFF "$OUT/console.log" 2>/dev/null | sed 's/^/    offset sweeps: /' || true
grep ULRATE "$OUT/console.log" 2>/dev/null | tail -1 | sed 's/^/    last rate line: /' || true
