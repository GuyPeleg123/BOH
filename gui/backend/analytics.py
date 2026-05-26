"""Offline analytics over recorded sessions.

Currently implements F6 (RNTIChurnAnalyzer) — estimates per-cell RNTI
reuse timer from the gaps between an RNTI going IDLE and being seen again.
Useful to size the cooldown window for downstream TMSI→IMSI binding.

Designed to run against a recorded .jsonl.zst session file produced by
the SessionRecorder, so it works offline without re-launching the sniffer.
Exposed via:

    GET /api/analytics/rnti-churn?path=<file>

(token-gated like everything else under /api/).
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from statistics import median, mean
from typing import Iterable


def _iter_session(path: Path) -> Iterable[dict]:
    """Yield dict events from a recorder file. Tolerant of partial last frame."""
    try:
        import zstandard as zstd
    except ImportError:
        return
    try:
        with open(path, "rb") as f:
            reader = zstd.ZstdDecompressor().stream_reader(f)
            text = io.TextIOWrapper(reader, encoding="utf-8", errors="replace")
            for line in text:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except FileNotFoundError:
        return


def analyze_rnti_churn(path: Path) -> dict:
    """Estimate RNTI lifetime + reuse delay.

    Heuristic:
      - For each RNTI, record (first_seen_ts, last_seen_ts) windows.
      - When the same RNTI appears with a gap > 5s, treat as a re-use:
        emit a (lifetime, gap_until_reuse) pair.

    Returns medians + distribution buckets so the operator can pick a
    sensible UE_FORGET_AFTER_S in state_tracker.py.
    """
    windows: dict[int, list[tuple[float, float]]] = {}  # rnti -> [(start, end), ...]

    GAP_THRESHOLD = 5.0  # seconds without seeing the RNTI = end of a window

    last_seen: dict[int, float] = {}
    cur_window: dict[int, tuple[float, float]] = {}

    n_events = 0
    n_sf = 0
    for ev in _iter_session(path):
        n_events += 1
        if ev.get("t") not in ("sf", "sf_tick"):
            continue
        n_sf += 1
        if ev.get("t") == "sf_tick":
            continue  # no per-RNTI breakdown
        ts = ev.get("ts", 0)
        for d in (ev.get("dl") or []) + (ev.get("ul") or []):
            r = d.get("rnti")
            if r is None or not (0x003D <= r <= 0xFFF3):
                continue
            prev_seen = last_seen.get(r)
            if prev_seen is None or (ts - prev_seen) > GAP_THRESHOLD:
                # Close the previous window if any, open a new one.
                if r in cur_window:
                    windows.setdefault(r, []).append(cur_window[r])
                cur_window[r] = (ts, ts)
            else:
                start, _ = cur_window[r]
                cur_window[r] = (start, ts)
            last_seen[r] = ts

    # Close any still-open windows.
    for r, win in cur_window.items():
        windows.setdefault(r, []).append(win)

    # Lifetimes (per-window duration), reuse-delays (gap between consecutive windows for same RNTI).
    lifetimes: list[float] = []
    reuse_delays: list[float] = []
    for r, wins in windows.items():
        for s, e in wins:
            lifetimes.append(e - s)
        for a, b in zip(wins, wins[1:]):
            reuse_delays.append(b[0] - a[1])

    def _stats(arr: list[float]) -> dict:
        if not arr:
            return {"n": 0}
        sorted_a = sorted(arr)
        return {
            "n":      len(arr),
            "min":    sorted_a[0],
            "p25":    sorted_a[max(0, len(arr)//4)],
            "median": median(arr),
            "mean":   round(mean(arr), 3),
            "p75":    sorted_a[min(len(arr)-1, 3*len(arr)//4)],
            "p95":    sorted_a[min(len(arr)-1, int(0.95*len(arr)))],
            "max":    sorted_a[-1],
        }

    return {
        "path": str(path),
        "events_total": n_events,
        "sf_events":    n_sf,
        "unique_rntis": len(windows),
        "total_windows":len(lifetimes),
        "lifetime_seconds":   _stats(lifetimes),
        "reuse_delay_seconds":_stats(reuse_delays),
    }
