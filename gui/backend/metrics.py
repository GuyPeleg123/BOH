"""Prometheus /metrics exporter.

Subscribes to the runner's event stream and projects it into Prometheus
counters + gauges. Exposed at GET /metrics (token-free, like /api/health,
so Prometheus scrapers don't need to know about the bearer token — bind
to 127.0.0.1 if you don't want the metrics readable from the LAN).

Conventions follow the Prometheus naming guidelines (snake_case, _total
suffix on counters, base units in labels where helpful).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from prometheus_client import (
    CollectorRegistry, Counter, Gauge, Histogram, generate_latest,
    CONTENT_TYPE_LATEST,
)

log = logging.getLogger(__name__)


class MetricsBus:
    """Owns a CollectorRegistry and updates it from runner events."""

    def __init__(self) -> None:
        self.reg = CollectorRegistry()

        self.dci = Counter(
            "ltesniffer_dci_decoded_total", "DCIs decoded since process start",
            ["direction"], registry=self.reg,
        )
        self.tbs = Counter(
            "ltesniffer_tbs_bits_total", "Cumulative transport block size in bits",
            ["direction"], registry=self.reg,
        )
        self.rb = Counter(
            "ltesniffer_rb_total", "Cumulative resource blocks observed",
            ["direction"], registry=self.reg,
        )
        self.sf_processed = Counter(
            "ltesniffer_sf_processed_total", "Subframes processed (from sf+sf_tick events)",
            registry=self.reg,
        )
        self.sf_skipped = Counter(
            "ltesniffer_sf_skipped_total", "Subframes skipped (from stats events)",
            registry=self.reg,
        )
        self.overflow = Counter(
            "ltesniffer_overflow_total", "FIFO/USB overflow events",
            registry=self.reg,
        )
        self.lifecycle = Counter(
            "ltesniffer_lifecycle_total", "Lifecycle transitions",
            ["event"], registry=self.reg,
        )

        self.rnti_active = Gauge(
            "ltesniffer_rnti_active", "Active RNTIs in the most recent stats event",
            registry=self.reg,
        )
        self.cfo_hz = Gauge(
            "ltesniffer_cfo_hz", "Most recently observed carrier frequency offset",
            registry=self.reg,
        )
        self.cell_pci = Gauge(
            "ltesniffer_cell_pci", "Currently locked cell PCI (-1 if no cell)",
            registry=self.reg,
        )
        self.dl_freq_hz = Gauge(
            "ltesniffer_dl_freq_hz", "Currently tuned downlink frequency",
            registry=self.reg,
        )
        self.capture_running = Gauge(
            "ltesniffer_capture_running", "1 if a capture is currently running",
            registry=self.reg,
        )
        self.dropped_events = Counter(
            "ltesniffer_dropped_events_total", "Events dropped by the C++ emitter (FIFO EAGAIN)",
            registry=self.reg,
        )
        self.mcs = Histogram(
            "ltesniffer_dci_mcs", "MCS values decoded",
            ["direction"], buckets=tuple(range(0, 32, 2)) + (32,), registry=self.reg,
        )

        # Initialise zero values so /metrics exposes them before the first event.
        for d in ("dl", "ul"):
            self.dci.labels(direction=d).inc(0)
            self.tbs.labels(direction=d).inc(0)
            self.rb.labels(direction=d).inc(0)
        self.cell_pci.set(-1)
        self.dl_freq_hz.set(0)
        self.capture_running.set(0)
        # Last dropped_events value seen (counter delta).
        self._last_dropped = 0

        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    async def start(self, runner) -> None:
        # Subscribe *synchronously* (before returning) so we don't miss the
        # first events if runner.start fires immediately after.
        self._q = runner.subscribe()
        self._task = asyncio.create_task(self._run(runner))

    async def stop(self) -> None:
        self._stopping = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    async def _run(self, runner) -> None:
        try:
            while not self._stopping:
                ev, _encoded = await self._q.get()
                self._apply(ev)
        except asyncio.CancelledError:
            pass
        finally:
            runner.unsubscribe(self._q)

    def _apply(self, ev: dict) -> None:  # noqa: C901
        t = ev.get("t")
        if t == "sf":
            self.sf_processed.inc()
            for d in ev.get("dl") or []:
                self.dci.labels(direction="dl").inc()
                self.tbs.labels(direction="dl").inc(d.get("tbs") or 0)
                self.rb.labels(direction="dl").inc(d.get("nprb") or 0)
                if "mcs" in d:
                    self.mcs.labels(direction="dl").observe(d["mcs"])
            for d in ev.get("ul") or []:
                self.dci.labels(direction="ul").inc()
                self.tbs.labels(direction="ul").inc(d.get("tbs") or 0)
                self.rb.labels(direction="ul").inc(d.get("nprb") or 0)
                if "mcs" in d:
                    self.mcs.labels(direction="ul").observe(d["mcs"])
        elif t == "sf_tick":
            # Lightweight per-subframe counters
            self.sf_processed.inc()
            self.dci.labels(direction="dl").inc(ev.get("dl_n") or 0)
            self.dci.labels(direction="ul").inc(ev.get("ul_n") or 0)
        elif t == "stats":
            self.rnti_active.set(ev.get("nof_rnti") or 0)
            self.cfo_hz.set(ev.get("cfo_hz") or 0)
            skipped = ev.get("sf_skipped") or 0
            # Skipped is reported as cumulative-per-capture in stats; track deltas.
            # Counters can only go up; we just set a snapshot every time.
            # If the user wants exact deltas they should use the sf_skipped delta
            # from two consecutive scrapes anyway.
            self._set_counter(self.sf_skipped, skipped)
            dropped = ev.get("dropped_events") or 0
            self._set_counter(self.dropped_events, dropped)
        elif t == "cell":
            self.cell_pci.set(ev.get("pci") or 0)
            self.dl_freq_hz.set(ev.get("dl_freq") or 0)
        elif t == "lifecycle":
            self.lifecycle.labels(event=ev.get("event") or "?").inc()
            if ev.get("event") == "started":
                self.capture_running.set(1)
            elif ev.get("event") == "exited":
                self.capture_running.set(0)
                self.cell_pci.set(-1)

    @staticmethod
    def _set_counter(counter: Counter, target: int) -> None:
        """Counters only have inc(); to track a cumulative value we sample the
        delta against an internal cache. This works as long as the source is
        monotonic (which sf_skipped and dropped_events are within one
        capture). On lifecycle:exited the prior value is forgotten — there's
        a momentary undercounting at the boundary, which is acceptable."""
        # We don't have stable per-label state here, so inc by the delta from
        # the previous sample stored on the metric itself via an attribute.
        prev = getattr(counter, "_prev_sample", 0)
        if target >= prev:
            counter.inc(target - prev)
        # else (counter went down — likely a restart): just resync without inc'ing.
        counter._prev_sample = target  # type: ignore[attr-defined]

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.reg), CONTENT_TYPE_LATEST
