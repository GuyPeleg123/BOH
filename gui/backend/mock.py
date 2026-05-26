"""Synthetic event generator for frontend development without SDR hardware.

Drop-in replacement for SnifferRunner: same public interface (start/stop/
restart/subscribe/state) but emits hand-crafted events on a timer so the UI
can be developed and demoed without a USRP.

Activated via env var:  LTESNIFFER_GUI_MOCK=1
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from collections import deque
from typing import Any, Optional

from config import SnifferConfig


class MockRunner:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._subscribers: set[asyncio.Queue] = set()
        self._last_events: deque[dict[str, Any]] = deque(maxlen=500)
        self._sticky: dict[str, dict[str, Any]] = {}
        self._state: dict[str, Any] = {
            "running": False,
            "pid": None,
            "started_at": None,
            "exit_code": None,
            "last_error": None,
            "argv": [],
            "mock": True,
        }
        self._cfg: Optional[SnifferConfig] = None

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def state(self) -> dict[str, Any]:
        return dict(self._state)

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def _broadcast(self, event: dict[str, Any]) -> None:
        t = event.get("t")
        if t in ("hello", "cell", "mib", "lifecycle", "stats"):
            self._sticky[t] = event
        self._last_events.append(event)
        # Mirror SnifferRunner: pre-encode JSON once, queues hold (dict, str).
        encoded = json.dumps(event)
        item = (event, encoded)
        # Drop-oldest semantics — mirror SnifferRunner._broadcast so a slow
        # consumer doesn't wedge the WS coroutine.
        for q in list(self._subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                try: q.get_nowait()
                except asyncio.QueueEmpty: pass
                try: q.put_nowait(item)
                except asyncio.QueueFull: pass

    def replay(self) -> list[dict[str, Any]]:
        # See sniffer.py: lifecycle must precede the others so its reset doesn't clobber them.
        sticky_keys = ("lifecycle", "hello", "cell", "mib", "stats")
        return [self._sticky[k] for k in sticky_keys if k in self._sticky] + list(self._last_events)

    async def start(self, cfg: SnifferConfig) -> None:
        if self.running:
            raise RuntimeError("mock sniffer already running")
        self._sticky.clear()
        self._last_events.clear()
        self._cfg = cfg
        self._state.update(
            running=True,
            pid=99999,
            started_at=time.time(),
            exit_code=None,
            last_error=None,
            argv=cfg.to_argv("<mock>"),
        )
        self._task = asyncio.create_task(self._run(cfg))

    async def stop(self, timeout: float = 5.0) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    async def restart(self, cfg: SnifferConfig) -> None:
        await self.stop()
        await self.start(cfg)

    async def _run(self, cfg: SnifferConfig) -> None:
        t0 = time.monotonic()

        def ts() -> float:
            return round(time.monotonic() - t0, 6)

        try:
            self._broadcast({"t": "lifecycle", "event": "started", "pid": 99999, "argv": self._state["argv"]})

            self._broadcast({
                "t": "hello", "ts": ts(), "version": 1,
                "args": {
                    "rf_freq": cfg.rf_freq, "ul_freq": cfg.ul_freq,
                    "sniffer_mode": cfg.sniffer_mode, "nof_prb": cfg.nof_prb,
                    "nof_threads": cfg.nof_sniffer_thread, "rnti": 65535,
                    "target_rnti": cfg.target_rnti, "cell_search": cfg.cell_search,
                    "rf_args": cfg.rf_args, "rf_gain": cfg.rf_gain,
                    "nof_rx_ant": cfg.rf_nof_rx_ant, "api_mode": cfg.api_mode,
                },
            })
            await asyncio.sleep(0.5)
            self._broadcast({"t": "log", "ts": ts(), "level": "info", "msg": "[MOCK] Cell search starting..."})
            await asyncio.sleep(1.0)

            nof_prb = cfg.nof_prb or 50
            pci = random.randint(0, 503)
            self._broadcast({
                "t": "cell", "ts": ts(),
                "pci": pci, "nof_prb": nof_prb, "nof_ports": 2,
                "cp": "normal", "mode": "FDD",
                "dl_freq": cfg.rf_freq or 1840e6, "ul_freq": cfg.ul_freq,
                "sample_rate": 11_520_000.0,
            })
            self._broadcast({"t": "mib", "ts": ts(), "sfn": 100, "sfn_offset": 2})

            # Simulated UE population
            rntis = [random.randint(60, 65000) for _ in range(8)]
            sfn = 100
            sf = 0
            sf_processed = 0
            sf_skipped = 0
            rb_dl_tot = 0
            rb_ul_tot = 0

            while True:
                sf += 1
                if sf == 10:
                    sf = 0
                    sfn = (sfn + 1) % 1024

                # Build a random allocation
                rb_dl = [0] * nof_prb
                rb_ul = [0] * nof_prb
                dl_dcis = []
                ul_dcis = []
                for r in random.sample(rntis, k=random.randint(0, min(4, len(rntis)))):
                    start = random.randint(0, nof_prb - 1)
                    width = random.randint(1, min(8, nof_prb - start))
                    for i in range(start, start + width):
                        rb_dl[i] = r
                    dl_dcis.append({
                        "rnti": r, "fmt": random.choice(["1A", "2", "2A"]),
                        "mcs": random.randint(0, 28), "nprb": width,
                        "tbs": width * random.randint(100, 800),
                        "ndi": random.randint(0, 1), "harq": random.randint(0, 7),
                        "ncce": 0, "L": 1, "hist": random.randint(1, 99),
                        "hex": f"{random.randint(0, 0xffff):04x}",
                    })
                    rb_dl_tot += width
                if cfg.sniffer_mode in (1, 2) and random.random() < 0.4:
                    r = random.choice(rntis)
                    width = random.randint(1, 6)
                    start = random.randint(0, nof_prb - width)
                    for i in range(start, start + width):
                        rb_ul[i] = r
                    ul_dcis.append({
                        "rnti": r, "fmt": "0", "mcs": random.randint(0, 28),
                        "nprb": width, "tbs": width * 200,
                        "ndi": random.randint(0, 1),
                        "ncce": 0, "L": 1, "hist": 1, "hex": "1234",
                    })
                    rb_ul_tot += width

                pwr = [-95.0 + random.gauss(0, 3) + (3 if rb_dl[i] else 0) for i in range(nof_prb)]
                self._broadcast({
                    "t": "sf", "ts": ts(), "sfn": sfn, "sf": sf, "cfi": 2,
                    "dl": dl_dcis, "ul": ul_dcis,
                    "rb_dl": rb_dl, "rb_ul": rb_ul,
                    "pwr_dl": [round(p, 2) for p in pwr],
                    "pwr_min": round(min(pwr), 2), "pwr_max": round(max(pwr), 2),
                })
                sf_processed += 1

                # Periodic stats
                if sf_processed % 100 == 0:
                    self._broadcast({
                        "t": "stats", "ts": ts(), "sfn": sfn,
                        "sf_processed": sf_processed, "sf_skipped": sf_skipped,
                        "nof_rnti": len(rntis), "rb_dl_total": rb_dl_tot,
                        "rb_ul_total": rb_ul_tot, "cfo_hz": round(random.gauss(-100, 30), 1),
                    })

                # Rare identity discovery
                if cfg.api_mode in (1, 3) and random.random() < 0.002:
                    self._broadcast({
                        "t": "identity", "ts": ts(), "sfn": sfn, "kind": "imsi",
                        "rnti": random.choice(rntis),
                        "value": f"310410{random.randint(0, 999_999_999):09d}",
                        "from": "AttachRequest",
                    })

                # Mock runs at ~50 sf/s (real LTE is 1000 sf/s, way too fast for the UI).
                await asyncio.sleep(0.02)
        except asyncio.CancelledError:
            self._broadcast({"t": "bye", "ts": ts(), "reason": "stop"})
            raise
        finally:
            self._state["running"] = False
            self._state["exit_code"] = 0
            self._broadcast({"t": "lifecycle", "event": "exited", "exit_code": 0})
