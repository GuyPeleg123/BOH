"""Per-UE state tracker (Phase 4.4 / F11 — Sni5Gect-style statefulness).

Consumes the broadcast event stream and projects it into a per-RNTI state
machine that binds the lifetime of a UE: first sighting (proxy for RA Msg4
contention-resolution) → DATA → idle/exit.

Also emits two derived event types into the same broadcast bus:

  - `ra_event`  : best-effort RA detection. Without C++ MAC-PDU parsing we
                  can't see the actual Msg1/Msg2/Msg3 exchange, so we use a
                  first-seen-C-RNTI heuristic with the current SFN/sf. This
                  is approximate but matches what most operators see in
                  passive monitoring.
  - `ue_state`  : transitions IDLE → DATA → IDLE per RNTI.

Both are tagged with a `cell_id` so multi-cell mode (Phase 4.7) keeps UEs
correctly separated.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

log = logging.getLogger(__name__)


# How long without any DCI before we consider a UE has gone IDLE.
UE_IDLE_AFTER_S = 8.0
# After this long with no DCI activity, drop the RNTI from tracking entirely
# (likely RNTI re-use cooldown completed or the UE has fully detached).
UE_FORGET_AFTER_S = 60.0
# C-RNTI value range from 3GPP TS 36.321 §7.1: 0x003D..0xFFF3 inclusive.
# Anything outside that is a non-C-RNTI (SI, P, RA, M, etc.) — skip.
C_RNTI_MIN = 0x003D
C_RNTI_MAX = 0xFFF3


class StateTracker:
    """Single-cell tracker — multi-cell wraps N of these."""

    def __init__(self, cell_id: int = 0) -> None:
        self.cell_id = cell_id
        # rnti -> {"first_seen": ts, "last_seen": ts, "state": str,
        #          "dl_count": int, "ul_count": int, "ra_emitted": bool}
        self._ues: dict[int, dict] = {}
        self._cell_pci: Optional[int] = None
        self._sf_now = (0, 0)        # (sfn, sf) latest seen
        self._publish = None         # set by start()
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    # ----- subscribe-able API used by main.py -----

    async def start(self, runner, publish_into_runner=None) -> None:
        self._publish = publish_into_runner or runner._broadcast
        self._q = runner.subscribe()
        self._task = asyncio.create_task(self._run(runner))

    async def stop(self) -> None:
        self._stopping = True
        if self._task:
            self._task.cancel()
            try: await self._task
            except (asyncio.CancelledError, Exception): pass

    async def _run(self, runner) -> None:
        # Periodically sweep for stale UEs.
        sweep_task = asyncio.create_task(self._sweep_loop())
        try:
            while not self._stopping:
                ev, _ = await self._q.get()
                self._apply(ev)
        except asyncio.CancelledError:
            pass
        finally:
            sweep_task.cancel()
            runner.unsubscribe(self._q)

    async def _sweep_loop(self) -> None:
        try:
            while not self._stopping:
                await asyncio.sleep(2.0)
                self._sweep()
        except asyncio.CancelledError:
            pass

    # ----- event processing -----

    def _apply(self, ev: dict) -> None:
        t = ev.get("t")
        if t == "cell":
            self._cell_pci = ev.get("pci")
        elif t == "lifecycle" and ev.get("event") == "started":
            # Reset all per-UE state at the start of a new capture.
            self._ues.clear()
            self._cell_pci = None
        elif t == "sf":
            self._sf_now = (ev.get("sfn", 0), ev.get("sf", 0))
            ts = ev.get("ts", 0)
            for d in ev.get("dl") or []:
                self._touch(d.get("rnti"), "dl", ts)
            for d in ev.get("ul") or []:
                self._touch(d.get("rnti"), "ul", ts)
        elif t == "sf_tick":
            # sf_tick has no per-RNTI breakdown; just advances SFN.
            self._sf_now = (ev.get("sfn", 0), ev.get("sf", 0))

    def _touch(self, rnti: Optional[int], direction: str, ts: float) -> None:
        if rnti is None or not (C_RNTI_MIN <= rnti <= C_RNTI_MAX):
            return
        ue = self._ues.get(rnti)
        if ue is None:
            # First sighting → emit a best-effort ra_event + ue_state(DATA).
            self._ues[rnti] = ue = {
                "first_seen": ts, "last_seen": ts, "state": "DATA",
                "dl_count": 0, "ul_count": 0,
            }
            self._emit({
                "t": "ra_event", "ts": ts, "cell_id": self.cell_id,
                "sfn": self._sf_now[0], "sf": self._sf_now[1],
                "rnti": rnti, "source": "first_seen_heuristic",
            })
            self._emit({
                "t": "ue_state", "ts": ts, "cell_id": self.cell_id,
                "rnti": rnti, "from": "IDLE", "to": "DATA",
            })
            self._emit({
                "t": "log", "ts": ts, "level": "info", "source": "state_tracker",
                "msg": f"[cell {self.cell_id}] new UE rnti=0x{rnti:04x} (first seen, sfn={self._sf_now[0]}.{self._sf_now[1]})",
            })
        else:
            ue["last_seen"] = ts
            if ue["state"] == "IDLE":
                # UE came back — re-emit a transition.
                self._emit({
                    "t": "ue_state", "ts": ts, "cell_id": self.cell_id,
                    "rnti": rnti, "from": "IDLE", "to": "DATA",
                })
                self._emit({
                    "t": "log", "ts": ts, "level": "info", "source": "state_tracker",
                    "msg": f"[cell {self.cell_id}] UE rnti=0x{rnti:04x} resumed (was IDLE)",
                })
                ue["state"] = "DATA"
        ue["dl_count" if direction == "dl" else "ul_count"] += 1

    def _sweep(self) -> None:
        # Use the latest event 'ts' (C++ elapsed seconds) rather than wall
        # clock — so a replay at the correct event-time pacing still triggers
        # idle/forget transitions properly.
        latest = max((u["last_seen"] for u in self._ues.values()), default=0)
        for rnti, ue in list(self._ues.items()):
            ago = latest - ue["last_seen"]
            if ue["state"] == "DATA" and ago > UE_IDLE_AFTER_S:
                ue["state"] = "IDLE"
                self._emit({
                    "t": "ue_state", "ts": latest, "cell_id": self.cell_id,
                    "rnti": rnti, "from": "DATA", "to": "IDLE",
                })
                self._emit({
                    "t": "log", "ts": latest, "level": "info", "source": "state_tracker",
                    "msg": f"[cell {self.cell_id}] UE rnti=0x{rnti:04x} → IDLE (no DCI for {ago:.0f}s, last had {ue['dl_count']}/{ue['ul_count']} DL/UL DCIs)",
                })
            elif ago > UE_FORGET_AFTER_S:
                self._emit({
                    "t": "ue_state", "ts": latest, "cell_id": self.cell_id,
                    "rnti": rnti, "from": ue["state"], "to": "FORGOTTEN",
                })
                del self._ues[rnti]

    def _emit(self, event: dict) -> None:
        if self._publish is None:
            return
        try:
            self._publish(event)
        except Exception as exc:
            log.debug("state_tracker publish failed: %s", exc)
