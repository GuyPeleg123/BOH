"""Session recorder: tees every broadcast event to a rolling .jsonl.zst file.

Lives at ~/.local/share/ltesniffer-gui/sessions/<isodate>.jsonl.zst with
gzip-style rotation every SESSION_ROTATE_MB. Each line is one JSON event,
identical to what the WebSocket sees — making the file directly replayable
by ReplayRunner.

Opt-out: LTESNIFFER_GUI_RECORD=0. Default ON because the cost is
negligible (one async fwrite + zstd compression at very-low CPU).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


SESSIONS_DIR = Path.home() / ".local" / "share" / "ltesniffer-gui" / "sessions"
SESSION_ROTATE_MB = 50
SESSION_ROTATE_BYTES = SESSION_ROTATE_MB * 1024 * 1024


def _enabled() -> bool:
    return os.environ.get("LTESNIFFER_GUI_RECORD", "1").lower() not in {"0", "false", "no", ""}


class SessionRecorder:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._zw = None
        self._fp = None
        self._path: Optional[Path] = None
        self._bytes_written = 0
        self._stopping = False
        self._seq = 0

    @property
    def path(self) -> Optional[Path]:
        return self._path

    def _open_new(self) -> None:
        try:
            import zstandard as zstd
        except ImportError:
            log.warning("session recorder: zstandard not installed; disabling.")
            return
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self._seq += 1
        self._path = SESSIONS_DIR / f"session_{ts}_{self._seq:03d}.jsonl.zst"
        # Use 0o600 perms so only the operator can read past sessions
        # (they may contain hex DCIs / RNTIs / etc.).
        self._fp = open(self._path, "wb")
        os.fchmod(self._fp.fileno(), 0o600)
        self._zw = zstd.ZstdCompressor(level=3).stream_writer(self._fp)
        self._bytes_written = 0
        log.info("session recorder: rolling -> %s", self._path)

    def _close(self) -> None:
        if self._zw is not None:
            try:
                self._zw.close()
            except Exception:
                pass
            self._zw = None
        if self._fp is not None:
            try:
                self._fp.close()
            except Exception:
                pass
            self._fp = None

    def _rotate_if_needed(self) -> None:
        if self._bytes_written >= SESSION_ROTATE_BYTES:
            self._close()
            self._open_new()

    async def start(self, runner) -> None:
        if not _enabled():
            log.info("session recorder disabled via LTESNIFFER_GUI_RECORD=0")
            return
        self._open_new()
        if self._zw is None:
            return  # bail (zstd missing)
        # Subscribe synchronously so REPLAY mode (which fires runner.start
        # inside the same lifespan tick) doesn't lose the head of stream.
        self._q = runner.subscribe()
        self._task = asyncio.create_task(self._run(runner))

    async def _run(self, runner) -> None:
        q = self._q
        try:
            while not self._stopping:
                _ev, encoded = await q.get()
                # encoded is the canonical JSON string (cached by _broadcast).
                line = (encoded + "\n").encode("utf-8")
                if self._zw is not None:
                    try:
                        self._zw.write(line)
                        self._bytes_written += len(line)
                        self._rotate_if_needed()
                    except OSError as exc:
                        log.warning("session recorder write failed: %s", exc)
                        self._close()
                        return
        except asyncio.CancelledError:
            pass
        finally:
            runner.unsubscribe(q)
            self._close()

    async def stop(self) -> None:
        self._stopping = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._close()


# ---------------------------------------------------------------------------
# ReplayRunner — exposes the same surface as SnifferRunner / MockRunner so
# main.py can drop it in via env. Reads a recorded .jsonl.zst back at
# real-time pacing (or as fast as possible with LTESNIFFER_GUI_REPLAY_FF=1).
# ---------------------------------------------------------------------------

class ReplayRunner:
    """Plays back a recorded session as if it were a live capture.

    Useful for: deterministic regression tests, demos without hardware,
    bug reports with the exact stimulus.

    The surface mirrors SnifferRunner / MockRunner: start/stop/restart,
    subscribe/unsubscribe/replay/state/running.
    """

    def __init__(self, source: Path) -> None:
        self._source = source
        self._subscribers: set[asyncio.Queue] = set()
        from collections import deque
        self._last_events = deque(maxlen=500)
        self._sticky: dict[str, dict] = {}
        self._state = {
            "running": False, "pid": None, "started_at": None,
            "exit_code": None, "last_error": None, "argv": [str(source)],
            "replay": True,
        }
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def replay(self) -> list[dict]:
        sticky_keys = ("lifecycle", "hello", "cell", "mib", "stats")
        return [self._sticky[k] for k in sticky_keys if k in self._sticky] + list(self._last_events)

    def state(self) -> dict:
        return dict(self._state)

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def _broadcast(self, event: dict) -> None:
        import json as _json
        t = event.get("t")
        if t in ("hello", "cell", "mib", "lifecycle", "stats"):
            self._sticky[t] = event
        self._last_events.append(event)
        encoded = _json.dumps(event)
        item = (event, encoded)
        for q in list(self._subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                try: q.get_nowait()
                except asyncio.QueueEmpty: pass
                try: q.put_nowait(item)
                except asyncio.QueueFull: pass

    async def start(self, cfg=None) -> None:
        if self.running:
            return
        self._sticky.clear()
        self._last_events.clear()
        self._state.update(running=True, started_at=time.time(), exit_code=None)
        self._task = asyncio.create_task(self._run())

    async def stop(self, timeout: float = 5.0) -> None:
        self._stopping = True
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    async def restart(self, cfg=None) -> None:
        await self.stop()
        self._stopping = False
        await self.start(cfg)

    async def _run(self) -> None:
        import json as _json
        try:
            import zstandard as zstd
        except ImportError:
            self._broadcast({"t": "log", "level": "error", "msg": "ReplayRunner needs zstandard"})
            self._state["running"] = False
            return
        fast_forward = os.environ.get("LTESNIFFER_GUI_REPLAY_FF", "").lower() in {"1", "true", "yes"}
        self._broadcast({"t": "lifecycle", "event": "started", "pid": 0, "argv": self._state["argv"]})
        first_ts: Optional[float] = None
        wall_start = time.monotonic()
        try:
            with open(self._source, "rb") as f:
                dctx = zstd.ZstdDecompressor()
                with dctx.stream_reader(f) as reader:
                    import io
                    text = io.TextIOWrapper(reader, encoding="utf-8")
                    for line in text:
                        if self._stopping:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = _json.loads(line)
                        except Exception:
                            continue
                        # Pace by event ts vs first ts (real-time replay).
                        ts = ev.get("ts")
                        if not fast_forward and isinstance(ts, (int, float)):
                            if first_ts is None:
                                first_ts = ts
                            wall_elapsed = time.monotonic() - wall_start
                            target_elapsed = ts - first_ts
                            sleep_for = target_elapsed - wall_elapsed
                            if sleep_for > 0:
                                await asyncio.sleep(min(sleep_for, 0.5))
                        self._broadcast(ev)
            self._broadcast({"t": "log", "level": "info", "msg": "replay complete"})
        except FileNotFoundError:
            self._broadcast({"t": "log", "level": "error", "msg": f"replay file not found: {self._source}"})
        except asyncio.CancelledError:
            pass
        finally:
            self._broadcast({"t": "lifecycle", "event": "exited", "exit_code": 0})
            self._state["running"] = False
            self._state["exit_code"] = 0
