"""Optional ZeroMQ PUB sink for the broadcast event stream.

Lets Python sidecars / Jupyter notebooks / off-host monitors subscribe to
the live sniffer feed without speaking WebSocket. Topic = event type (so a
subscriber can `s.subscribe(b"sf")` to get only subframes), payload is the
exact JSON bytes the WS sees.

Disabled by default; opt in with `LTESNIFFER_GUI_ZMQ_BIND=tcp://127.0.0.1:5555`
(or any zmq endpoint). When set, the publisher is bound at backend start and
torn down on shutdown via the FastAPI lifespan.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

log = logging.getLogger(__name__)


# Topics the WS already produces — keep this in sync with the protocol so a
# subscriber's `subscribe(topic)` actually matches.
_KNOWN_TOPICS = {"hello", "cell", "mib", "sf", "sf_tick", "stats", "log",
                 "identity", "lifecycle", "bye", "replay"}


class ZmqPublisher:
    """Bind a ZMQ PUB socket and forward every broadcast event to it.

    The publisher subscribes to the runner via `runner.subscribe()` like any
    other consumer; each event ((dict, encoded_str)) is sent as a two-frame
    multipart: [topic_bytes, payload_bytes]. Cheap — no extra JSON work
    because the encoded string is already cached.
    """

    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint
        self._sock = None
        self._ctx = None
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    async def start(self, runner) -> None:
        try:
            import zmq
            import zmq.asyncio
        except ImportError:
            log.warning("LTESNIFFER_GUI_ZMQ_BIND set but pyzmq not installed; disabling.")
            return
        self._ctx = zmq.asyncio.Context()
        self._sock = self._ctx.socket(zmq.PUB)
        # Drop-oldest under high load instead of blocking the broadcast loop.
        self._sock.setsockopt(zmq.SNDHWM, 5000)
        try:
            self._sock.bind(self.endpoint)
        except Exception as exc:
            log.error("ZMQ bind to %s failed: %s", self.endpoint, exc)
            self._sock = None
            return
        log.info("ZMQ publisher bound to %s; topics=%s", self.endpoint, sorted(_KNOWN_TOPICS))
        # Subscribe synchronously so we don't race with runner.start()
        self._q = runner.subscribe()
        self._task = asyncio.create_task(self._run(runner))

    async def _run(self, runner) -> None:
        import zmq
        q = self._q
        try:
            while not self._stopping:
                _ev, encoded = await q.get()
                topic = (_ev.get("t") or "?").encode("utf-8")
                payload = encoded.encode("utf-8")
                try:
                    # NOBLOCK + drop-on-fail: a wedged subscriber must not
                    # back-pressure the producer.
                    self._sock.send_multipart([topic, payload], flags=zmq.NOBLOCK)
                except zmq.Again:
                    # All subscribers' HWM full; drop.
                    pass
        except asyncio.CancelledError:
            pass
        finally:
            runner.unsubscribe(q)

    async def stop(self) -> None:
        self._stopping = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        if self._sock is not None:
            try:
                self._sock.close(linger=200)
            except Exception:
                pass
        if self._ctx is not None:
            try:
                self._ctx.term()
            except Exception:
                pass


def maybe_create() -> Optional[ZmqPublisher]:
    """Return a ZmqPublisher if LTESNIFFER_GUI_ZMQ_BIND is set, else None."""
    endpoint = os.environ.get("LTESNIFFER_GUI_ZMQ_BIND", "").strip()
    if not endpoint:
        return None
    return ZmqPublisher(endpoint)
