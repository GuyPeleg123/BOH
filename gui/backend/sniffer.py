"""LTESniffer subprocess + event-stream lifecycle.

The backend creates a FIFO, launches `LTESniffer ... -J <fifo>`, and reads
newline-delimited JSON events from the FIFO. Events are pushed into the
broadcast queue and fanned out to every connected WebSocket.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import tempfile
import time
from collections import deque
from pathlib import Path
from typing import Any, AsyncIterator, Optional

import re

from config import SnifferConfig


# Redact KASME / K_eNB (256-bit, 64 hex) and intermediate keys (128-bit, 32 hex)
# from anything LTESniffer prints to stderr before it lands in the rolling
# event buffer / WebSocket fan-out. Matches loose word boundaries so things
# like "kenb=ABCD..." get caught.
_HEX_KEY_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_HEX_KEY_RE_128 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")


def _redact_keys(msg: str) -> str:
    msg = _HEX_KEY_RE.sub("<redacted-256>", msg)
    msg = _HEX_KEY_RE_128.sub("<redacted-128>", msg)
    return msg


# Hard allowlist of LTESniffer binaries the backend will spawn. Anything else
# is rejected with a 403 before we touch sudo. This is the second line of
# defence behind a properly-scoped sudoers entry — without it, an attacker
# who can edit the saved config can run /usr/bin/id (or worse) as root.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_ALLOWED_BINARIES: set[Path] = {
    (_REPO_ROOT / "build" / "src" / "LTESniffer").resolve(),
    Path("/usr/local/bin/LTESniffer"),
    Path("/usr/bin/LTESniffer"),
}


_STREAM_FIFO_ALLOWED_ROOTS = (Path("/tmp"), Path.home() / "ltesniffer-captures")


def _ensure_stream_fifo(path_s: str) -> Path:
    """Validate a pcap-stream FIFO path and create it as a FIFO if missing.

    Refuses paths outside /tmp/ or the default captures dir, refuses symlinks,
    and refuses existing regular files (don't accidentally append a libpcap
    header onto someone's important file).
    """
    p = Path(path_s).expanduser()
    if not p.is_absolute():
        raise PermissionError(f"pcap_stream_fifo must be absolute, got {path_s}")
    if p.is_symlink():
        raise PermissionError(f"pcap_stream_fifo refuses symlinks: {p}")
    if not any(str(p).startswith(str(r) + os.sep) for r in _STREAM_FIFO_ALLOWED_ROOTS):
        raise PermissionError(
            f"pcap_stream_fifo must live under one of: "
            f"{', '.join(str(r) for r in _STREAM_FIFO_ALLOWED_ROOTS)}"
        )
    if p.exists():
        # Must already be a FIFO — refuse to overwrite something else.
        st = os.stat(p, follow_symlinks=False)
        import stat as _stat
        if not _stat.S_ISFIFO(st.st_mode):
            raise PermissionError(f"{p} exists and is not a FIFO; refusing to touch it")
        return p
    p.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(p, 0o660)
    return p


def _resolve_and_validate_binary(cfg_path: str) -> Path:
    """Resolve `cfg.binary_path` and confirm it's in the allowlist.

    Raises PermissionError with a clear message otherwise.
    """
    p = Path(cfg_path).expanduser()
    if not p.is_absolute():
        p = (Path(__file__).resolve().parent / p).resolve()
    else:
        p = p.resolve()
    if p not in _ALLOWED_BINARIES:
        allowed = ", ".join(sorted(str(x) for x in _ALLOWED_BINARIES))
        raise PermissionError(
            f"binary_path '{cfg_path}' (resolved to {p}) is not in the allowlist. "
            f"Allowed: {allowed}"
        )
    if not p.exists():
        raise FileNotFoundError(f"LTESniffer binary not found at {p}")
    return p


class SnifferRunner:
    """Owns a single LTESniffer subprocess + its event stream."""

    def __init__(self) -> None:
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._fifo_dir: Optional[tempfile.TemporaryDirectory] = None
        self._fifo_path: Optional[Path] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._wait_task: Optional[asyncio.Task] = None  # tracked so we can cancel on restart
        self._subscribers: set[asyncio.Queue] = set()
        self._last_events: deque[dict[str, Any]] = deque(maxlen=500)
        self._dropped_for_slow_consumer = 0
        self._last_drop_log = 0
        # Sticky events kept outside the rolling buffer so that a refresh
        # after the buffer has rolled past still shows cell / lifecycle state.
        self._sticky: dict[str, dict[str, Any]] = {}
        self._state: dict[str, Any] = {
            "running": False,
            "pid": None,
            "started_at": None,
            "exit_code": None,
            "last_error": None,
            "argv": [],
        }

    # ------------------------------------------------------------------ pubsub

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def replay(self) -> list[dict[str, Any]]:
        """Return events for a freshly-connected client.

        Order: sticky events (hello/cell/mib/lifecycle/stats), then the
        rolling buffer. Sticky events that are still in the rolling buffer
        are NOT deduplicated — emitting them twice is harmless (the reducer
        is idempotent for these types) and dedup would cost more than it saves.
        """
        # lifecycle must be first: the frontend reducer treats lifecycle:started
        # as a hard reset for the rest of the state, so it has to be applied
        # before the cell/hello/mib events from the same capture.
        sticky_keys = ("lifecycle", "hello", "cell", "mib", "stats")
        return [self._sticky[k] for k in sticky_keys if k in self._sticky] + list(self._last_events)

    def state(self) -> dict[str, Any]:
        return dict(self._state)

    def _broadcast(self, event: dict[str, Any]) -> None:
        t = event.get("t")
        if t in ("hello", "cell", "mib", "lifecycle", "stats"):
            self._sticky[t] = event
        self._last_events.append(event)

        # Pre-encode the JSON once instead of per-subscriber. At 1000 sf/s with
        # rb_dl/rb_ul/pwr_dl arrays of ~100 floats, json.dumps was the
        # dominant CPU cost in the WS hot path (one encode per client per
        # event). Now each subscriber gets the same shared str.
        encoded = json.dumps(event)
        item = (event, encoded)

        # Drop-oldest semantics: when a slow consumer's queue is full, evict
        # the oldest event instead of dropping the new one (and instead of
        # killing the subscription, which leaves the WS task awaiting a dead
        # queue forever).
        for q in list(self._subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(item)
                except asyncio.QueueFull:
                    pass
                self._dropped_for_slow_consumer += 1
                if self._dropped_for_slow_consumer - self._last_drop_log >= 500:
                    self._last_drop_log = self._dropped_for_slow_consumer
                    # Don't recurse via _broadcast (could amplify under sustained drop) —
                    # append to the buffer directly so the log shows up but doesn't burn the queues.
                    drop_msg = {
                        "t": "log", "level": "warn", "source": "broadcast",
                        "msg": f"slow consumer: {self._dropped_for_slow_consumer} events dropped cumulatively",
                    }
                    self._last_events.append(drop_msg)

    # --------------------------------------------------------------- lifecycle

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self, cfg: SnifferConfig) -> None:
        if self.running:
            raise RuntimeError("sniffer already running")

        # New run — drop stale sticky state from the previous capture.
        self._sticky.clear()
        self._last_events.clear()

        self._fifo_dir = tempfile.TemporaryDirectory(prefix="ltesniffer-gui-")
        self._fifo_path = Path(self._fifo_dir.name) / "events.jsonl"
        os.mkfifo(self._fifo_path)

        try:
            binary = _resolve_and_validate_binary(cfg.binary_path)
        except (PermissionError, FileNotFoundError):
            self._cleanup_fifo()
            raise

        argv = cfg.to_argv(str(self._fifo_path))
        argv[argv.index(cfg.binary_path)] = str(binary)

        captures_dir = Path(cfg.captures_dir).expanduser()
        captures_dir.mkdir(parents=True, exist_ok=True)

        # If the user opted into the live pcap-stream FIFO, ensure it exists
        # as an actual FIFO. The C++ side opens it O_WRONLY|O_NONBLOCK, which
        # fails with ENXIO if no reader is connected — log a hint so the user
        # knows to open Wireshark *before* hitting Start.
        if cfg.pcap_stream_fifo:
            try:
                _ensure_stream_fifo(cfg.pcap_stream_fifo)
            except (PermissionError, OSError) as e:
                self._cleanup_fifo()
                raise PermissionError(f"pcap_stream_fifo rejected: {e}")

        self._state.update(
            running=True,
            pid=None,
            started_at=time.time(),
            exit_code=None,
            last_error=None,
            argv=list(argv),
        )

        # Reader task must be running before child opens FIFO for write
        # (fopen blocks until both ends are connected).
        self._reader_task = asyncio.create_task(self._read_events(self._fifo_path))

        self._proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.DEVNULL,   # we don't read it, and PIPE would fill at ~64KB and wedge LTESniffer
            stderr=asyncio.subprocess.PIPE,
            cwd=str(captures_dir),
        )
        self._state["pid"] = self._proc.pid
        self._broadcast({"t": "lifecycle", "event": "started", "pid": self._proc.pid, "argv": argv})

        self._stderr_task = asyncio.create_task(self._drain_stderr())
        self._wait_task = asyncio.create_task(self._wait_exit())

    async def stop(self, timeout: float = 5.0) -> None:
        if not self.running or self._proc is None:
            return

        # Determine whether we launched through sudo so we can kill the real
        # process (LTESniffer, running as root) before killing the sudo wrapper.
        # If we only SIGKILL sudo and leave LTESniffer running, it gets
        # re-parented to init and becomes an OOM-causing orphan.
        uses_sudo = bool(self._state.get("argv") and self._state["argv"][0] == "sudo")
        sudo_pid = self._proc.pid

        # Step 1: polite SIGINT (sudo forwards to LTESniffer automatically).
        try:
            self._proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            pass

        try:
            await asyncio.wait_for(self._proc.wait(), timeout)
            return  # clean exit — nothing else to do
        except asyncio.TimeoutError:
            pass

        # Step 2: escalate.  When running under sudo, kill LTESniffer children
        # *first* so they don't become orphans when sudo is subsequently killed.
        # We use a dedicated kill-wrapper script that is whitelisted in
        # sudoers (NOPASSWD) so the non-root backend can reach root processes.
        if uses_sudo:
            kill_script = (
                Path(__file__).resolve().parent.parent.parent
                / "scripts" / "kill-ltesniffer.sh"
            )
            try:
                kill_proc = await asyncio.create_subprocess_exec(
                    "sudo", "-n", str(kill_script),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(kill_proc.wait(), 3.0)
            except Exception:
                pass

        # Step 3: kill the sudo wrapper (or the binary itself if no sudo).
        try:
            self._proc.kill()
        except ProcessLookupError:
            pass
        await self._proc.wait()

        # Cancel background tasks in case _wait_exit hasn't fired yet.
        for task in (self._wait_task, self._reader_task, self._stderr_task):
            if task and not task.done():
                task.cancel()

    async def restart(self, cfg: SnifferConfig) -> None:
        await self.stop()
        await self.start(cfg)

    # ----------------------------------------------------------------- private

    async def _wait_exit(self) -> None:
        assert self._proc is not None
        rc = await self._proc.wait()
        self._state["running"] = False
        self._state["exit_code"] = rc
        self._broadcast({"t": "lifecycle", "event": "exited", "exit_code": rc})
        if self._reader_task:
            self._reader_task.cancel()
        if self._stderr_task:
            self._stderr_task.cancel()
        self._cleanup_fifo()

    def _cleanup_fifo(self) -> None:
        if self._fifo_dir:
            try:
                self._fifo_dir.cleanup()
            except Exception:
                pass
        self._fifo_dir = None
        self._fifo_path = None

    @staticmethod
    def _stderr_level(line: str) -> str:
        """Detect srsRAN/UHD log level from the line prefix so the GUI can
        colour INFO messages differently from real errors."""
        ul = line.upper()
        if "[ERROR]" in ul or "ERROR:" in ul:
            return "error"
        if "[WARNING]" in ul or "[WARN]" in ul or "WARNING:" in ul:
            return "warn"
        if "[INFO]" in ul or "[DEBUG]" in ul or "[TRACE]" in ul:
            return "info"
        return "info"   # default: treat unknown lines as info, not red

    async def _drain_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        try:
            async for line in self._proc.stderr:
                msg = line.decode(errors="replace").rstrip()
                if msg:
                    msg = _redact_keys(msg)
                    level = self._stderr_level(msg)
                    self._broadcast({"t": "log", "level": level, "source": "stderr", "msg": msg})
        except asyncio.CancelledError:
            pass

    async def _read_events(self, fifo: Path) -> None:
        """Open the FIFO and stream events.

        Opening for read is non-blocking; the loop tolerates the writer
        connecting later (returns empty reads until then).
        """
        loop = asyncio.get_running_loop()

        def _open_nonblocking() -> int:
            # O_RDWR never blocks on a FIFO (no need to wait for a writer),
            # so the executor thread returns immediately instead of hanging
            # forever if the sniffer crashes before opening its write end.
            # We hold the write end ourselves; reads still deliver whatever
            # the sniffer writes, and the task is cancelled cleanly on exit.
            return os.open(fifo, os.O_RDWR)

        try:
            fd = await loop.run_in_executor(None, _open_nonblocking)
        except FileNotFoundError:
            return

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await loop.connect_read_pipe(lambda: protocol, os.fdopen(fd, "rb", buffering=0))

        try:
            while True:
                line = await reader.readline()
                if not line:
                    await asyncio.sleep(0.05)
                    if not self.running:
                        break
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    self._broadcast({"t": "log", "level": "warn", "source": "parser", "msg": f"bad json line: {line[:120]!r}"})
                    continue
                self._broadcast(event)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                transport.close()
            except Exception:
                pass
