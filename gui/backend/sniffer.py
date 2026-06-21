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
import struct
import tempfile
import time
from collections import deque
from datetime import datetime
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


# libpcap magic numbers (us-resolution and ns-resolution, both byte orders).
_PCAP_MAGIC_LE = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
_PCAP_MAGIC_BE = (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")


def count_pcap_records(path: Path) -> int:
    """Count MAC records in a libpcap file by walking the record headers.

    Pure-Python, no tshark: skip the 24-byte global header, then for each
    16-byte record header read the 32-bit caplen and seek past the payload.
    This counts the *actual frames written to disk* — unlike decoded-grant
    (DCI) tallies, which overcount because grants can be found yet fail PDSCH
    (e.g. 4-port cells) and so never get written. Verified byte-exact against
    `tshark -r ... | wc -l` on real DL/UL/dual captures.

    Returns 0 on any error (file not yet created, partial header, bad magic),
    so a mid-run read of a freshly-opened pcap is harmless.
    """
    try:
        with open(path, "rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                return 0
            magic = gh[:4]
            if magic in _PCAP_MAGIC_LE:
                endian = "<"
            elif magic in _PCAP_MAGIC_BE:
                endian = ">"
            else:
                return 0
            n = 0
            while True:
                rh = f.read(16)
                if len(rh) < 16:
                    break
                # record header: ts_sec, ts_frac, caplen, origlen (all u32)
                caplen = struct.unpack(endian + "IIII", rh)[2]
                f.seek(caplen, os.SEEK_CUR)
                n += 1
            return n
    except OSError:
        return 0


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
        self._frames_task: Optional[asyncio.Task] = None  # periodic live-pcap frame count
        self._run_dir: Optional[Path] = None            # timestamped subdir for this run's pcaps
        self._log_fp = None                             # per-run sniffer.log for the history browser
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
            "run_dir": None,
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
        sticky_keys = ("lifecycle", "hello", "cell", "mib", "stats", "frames")
        return [self._sticky[k] for k in sticky_keys if k in self._sticky] + list(self._last_events)

    def state(self) -> dict[str, Any]:
        return dict(self._state)

    def _broadcast(self, event: dict[str, Any]) -> None:
        t = event.get("t")
        if t in ("hello", "cell", "mib", "lifecycle", "stats", "frames"):
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

        # Each run gets its own timestamped subdirectory so captures never
        # overwrite each other.  LTESniffer always uses hardcoded filenames
        # (ltesniffer_dl_mode.pcap, api_collector.pcap, …) relative to CWD,
        # so isolating CWD per-run is the cleanest way to separate captures.
        captures_dir = Path(cfg.captures_dir).expanduser()
        run_tag = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        run_dir = captures_dir / run_tag
        run_dir.mkdir(parents=True, exist_ok=True)
        self._run_dir = run_dir

        # Persist this run's sniffer output to run_dir/sniffer.log so the GUI's
        # log-history browser can show it later. Best-effort — never let logging
        # break the capture.
        try:
            self._log_fp = open(run_dir / "sniffer.log", "w", buffering=1)
            self._log_fp.write(f"# LTESniffer run {run_tag}\n# argv: {' '.join(argv)}\n")
        except OSError:
            self._log_fp = None

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
            run_dir=str(run_dir),
        )

        # Reader task must be running before child opens FIFO for write
        # (fopen blocks until both ends are connected).
        self._reader_task = asyncio.create_task(self._read_events(self._fifo_path))

        # Pass the live-stream FIFO path via the environment (preserved across
        # sudo by a scoped `env_keep` rule) instead of a `sudo env …` prefix.
        child_env = dict(os.environ)
        if cfg.pcap_stream_fifo:
            child_env["LTESNIFFER_PCAP_STREAM"] = cfg.pcap_stream_fifo
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.DEVNULL,   # we don't read it, and PIPE would fill at ~64KB and wedge LTESniffer
                stderr=asyncio.subprocess.PIPE,
                cwd=str(run_dir),
                env=child_env,
                start_new_session=True,   # own process group, so teardown can target the tree
            )
        except Exception as e:
            # Spawn failed (bad binary, sudo -n denied, ENOMEM…). Without this
            # the GUI would stay stuck showing "running" forever — running=True
            # was set above but _proc is None — and Start would be disabled with
            # no way to recover but a backend restart. Roll the state back.
            if self._reader_task:
                self._reader_task.cancel()
                self._reader_task = None
            self._cleanup_fifo()
            self._close_log()
            self._state.update(running=False, pid=None, last_error=str(e))
            raise
        self._state["pid"] = self._proc.pid
        self._broadcast({
            "t": "lifecycle",
            "event": "started",
            "pid": self._proc.pid,
            "argv": argv,
            "run_dir": str(run_dir),
        })

        self._stderr_task = asyncio.create_task(self._drain_stderr())
        self._wait_task = asyncio.create_task(self._wait_exit())
        self._frames_task = asyncio.create_task(self._poll_frames(run_dir))

    async def stop(self, graceful_timeout: float = 15.0) -> None:
        """Stop the running sniffer.

        Strategy: signal LTESniffer DIRECTLY (not via sudo). `sudo -n` running
        without a controlling tty does not reliably forward SIGINT/SIGTERM to
        its child — sudo exits, the child gets reparented to init, and the
        polite signal is lost. We use the sudoers-whitelisted kill-wrapper to
        send SIGTERM to the LTESniffer process(es) directly.

        Phases:
          1. SIGTERM via kill-wrapper. LTESniffer's SignalGate handler (commits
             2e1619a + 07aea53) catches SIGTERM, sets go_exit=true, the main
             loop exits, the destructor runs, and pcapwriter.close() flushes
             the libc stdio buffer to disk. graceful_timeout (15s) is generous
             enough to cover the dual-mode shutdown sequence (joinPending +
             srsran_rf_close + ue_sync_free).
          2. SIGKILL via kill-wrapper, only if still alive. This is the data-
             loss path — anything still in the 8 KB stdio buffer past the last
             periodic flush (commit 3eaf404) is dropped.
          3. Reap the sudo wrapper if it's somehow still around (rare — sudo
             usually exits when its child does).
        """
        if not self.running or self._proc is None:
            return

        uses_sudo = bool(self._state.get("argv") and self._state["argv"][0] == "sudo")
        kill_script = (
            Path(__file__).resolve().parent.parent.parent
            / "scripts" / "kill-ltesniffer.sh"
        )

        async def _signal_all(sig_name: str, wrapper_timeout: float = 3.0) -> None:
            """Send `sig_name` to every LTESniffer process via the kill wrapper.
            If we're not running under sudo, signal our direct child instead."""
            if uses_sudo:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "sudo", "-n", str(kill_script), sig_name,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await asyncio.wait_for(proc.wait(), wrapper_timeout)
                except Exception:
                    pass
            else:
                # No sudo → our direct child IS LTESniffer.
                sig = getattr(signal, f"SIG{sig_name}", signal.SIGTERM)
                try:
                    self._proc.send_signal(sig)
                except ProcessLookupError:
                    pass

        # Phase 1: polite SIGTERM to LTESniffer directly.
        await _signal_all("TERM")

        try:
            await asyncio.wait_for(self._proc.wait(), graceful_timeout)
            # clean exit — sudo wrapper exits when its child does.
            return
        except asyncio.TimeoutError:
            pass

        # Phase 2: escalate to SIGKILL. Data loss territory — anything still
        # in the libc stdio buffer past the last periodic flush is gone.
        await _signal_all("KILL")

        # Phase 3: reap the sudo wrapper if it's hanging around.
        try:
            self._proc.kill()
        except ProcessLookupError:
            pass
        # Bound the final reap so a wedged wrapper can't hang /api/capture/stop
        # indefinitely on an unattended box.
        try:
            await asyncio.wait_for(self._proc.wait(), 5.0)
        except asyncio.TimeoutError:
            pass

        # Cancel background tasks in case _wait_exit hasn't fired yet.
        for task in (self._wait_task, self._reader_task, self._stderr_task, self._frames_task):
            if task and not task.done():
                task.cancel()

    async def restart(self, cfg: SnifferConfig) -> None:
        await self.stop()
        await self.start(cfg)

    # ----------------------------------------------------------------- private

    async def _wait_exit(self) -> None:
        if self._proc is None:
            return
        try:
            rc = await self._proc.wait()
            self._state["running"] = False
            self._state["exit_code"] = rc
            self._broadcast({
                "t": "lifecycle",
                "event": "exited",
                "exit_code": rc,
                "run_dir": str(self._run_dir) if self._run_dir else None,
            })
            if self._reader_task:
                self._reader_task.cancel()
            if self._stderr_task:
                self._stderr_task.cancel()
            if self._frames_task:
                # One last count so the final tally reflects everything flushed
                # at shutdown, then stop the poller. Offloaded to a thread (await)
                # so a large pcap can't block the loop / stall lifecycle:exited.
                await self._emit_frame_count()
                self._frames_task.cancel()
            self._prune_empty_outputs()
            self._maybe_autosplit()
        finally:
            # Always release the FIFO/temp dir even if broadcast/cancel raised,
            # so an exit can never leak the pipe or strand the UI's state.
            self._cleanup_fifo()
            self._close_log()

    # Hardcoded by the C++ core (relative to per-run CWD). The dual-mode pcap is
    # the canonical run record; in DL-only / UL-only modes the matching name is
    # written instead — we count whichever exists and is largest.
    _LIVE_PCAP_NAMES = (
        "ltesniffer_dual_mode.pcap",
        "ltesniffer_dl_mode.pcap",
        "ltesniffer_ul_mode.pcap",
    )
    _FRAMES_POLL_S = 2.0

    def _live_pcap(self, run_dir: Path) -> Optional[Path]:
        """Pick the run's live MAC pcap (largest of the known mode files)."""
        best: Optional[Path] = None
        best_sz = -1
        for name in self._LIVE_PCAP_NAMES:
            p = run_dir / name
            try:
                sz = p.stat().st_size
            except OSError:
                continue
            if sz > best_sz:
                best, best_sz = p, sz
        return best

    async def _emit_frame_count(self) -> None:
        """Count the live pcap once and broadcast a `frames` event.

        Used at shutdown for the final tally; the count walk is offloaded to a
        thread (like the periodic poller) so the event loop never blocks."""
        run_dir = self._run_dir
        if run_dir is None:
            return
        p = self._live_pcap(run_dir)
        if p is None:
            return
        count = await asyncio.get_running_loop().run_in_executor(None, count_pcap_records, p)
        self._broadcast({"t": "frames", "ts": time.time(), "count": count})

    async def _poll_frames(self, run_dir: Path) -> None:
        """Every ~2 s, count MAC records in the live pcap and broadcast it.

        Counting walks the file's record headers in a worker thread (cheap, but
        still disk I/O), so the event loop is never blocked. Emits `frames`
        events the frontend renders as a live "frames" tile."""
        loop = asyncio.get_running_loop()
        try:
            while True:
                p = self._live_pcap(run_dir)
                if p is not None:
                    count = await loop.run_in_executor(None, count_pcap_records, p)
                    self._broadcast({"t": "frames", "ts": time.time(), "count": count})
                await asyncio.sleep(self._FRAMES_POLL_S)
        except asyncio.CancelledError:
            pass

    _EMPTY_PCAP_HDR = 24  # a libpcap global header with zero packets

    def _prune_empty_outputs(self) -> None:
        """Delete output files LTESniffer always opens but only fills in specific
        modes: api_collector.pcap (-z API/IMSI mode), iq_sample_dl.bin /
        ul_sample.raw (IQ-dump mode), *_decrypted_ip.pcap (-K decrypt with a DRB
        hit). When a run doesn't use that mode they stay empty (0 bytes, or a
        24-byte pcap header), so the run folder keeps only real output. Strictly
        conditional on emptiness — anything with real content is left untouched.
        The main *_dual_mode.pcap is never touched (it's the run record)."""
        run_dir = self._run_dir
        if run_dir is None:
            return
        try:
            for name in ("iq_sample_dl.bin", "ul_sample.raw"):
                f = run_dir / name
                if f.is_file() and f.stat().st_size == 0:
                    f.unlink()
            for f in run_dir.glob("*.pcap"):
                if (f.name == "api_collector.pcap" or f.name.endswith("_decrypted_ip.pcap")) \
                        and f.is_file() and f.stat().st_size <= self._EMPTY_PCAP_HDR:
                    f.unlink()
        except OSError:
            pass

    def _maybe_autosplit(self) -> None:
        """If configured, split the just-finished capture in the background."""
        run_dir = self._run_dir
        if run_dir is None:
            return
        try:
            import config as config_mod
            cfg = config_mod.load()
        except Exception:
            return
        if not getattr(cfg, "auto_split_enabled", False) or not getattr(cfg, "auto_split_dims", None):
            return
        dims = list(cfg.auto_split_dims)

        def _job() -> None:
            try:
                import captures as captures_mod
                pcaps = sorted(
                    (p for p in run_dir.glob("ltesniffer_*mode.pcap") if p.is_file()),
                    key=lambda p: p.stat().st_size, reverse=True,
                )
                if pcaps and pcaps[0].stat().st_size > 24:
                    captures_mod.split_capture(cfg, str(pcaps[0]), dims)
            except Exception:
                pass

        try:
            asyncio.create_task(asyncio.to_thread(_job))
        except RuntimeError:
            pass  # no running loop (shouldn't happen here)

    def _close_log(self) -> None:
        if self._log_fp is not None:
            try:
                self._log_fp.close()
            except OSError:
                pass
            self._log_fp = None

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
                    if self._log_fp is not None:
                        try:
                            self._log_fp.write(msg + "\n")
                        except OSError:
                            pass
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
                # A valid-JSON non-object (bare int/str) would crash every
                # consumer's event.get(...) downstream — drop it.
                if not isinstance(event, dict):
                    continue
                self._broadcast(event)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                transport.close()
            except Exception:
                pass
