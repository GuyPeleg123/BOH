"""Optional spectrum-analyzer GUI launcher.

Detects common UHD/SDR spectrum tools and spawns one on the backend's
desktop session, prefilled with the sniffer's current DL frequency.

These tools open native windows on the X / Wayland display the backend
process is running under, so this is most useful when the backend runs
on the user's local machine (the typical sniffer setup).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from typing import Optional


# Ordered by preference: (command, label, argv_builder(freq, sr, args, extras) -> list[str])
#
# These are all *receiver* tools — they open a USRP, draw a live FFT of the
# RF spectrum, and stay running until closed. Do NOT add `uhd_siggen_gui`
# here: it's a *transmitter* (signal generator), not a spectrum analyzer,
# and clicking it would start beaming a signal instead of viewing one.
#
# `extras` is a dict of optional per-launch tuning knobs the GUI exposes:
#   gain_db:     float (RX gain in dB; None = tool default midpoint)
#   antenna:     str   (e.g. "RX2"; None = tool default)
#   fft_size:    int   (FFT bin count, e.g. 1024/2048/4096)
#   fft_average: str   ("off" | "low" | "medium" | "high")
#   update_rate: float (FFT redraw rate in Hz)
def _uhd_fft_argv(f, sr, args, extras):
    ex = extras or {}
    out: list[str] = []
    if args:                                    out += ["-a", args]
    out += ["-f", str(int(f))]
    if sr:                                      out += ["-s", str(int(sr))]
    if ex.get("gain_db") is not None:           out += ["-g", str(float(ex["gain_db"]))]
    if ex.get("antenna"):                       out += ["-A", str(ex["antenna"])]
    if ex.get("fft_size"):                      out += ["--fft-size", str(int(ex["fft_size"]))]
    if ex.get("fft_average") in ("off", "low", "medium", "high"):
        out += ["--fft-average", ex["fft_average"]]
    if ex.get("update_rate"):                   out += ["--update-rate", str(float(ex["update_rate"]))]
    return out


TOOLS: list[tuple[str, str, callable]] = [
    ("uhd_fft",  "uhd_fft (UHD spectrum)", _uhd_fft_argv),
    ("usrp_fft", "usrp_fft (legacy)",      _uhd_fft_argv),    # same CLI surface
    ("gqrx",     "gqrx",                   lambda *_a: []),    # gqrx uses a config file
]

# How long after launch we keep watching for an early exit before reporting
# a "started" state to the UI.
EARLY_EXIT_WINDOW_S = 2.5
STDERR_TAIL_BYTES = 4096
STDERR_CAP_BYTES = 65536   # max total stderr buffered per launch (~64 KB)


class SpectrumLauncher:
    def __init__(self) -> None:
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._tool: Optional[str] = None
        self._argv: list[str] = []
        self._started_at: Optional[float] = None
        self._last_error: Optional[str] = None
        self._last_exit_code: Optional[int] = None
        self._stderr_chunks: list[bytes] = []
        self._stderr_total_bytes: int = 0       # tracks total buffered to enforce cap
        self._stderr_task: Optional[asyncio.Task] = None
        self._watch_task: Optional[asyncio.Task] = None

    def available(self) -> list[dict[str, str]]:
        return [
            {"cmd": cmd, "label": label}
            for cmd, label, _ in TOOLS
            if shutil.which(cmd) is not None
        ]

    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    def status(self) -> dict:
        return {
            "available": self.available(),
            "running": self.running(),
            "tool": self._tool if self.running() else None,
            "pid": self._proc.pid if self.running() and self._proc else None,
            "argv": self._argv if self.running() else [],
            "display_required": True,
            "display_env": os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or None,
            "last_error": self._last_error,
            "last_exit_code": self._last_exit_code,
            "last_tool": self._tool,
            "preflight": self.preflight(),
        }

    def preflight(self) -> dict:
        """Best-effort upfront checks so the GUI can tell the operator what
        will fail before they click launch.

        Each check returns: {ok: bool, detail: str, fix: str|None}.
        """
        # Display
        disp = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        display_check = {
            "ok": bool(disp),
            "detail": f"DISPLAY={disp}" if disp else "no $DISPLAY / $WAYLAND_DISPLAY in backend env",
            "fix": "Start the backend from a graphical login (or `ssh -X`)." if not disp else None,
        }

        # UHD firmware images
        images_dirs = [
            "/usr/share/uhd/images",
            "/usr/local/share/uhd/images",
            os.path.expanduser("~/.uhd/images"),
        ]
        images_present = None
        for d in images_dirs:
            try:
                if os.path.isdir(d) and any(name.endswith(".hex") or name.endswith(".bit")
                                            for name in os.listdir(d)):
                    images_present = d
                    break
            except OSError:
                continue
        images_check = {
            "ok": images_present is not None,
            "detail": f"images dir: {images_present}" if images_present else "no UHD firmware images found",
            "fix": (
                "Run once:  sudo /lib/x86_64-linux-gnu/uhd/utils/uhd_images_downloader.py"
                if not images_present else None
            ),
        }

        # Tool available
        tool_check = {
            "ok": len(self.available()) > 0,
            "detail": ("available: " + ", ".join(t["cmd"] for t in self.available()))
                      if self.available() else "no uhd_fft / gqrx on PATH",
            "fix": "sudo apt install gnuradio-uhd  # for uhd_fft" if not self.available() else None,
        }

        return {
            "display": display_check,
            "uhd_images": images_check,
            "tool": tool_check,
            "all_ok": all(c["ok"] for c in (display_check, images_check, tool_check)),
        }

    async def launch(self, freq_hz: float, sample_rate_hz: float,
                     tool: Optional[str] = None, device_args: Optional[str] = None,
                     extras: Optional[dict] = None) -> dict:
        if self.running():
            raise RuntimeError("spectrum already running; stop it first")

        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            raise RuntimeError(
                "no $DISPLAY or $WAYLAND_DISPLAY set on the backend host; "
                "spectrum analyzer windows need a desktop session. "
                "Either run the backend from a graphical login, or ssh -X."
            )

        avail = self.available()
        if not avail:
            raise FileNotFoundError(
                "No spectrum analyzer found on PATH. Install one of: "
                + ", ".join(t[0] for t in TOOLS)
            )
        chosen_cmd = tool or avail[0]["cmd"]
        builder = next((b for c, _, b in TOOLS if c == chosen_cmd), None)
        if builder is None or shutil.which(chosen_cmd) is None:
            raise FileNotFoundError(f"Tool '{chosen_cmd}' not found")

        argv = [chosen_cmd, *builder(freq_hz, sample_rate_hz, device_args or "", extras or {})]

        # Reset per-launch state
        self._last_error = None
        self._last_exit_code = None
        self._stderr_chunks = []
        self._stderr_total_bytes = 0
        self._argv = argv
        self._tool = chosen_cmd

        self._proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self._started_at = time.monotonic()

        # Drain stderr so the pipe doesn't fill up and so we can surface
        # errors after an early crash.
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        # Watch for an early exit (within EARLY_EXIT_WINDOW_S) to flip last_error.
        # Stored so it can be cancelled when stop() is called.
        self._watch_task = asyncio.create_task(self._watch_exit())

        # Block briefly so the synchronous launch result reflects an early crash.
        try:
            rc = await asyncio.wait_for(self._proc.wait(), EARLY_EXIT_WINDOW_S)
            # Process died fast — surface the error to the caller.
            err = self._stderr_tail() or f"exited rc={rc} with no stderr"
            self._last_error = err
            self._last_exit_code = rc
            raise RuntimeError(f"spectrum tool exited (rc={rc}): {err}")
        except asyncio.TimeoutError:
            # Still alive after the watch window → consider launch successful.
            return {
                "ok": True,
                "tool": chosen_cmd,
                "pid": self._proc.pid,
                "argv": argv,
            }

    async def stop(self) -> dict:
        # Cancel background tasks regardless of whether the process is still up.
        for task in (self._watch_task, self._stderr_task):
            if task and not task.done():
                task.cancel()

        if not self.running() or self._proc is None:
            return {"ok": True, "running": False}
        try:
            self._proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(self._proc.wait(), 3.0)
        except asyncio.TimeoutError:
            try:
                self._proc.kill()
            except ProcessLookupError:
                pass
            await self._proc.wait()
        return {"ok": True, "running": False}

    # ------------------------------------------------------------------- internal

    def _stderr_tail(self) -> str:
        blob = b"".join(self._stderr_chunks)
        if len(blob) > STDERR_TAIL_BYTES:
            blob = blob[-STDERR_TAIL_BYTES:]
        text = blob.decode(errors="replace").strip()
        # Trim noisy multi-line tracebacks for the UI — keep last few lines.
        lines = [l for l in text.splitlines() if l.strip()]
        if len(lines) > 12:
            lines = ["…(truncated)…", *lines[-11:]]
        return "\n".join(lines)

    async def _drain_stderr(self) -> None:
        if not self._proc or not self._proc.stderr:
            return
        try:
            while True:
                chunk = await self._proc.stderr.read(1024)
                if not chunk:
                    break
                self._stderr_chunks.append(chunk)
                self._stderr_total_bytes += len(chunk)
                # Evict oldest chunks once we exceed the cap so this list
                # never grows without bound during a long-running capture.
                while self._stderr_total_bytes > STDERR_CAP_BYTES and self._stderr_chunks:
                    dropped = self._stderr_chunks.pop(0)
                    self._stderr_total_bytes -= len(dropped)
        except asyncio.CancelledError:
            pass

    async def _watch_exit(self) -> None:
        if not self._proc:
            return
        rc = await self._proc.wait()
        # If the early-exit window already handled this, leave fields alone.
        if self._last_exit_code is None:
            self._last_exit_code = rc
            if rc != 0:
                self._last_error = self._stderr_tail() or f"exited rc={rc} with no stderr"
