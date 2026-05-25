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


# Ordered by preference: (command, label, argv_builder(freq_hz, sample_rate_hz, device_args) -> list[str])
TOOLS: list[tuple[str, str, callable]] = [
    ("uhd_fft",         "uhd_fft (UHD spectrum)",
     lambda f, sr, args: (["-a", args] if args else []) + ["-f", str(int(f))] + (["-s", str(int(sr))] if sr else [])),
    ("usrp_fft",        "usrp_fft (legacy)",
     lambda f, sr, args: (["-a", args] if args else []) + ["-f", str(int(f))] + (["-s", str(int(sr))] if sr else [])),
    ("uhd_siggen_gui",  "uhd_siggen_gui",
     lambda f, _sr, args: (["-a", args] if args else []) + ["-f", str(int(f))]),
    ("gqrx",            "gqrx",
     lambda _f, _sr, _args: []),  # gqrx config file controls freq + device
]

# How long after launch we keep watching for an early exit before reporting
# a "started" state to the UI.
EARLY_EXIT_WINDOW_S = 2.5
STDERR_TAIL_BYTES = 4096


class SpectrumLauncher:
    def __init__(self) -> None:
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._tool: Optional[str] = None
        self._argv: list[str] = []
        self._started_at: Optional[float] = None
        self._last_error: Optional[str] = None
        self._last_exit_code: Optional[int] = None
        self._stderr_chunks: list[bytes] = []
        self._stderr_task: Optional[asyncio.Task] = None

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
        }

    async def launch(self, freq_hz: float, sample_rate_hz: float,
                     tool: Optional[str] = None, device_args: Optional[str] = None) -> dict:
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

        argv = [chosen_cmd, *builder(freq_hz, sample_rate_hz, device_args or "")]

        # Reset per-launch state
        self._last_error = None
        self._last_exit_code = None
        self._stderr_chunks = []
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
        asyncio.create_task(self._watch_exit())

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
