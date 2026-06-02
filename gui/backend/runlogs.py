"""Per-run sniffer log history for the GUI.

Each capture run writes its output to <captures_dir>/<YYYY-MM-DD_HH-MM-SS>/sniffer.log
(see sniffer.py). The run-dir name IS the start date/time, so listings sort
chronologically for free.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from config import SnifferConfig

LOG_NAME = "sniffer.log"
MAX_READ_BYTES = 2_000_000  # tail this many bytes for huge logs


def _runs_base(cfg: SnifferConfig) -> Path:
    return Path(cfg.captures_dir).expanduser().resolve()


def _parse_run_time(run_tag: str) -> str | None:
    try:
        return datetime.strptime(run_tag, "%Y-%m-%d_%H-%M-%S").isoformat()
    except ValueError:
        return None


def list_run_logs(cfg: SnifferConfig) -> list[dict]:
    """Descriptors for every run log under captures_dir, newest first."""
    base = _runs_base(cfg)
    out: list[dict] = []
    if base.is_dir():
        try:
            entries = list(base.iterdir())
        except OSError:
            entries = []
        for d in entries:
            log = d / LOG_NAME
            if not log.is_file():
                continue
            try:
                st = log.stat()
            except OSError:
                continue
            out.append({
                "run": d.name,                       # the timestamped run tag
                "started": _parse_run_time(d.name),  # ISO, or None if non-standard name
                "path": str(log.resolve()),
                "size": st.st_size,
                "mtime": st.st_mtime,
            })
    out.sort(key=lambda r: r["mtime"], reverse=True)
    return out


def read_run_log(cfg: SnifferConfig, path: str) -> str:
    """Return a run log's text. Restricted to sniffer.log files under captures_dir."""
    p = Path(path).expanduser().resolve()
    base = _runs_base(cfg)
    if p.name != LOG_NAME:
        raise PermissionError("only sniffer.log files can be read")
    try:
        p.relative_to(base)
    except ValueError:
        raise PermissionError(f"{p} is outside the captures directory")
    if not p.is_file():
        raise FileNotFoundError(path)
    data = p.read_bytes()
    if len(data) > MAX_READ_BYTES:
        data = b"... (truncated; showing last 2 MB) ...\n" + data[-MAX_READ_BYTES:]
    return data.decode(errors="replace")
