"""Persisted registry of LTE cells that have successfully decoded.

Stored at ~/.config/ltesniffer-gui/known_cells.json. Each entry remembers
the freq pair, USRP wiring, observed PCI, bandwidth, and a free-form note
(e.g. operator name) so the operator can re-tune to a known-good cell
later without re-running spectrum scans.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


_DIR = (Path.home() / ".config" / "ltesniffer-gui").resolve()
KNOWN_CELLS_PATH = _DIR / "known_cells.json"


class KnownCell(BaseModel):
    label: str = Field(..., description="Operator name / location / anything human-readable")
    dl_freq_mhz: float = Field(..., gt=0, lt=10000)
    ul_freq_mhz: float = Field(0.0, ge=0, lt=10000, description="0 = DL-only")
    bandwidth_mhz: Optional[float] = Field(None, description="LTE channel BW (5/10/15/20)")
    nof_prb: int = Field(50, ge=6, le=110)
    pci: Optional[int] = Field(None, description="Last observed Physical Cell ID")
    sniffer_mode: int = Field(2, ge=0, le=2, description="0=DL 1=UL 2=Dual")
    usrp_a_args: str = Field("clock=gpsdo,serial=32FCD4C", description="USRP A (DL) rfargs")
    usrp_b_args: str = Field("clock=gpsdo,serial=3367EF9", description="USRP B (UL) rfargs")
    rf_gain: float = Field(-1.0, description="RX gain dB; -1 = AGC")
    last_success_iso: str = Field("", description="ISO 8601 timestamp of last successful capture")
    notes: str = Field("", description="Free-form")


class KnownCellsFile(BaseModel):
    cells: list[KnownCell] = Field(default_factory=list)


def _validate_path(p: Path) -> Path:
    p = Path(p).expanduser()
    resolved = (p.parent.resolve() / p.name)
    try:
        resolved.relative_to(_DIR)
    except ValueError:
        raise PermissionError(f"known_cells path '{p}' outside {_DIR}")
    if resolved.is_symlink():
        raise PermissionError(f"known_cells path is a symlink; refused")
    return resolved


def load(path: Path = KNOWN_CELLS_PATH) -> KnownCellsFile:
    if not path.exists():
        return KnownCellsFile()
    try:
        return KnownCellsFile.model_validate_json(path.read_text())
    except Exception:
        return KnownCellsFile()


def save(payload: KnownCellsFile, path: Path = KNOWN_CELLS_PATH) -> Path:
    path = _validate_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(payload.model_dump_json(indent=2) + "\n")
    finally:
        try: os.chmod(path, 0o600)
        except OSError: pass
    return path
