"""USRP enumeration via the UHD `uhd_find_devices` CLI."""

from __future__ import annotations

import asyncio
import re
from typing import Any


async def find_devices(timeout: float = 5.0) -> list[dict[str, Any]]:
    """Run uhd_find_devices and parse the human-readable output.

    Returns one dict per device, e.g.
    [{"type":"b200","serial":"32FCD4C","name":"MyB210","product":"B210"}].

    Returns [] on any error (uhd not installed, no devices, timeout). The GUI
    treats an empty list as "couldn't enumerate" and lets the user type a
    serial manually.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "uhd_find_devices",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return []
    except FileNotFoundError:
        return []

    text = stdout.decode(errors="replace")
    devices: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        if "Device Address:" in line:
            if current:
                devices.append(current)
            current = {}
            continue
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", line)
        if m and current is not None:
            current[m.group(1)] = m.group(2).strip()
    if current:
        devices.append(current)
    return devices
