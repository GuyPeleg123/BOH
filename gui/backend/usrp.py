"""USRP enumeration via the UHD `uhd_find_devices` CLI."""

from __future__ import annotations

import asyncio
import re
import shutil
from typing import Any


async def find_devices(timeout: float = 5.0) -> list[dict[str, Any]]:
    """Run uhd_find_devices and parse the human-readable output.

    Returns one dict per device, e.g.
    [{"type":"b200","serial":"32FCD4C","name":"MyB210","product":"B210"}].

    Returns [] on any error (uhd not installed, no devices, timeout).
    """
    if not shutil.which("uhd_find_devices"):
        return []
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
            await proc.wait()
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


def suggest_rf_args(device: dict[str, Any]) -> str:
    """Build a sensible rf_args string for a single device.

    NOTE: do NOT add num_recv_frames / recv_frame_size here — LTESniffer_Core
    already appends those to whatever rf_args the user passes, so including
    them here would cause duplication and confuse UHD's device-address parser.

    For B200/B210 family the internal clock is fine for DL-only mode.
    The serial is included so that if a second USRP is later connected the
    correct one is still selected.
    """
    if device.get("serial"):
        return f"serial={device['serial']}"
    return ""


def suggest_dual_args(device: dict[str, Any], require_gpsdo: bool = True) -> str:
    """Build rfargs for a device used in dual-USRP (UL/DUAL) mode.

    Dual mode requires hardware time synchronisation — GPSDO is the standard
    way to achieve this on a B210 pair.

    NOTE: do NOT add num_recv_frames / recv_frame_size — see suggest_rf_args.
    """
    parts = []
    if require_gpsdo:
        parts.append("clock=gpsdo")
    if device.get("serial"):
        parts.append(f"serial={device['serial']}")
    return ",".join(parts)


async def auto_config_patch(timeout: float = 5.0) -> dict[str, Any]:
    """Detect USRPs and return a partial SnifferConfig patch dict.

    Rules:
    • 0 USRPs detected  → empty patch (user must configure manually)
    • 1 USRP detected   → set rf_args to serial=<serial>,...  (DL-only)
    • 2+ USRPs detected → set usrp_a_args (first) and usrp_b_args (second)
                          with clock=gpsdo for dual-mode use

    The caller can merge this patch into the current config.
    """
    devices = await find_devices(timeout)
    patch: dict[str, Any] = {"_detected_devices": devices}

    if not devices:
        patch["_message"] = "No USRPs detected — check USB connection and UHD install."
        return patch

    if len(devices) == 1:
        patch["rf_args"] = suggest_rf_args(devices[0])
        patch["_message"] = (
            f"1 USRP detected ({devices[0].get('product','USRP')} "
            f"serial={devices[0].get('serial','?')}). "
            "DL-only mode is supported. UL/DUAL requires a second USRP."
        )
    else:
        # Two or more: assign first to A (DL), second to B (UL)
        patch["rf_args"] = ""          # clear single-USRP field
        patch["usrp_a_args"] = suggest_dual_args(devices[0])
        patch["usrp_b_args"] = suggest_dual_args(devices[1])
        patch["_message"] = (
            f"{len(devices)} USRPs detected. "
            f"A={devices[0].get('serial','?')} (DL), "
            f"B={devices[1].get('serial','?')} (UL). "
            "usrp_a_args / usrp_b_args have been pre-filled with clock=gpsdo."
        )

    return patch
