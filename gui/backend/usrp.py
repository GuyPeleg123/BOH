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


async def probe_gpsdo(serial: str, timeout: float = 8.0) -> bool:
    """Return True if the device reports 'gpsdo' in its Clock sources line.

    Uses uhd_usrp_probe which takes 3-8 seconds per device; run concurrently
    for multiple devices via probe_all_gpsdo().
    """
    if not shutil.which("uhd_usrp_probe") or not serial:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "uhd_usrp_probe", "--args", f"serial={serial}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False
    except FileNotFoundError:
        return False

    for line in stdout.decode(errors="replace").splitlines():
        if "Clock sources:" in line and "gpsdo" in line.lower():
            return True
    return False


async def probe_all_gpsdo(
    devices: list[dict[str, Any]], timeout: float = 8.0
) -> list[dict[str, Any]]:
    """Probe GPSDO presence on all devices concurrently.

    Returns a copy of each device dict with an added 'gpsdo' bool field.
    """
    results = await asyncio.gather(
        *(probe_gpsdo(d.get("serial", ""), timeout) for d in devices),
        return_exceptions=True,
    )
    return [
        {**d, "gpsdo": bool(r) if not isinstance(r, Exception) else False}
        for d, r in zip(devices, results)
    ]


def suggest_rf_args(device: dict[str, Any]) -> str:
    """Build a sensible rf_args string for a single device.

    NOTE: do NOT add num_recv_frames / recv_frame_size here — LTESniffer_Core
    already appends those to whatever rf_args the user passes, so including
    them here would cause duplication and confuse UHD's device-address parser.

    We explicitly set type=b200 for B200/B210 family devices.  Without it,
    srsRAN will fall back to the 'soapy' backend (which opens the PC's audio
    card) whenever UHD takes a moment to re-enumerate after a USB reset,
    producing completely wrong samples.
    """
    parts: list[str] = []
    dev_type = device.get("type", "")
    if dev_type in ("b200", "b210", "b200mini", "b205mini"):
        parts.append("type=b200")
    if device.get("serial"):
        parts.append(f"serial={device['serial']}")
    return ",".join(parts) if parts else ""


def suggest_dual_args(device: dict[str, Any]) -> str:
    """Build rfargs for a device used in dual-USRP (UL/DUAL) mode.

    Does NOT include clock=gpsdo — that is added conditionally by the frontend
    after probing GPSDO presence via probe_all_gpsdo() / uhd_usrp_probe.
    """
    parts: list[str] = []
    dev_type = device.get("type", "")
    if dev_type in ("b200", "b210", "b200mini", "b205mini"):
        parts.append("type=b200")
    if device.get("serial"):
        parts.append(f"serial={device['serial']}")
    return ",".join(parts) if parts else ""


async def auto_config_patch(timeout: float = 5.0) -> dict[str, Any]:
    """Detect USRPs and return a partial SnifferConfig patch dict.

    Rules:
    • 0 USRPs detected  → empty patch (user must configure manually)
    • 1 USRP detected   → rf_args=serial=<X>, clear dual fields, mode=0 (DL)
    • 2+ USRPs detected → usrp_a_args + usrp_b_args, clear rf_args, mode=2 (DUAL)

    clock=gpsdo is NOT included here — call probe_all_gpsdo() separately so
    this endpoint stays fast (<1s).  The caller (frontend) applies GPSDO
    results once the background probe completes.
    """
    devices = await find_devices(timeout)
    patch: dict[str, Any] = {"_detected_devices": devices}

    if not devices:
        patch["_message"] = "No USRPs detected — check USB connection and UHD install."
        return patch

    if len(devices) == 1:
        patch["rf_args"] = suggest_rf_args(devices[0])
        patch["usrp_a_args"] = ""
        patch["usrp_b_args"] = ""
        patch["sniffer_mode"] = 0
        patch["_message"] = (
            f"1 USRP detected ({devices[0].get('product', 'USRP')} "
            f"serial={devices[0].get('serial', '?')}). "
            "Configured for DL-only mode."
        )
    else:
        patch["rf_args"] = ""
        patch["usrp_a_args"] = suggest_dual_args(devices[0])
        patch["usrp_b_args"] = suggest_dual_args(devices[1])
        patch["sniffer_mode"] = 2
        patch["_message"] = (
            f"{len(devices)} USRPs detected. "
            f"A={devices[0].get('serial', '?')} (DL), "
            f"B={devices[1].get('serial', '?')} (UL). "
            "Configured for dual mode. Probing GPSDO in background…"
        )

    return patch
