"""LTE cell scan — find the cells on the current DL frequency so the operator can
PIN a specific one instead of letting cell-search grab whichever it likes.

Runs a short cell-search capture, parses the detected PCIs (with signal metrics),
and enriches the locked cell with its PRB + Cell Identity / TAC / PLMN read from
SIB1. Post-capture friendly: no C++ change, uses the same binary + config.

Reality (see CLAUDE.md): the radio locks by PCI (physical layer). Cell ID / TAC
come from SIB1, so they are only known for a cell we actually lock and decode —
the scan reports them for the locked cell; every other PCI comes with its signal
so you can still pin it by PCI.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from config import SnifferConfig
import captures as C

# Set by cancel_pin() to abort an in-flight pin_cell() mid-run.
_PIN_CANCEL = threading.Event()


def cancel_pin() -> dict:
    """Abort a running pin: flag the loop and SIGINT the pinned capture so it
    stops promptly. Safe — pin_cell requires the radios free, so the only
    LTESniffer running during a pin is the pin itself."""
    _PIN_CANCEL.set()
    n = 0
    for pid in _root_child_pids("build/src/LTESniffer"):
        subprocess.run(["sudo", "-n", "kill", "-INT", str(pid)])
        n += 1
    return {"ok": True, "signalled": n}

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_FOUND_RE = re.compile(
    r"(\*?)\s*Found Cell_id:\s*(\d+)\s+(FDD|TDD),\s*CP:\s*(\w+)\s*,\s*"
    r"DetectRatio=\s*(\d+)%\s*PSR=([\d.]+),\s*Power=\s*(-?[\d.]+|-inf)\s*dBm"
)
# The confirmed lock: cell-search only prints "- PCI:"/"- PRB:" after a PBCH/MIB
# decode succeeds. "Found Cell_id" alone is a candidate (often PSS noise on FDD/TDD
# hypotheses); we only trust a cell we actually decoded.
_PCI_RE = re.compile(r"-\s*PCI:\s*(\d+)")
_PRB_RE = re.compile(r"-\s*PRB:\s*(\d+)")
_MIB_RE = re.compile(r"Decoded MIB")


def _root_child_pids(binary: str) -> list[int]:
    try:
        out = subprocess.run(["pgrep", "-u", "root", "-f", binary],
                             capture_output=True, text=True)
        return [int(x) for x in out.stdout.split()]
    except Exception:  # noqa: BLE001
        return []


def _find_pcap(rundir: Path) -> Path | None:
    cands = [p for p in rundir.glob("*.pcap") if "api_collector" not in p.name]
    cands = [p for p in cands if p.stat().st_size > 24]
    return max(cands, key=lambda p: p.stat().st_size) if cands else None


def _parse(text: str) -> tuple[list[dict], int | None, int | None]:
    """Return (candidates, decoded_pci, decoded_prb).

    candidates: one entry per PCI seen in "Found Cell_id" (signal only — may be
    PSS noise). decoded_pci/prb: the cell we actually PBCH/MIB-decoded (trusted),
    or None if nothing decoded (weak signal)."""
    best: dict[int, dict] = {}
    decoded_pci: int | None = None
    decoded_prb: int | None = None
    last_pci: int | None = None
    last_prb: int | None = None
    for line in text.splitlines():
        mpci = _PCI_RE.search(line)
        if mpci:
            last_pci = int(mpci.group(1))
        mprb = _PRB_RE.search(line)
        if mprb:
            last_prb = int(mprb.group(1))
        if _MIB_RE.search(line) and last_pci is not None:
            decoded_pci, decoded_prb = last_pci, last_prb  # confirmed lock
        m = _FOUND_RE.search(line)
        if not m:
            continue
        _star, pci_s, mode, cp, ratio_s, psr_s, power_s = m.groups()
        pci = int(pci_s)
        rec = {
            "pci": pci, "mode": mode, "cp": cp.strip(),
            "detect_ratio": int(ratio_s), "psr": float(psr_s),
            "power_dbm": None if power_s == "-inf" else float(power_s),
        }
        cur = best.get(pci)
        if cur is None or rec["psr"] > cur["psr"]:
            best[pci] = rec
    return list(best.values()), decoded_pci, decoded_prb


def scan_cells(cfg: SnifferConfig, duration_s: int = 25) -> dict:
    """Run a short cell-search and return the cells found on the DL frequency.
    Never raises to the caller — returns a manifest with ok/error."""
    res: dict = {"ok": False, "error": None, "cells": [], "source": None,
                 "duration_s": duration_s, "freq_hz": int(cfg.rf_freq)}
    if not shutil.which("tshark"):
        res["error"] = "tshark not found on PATH"
        return res

    scfg = cfg.model_copy(update={"cell_search": True, "en_debug": True})
    rundir = Path(tempfile.mkdtemp(prefix="lte-scan-"))
    logf = rundir / "scan.log"
    try:
        from sniffer import _resolve_and_validate_binary
        binpath = _resolve_and_validate_binary(scfg.binary_path)
        argv = scfg.to_argv(str(rundir / "events.json"))
        argv[argv.index(scfg.binary_path)] = str(binpath)

        with open(logf, "w") as lf:
            proc = subprocess.Popen(argv, stdout=lf, stderr=subprocess.STDOUT, cwd=str(rundir))
        deadline = time.time() + duration_s
        while time.time() < deadline and proc.poll() is None:
            time.sleep(1)
        # stop cleanly so the pcap flushes (needed for SIB1)
        for pid in _root_child_pids(str(binpath)):
            subprocess.run(["sudo", "-n", "kill", "-INT", str(pid)])
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            for pid in _root_child_pids(str(binpath)):
                subprocess.run(["sudo", "-n", "kill", "-9", str(pid)])
            proc.wait(timeout=5)

        text = _ANSI.sub("", logf.read_text(errors="replace"))
        candidates, decoded_pci, decoded_prb = _parse(text)
        pcap = _find_pcap(rundir)
        cid = C.read_cell_id(pcap) if pcap else None

        cells: list[dict] = []
        for c in candidates:
            # keep the decoded cell always; otherwise only plausible detections
            is_decoded = (decoded_pci is not None and c["pci"] == decoded_pci)
            if not (is_decoded or (c["detect_ratio"] >= 75 and c["psr"] >= 2.5
                                   and c["power_dbm"] is not None and c["power_dbm"] > -20)):
                continue
            c["decoded"] = is_decoded
            if is_decoded:
                if decoded_prb:
                    c["nof_prb"] = decoded_prb
                if cid:
                    c.update({k: cid[k] for k in
                              ("cell_identity", "eci", "enb_id", "sector", "tac", "plmn")})
            cells.append(c)

        cells.sort(key=lambda c: (not c["decoded"],
                                  -(c["power_dbm"] if c["power_dbm"] is not None else -999)))
        res["cells"] = cells
        res["decoded_pci"] = decoded_pci
        res["source"] = str(pcap) if pcap else None
        res["ok"] = True
        if decoded_pci is None:
            res["note"] = ("No cell fully decoded — signal weak right now (cell search "
                           "only saw PSS noise). Cell ID/TAC need a decodable cell; try again "
                           "when the signal is stronger. Detections below are candidates only.")
        return res
    except Exception as ex:  # noqa: BLE001
        res["error"] = f"{type(ex).__name__}: {ex}"
        return res
    finally:
        try:
            shutil.rmtree(rundir, ignore_errors=True)
        except OSError:
            pass


def pin_cell(cfg: SnifferConfig, timeout_s: int = 60) -> dict:
    """Fast-lock the target PCI and read its Cell ID / MCC / MNC.

    Uses the fast cell-search acquisition (PSS/SSS + CFO) constrained to the
    target PCI's PSS group (`-l N_id_2`), then VERIFIES the decoded PCI equals the
    target. For a PCI that is the only/strongest one in its group (e.g. 237 vs 238,
    which sit in *different* groups) this is fast AND exact. If a stronger cell
    shares the group, it reports the PCI it actually locked. Radios must be free
    (caller checks). Never raises."""
    target = cfg.cell_id
    res: dict = {"ok": False, "error": None, "pci": target, "requested_pci": target,
                 "nof_prb": cfg.nof_prb, "n_id_2": target % 3, "n_id_1": target // 3,
                 "timeout_s": timeout_s}
    if not shutil.which("tshark"):
        res["error"] = "tshark not found on PATH"
        return res
    # EXACT PCI: fast search forcing BOTH the PSS group (-l) and the SSS (-N)
    scfg = cfg.model_copy(update={"cell_search": True, "force_n_id_2": target % 3,
                                  "force_n_id_1": target // 3, "en_debug": True})
    rundir = Path(tempfile.mkdtemp(prefix="lte-pin-"))
    try:
        from sniffer import _resolve_and_validate_binary
        binpath = _resolve_and_validate_binary(scfg.binary_path)
        argv = scfg.to_argv(str(rundir / "events.json"))
        argv[argv.index(scfg.binary_path)] = str(binpath)
        _PIN_CANCEL.clear()
        with open(rundir / "pin.log", "w") as lf:
            proc = subprocess.Popen(argv, stdout=lf, stderr=subprocess.STDOUT, cwd=str(rundir))
        found = None
        cancelled = False
        deadline = time.time() + timeout_s
        while time.time() < deadline and proc.poll() is None:
            if _PIN_CANCEL.is_set():
                cancelled = True
                break
            time.sleep(1)
            try:                                # track the PCI the search locked
                text = _ANSI.sub("", (rundir / "pin.log").read_text(errors="replace"))
                _, dpci, _dprb = _parse(text)
                if dpci is not None:
                    res["pci"] = dpci
            except OSError:
                pass
            pcap = _find_pcap(rundir)
            if pcap:
                cid = C.read_cell_id(pcap)
                if cid and cid.get("mcc"):      # SIB1 decoded with a PLMN
                    found = cid
                    break
        for pid in _root_child_pids(str(binpath)):
            subprocess.run(["sudo", "-n", "kill", "-INT", str(pid)])
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            for pid in _root_child_pids(str(binpath)):
                subprocess.run(["sudo", "-n", "kill", "-9", str(pid)])
            proc.wait(timeout=5)
        if found:
            res["ok"] = True
            res["exact"] = (res.get("pci") == target)   # did we lock the requested PCI?
            res.update({k: found.get(k) for k in
                        ("cell_identity", "eci", "enb_id_hex", "sector", "tac", "tac_hex",
                         "mcc", "mnc", "plmn")})
        elif cancelled or _PIN_CANCEL.is_set():
            res["cancelled"] = True
            res["error"] = "Pin cancelled."
        else:
            res["error"] = (f"No cell locked in PSS group N_id_2={target % 3} (for PCI {target}) "
                            f"within {timeout_s}s — signal may be weak right now, or the PRB "
                            f"({cfg.nof_prb}) doesn't match the cell.")
        return res
    except Exception as ex:  # noqa: BLE001
        res["error"] = f"{type(ex).__name__}: {ex}"
        return res
    finally:
        shutil.rmtree(rundir, ignore_errors=True)
