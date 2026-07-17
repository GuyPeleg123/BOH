"""Persisted GUI/sniffer configuration."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

from pydantic import BaseModel, Field, field_validator


CONFIG_PATH = Path.home() / ".config" / "ltesniffer-gui" / "config.json"

# The only legal LTE downlink bandwidths, in PRBs. Anything else (e.g. a stray
# 125) makes srsRAN's FFT/MIB init fail with "Invalid number of PRB" and the
# sniffer never starts — so we snap bad values to the nearest legal one.
VALID_PRB = (6, 15, 25, 50, 75, 100)


class SnifferConfig(BaseModel):
    """Mirror of every CLI flag LTESniffer accepts.

    Field names match the underlying `Args` struct where possible; the GUI form
    binds 1:1 to this model.
    """

    # --- RF / hardware ---
    rf_freq: float = Field(0.0, description="Downlink centre frequency (Hz). -f")
    ul_freq: float = Field(0.0, description="Uplink centre frequency (Hz). -u")
    rf_gain: float = Field(-1.0, description="RX gain dB; -1 enables AGC. -g")
    ul_rf_gain: float = Field(30.0, description="UL (rf_b) RX gain dB (-G). Lower it when an "
                             "LNA is inline to protect the USRP: no LNA -> 50, with LNA -> 30. "
                             "-1 follows the general gain.")
    rf_nof_rx_ant: int = Field(1, ge=1, le=4, description="Number of RX antennas. -A")
    rf_args: str = Field("", description="Free-form rfargs for single-USRP mode. -a")
    usrp_a_args: str = Field("", description="Override USRP A rfargs (dual mode). -X")
    usrp_b_args: str = Field("", description="Override USRP B rfargs (dual mode). -Z")
    clock_source: str = Field(
        "internal",
        description=(
            "RX clock + time reference, injected as clock=<source> into the device "
            "args (-a/-X/-Z). 'internal' = onboard oscillator; 'gpsdo' = onboard GPSDO "
            "(10 MHz + 1 PPS from GPS); 'external' = REF IN (10 MHz) + PPS IN (1 PPS) "
            "shared reference. Authoritative — overrides any embedded clock=. "
            "'' disables injection."
        ),
    )
    decimate: int = Field(0, description="Decimation factor. -Y")
    cpu_affinity: int = Field(-1, description="CPU affinity bitmask; -1 disables. -y")

    # --- Cell / modes ---
    sniffer_mode: int = Field(0, ge=0, le=2, description="0 DL, 1 UL, 2 dual. -m")
    api_mode: int = Field(-1, ge=-1, le=3, description="-1 off, 0 identity, 1 IMSI, 2 UECapa, 3 all. -z")
    cell_search: bool = Field(True, description="Enable PSS/SSS cell search. -C")
    force_n_id_2: int = Field(-1, ge=-1, le=2,
                              description="Constrain cell-search to PSS group N_id_2 (=PCI mod 3); "
                                          "-1 = any. Fast way to target a specific PCI. -l")
    force_n_id_1: int = Field(-1, ge=-1, le=167,
                              description="Force SSS N_id_1 (=PCI//3) for an EXACT-PCI lock (with "
                                          "force_n_id_2); -1 = any. -N")
    cell_id: int = Field(0, description="Fixed PCI (0-503) when -C disabled. -I")
    nof_prb: int = Field(50, description="PRBs of fixed cell. -p")
    # MCC/MNC are the TARGET network. The radio locks by PCI (physical layer);
    # PLMN (MCC+MNC) is only in SIB1, read after lock — so these are used to
    # label/verify the cell, not to drive the -I lock. Not passed as CLI flags.
    mcc: str = Field("", description="Target MCC (network id). Verification/label only.")
    mnc: str = Field("", description="Target MNC (network id). Verification/label only.")
    target_rnti: int = Field(0, description="Only decode this RNTI; 0 = all. -r")

    @field_validator("nof_prb")
    @classmethod
    def _snap_nof_prb(cls, v: int) -> int:
        # Guard against an illegal value (typed in the form or hand-edited in
        # config.json) that would otherwise crash the FFT/MIB decoder at start.
        if v in VALID_PRB:
            return v
        return min(VALID_PRB, key=lambda p: abs(p - v))

    @field_validator("clock_source")
    @classmethod
    def _norm_clock_source(cls, v: str) -> str:
        # Constrain to the known UHD sources so a typo can't silently produce a
        # bad clock= arg. Anything unrecognised falls back to the safe default.
        v = (v or "").strip().lower()
        return v if v in ("", "internal", "gpsdo", "external") else "internal"

    # --- Decoder tuning ---
    nof_sniffer_thread: int = Field(4, ge=2, description="Number of worker threads. -W")
    skip_secondary_meta_formats: bool = Field(False, description="-s")
    dci_format_split_ratio: float = Field(0.5, ge=0.0, le=1.0, description="-S")
    dci_format_split_update_interval_ms: int = Field(100, description="-T")
    enable_shortcut_discovery: bool = Field(True, description="-L disables")
    rnti_histogram_threshold: int = Field(0, description="-H")
    mcs_tracking_mode: int = Field(1, description="-q")
    en_debug: bool = Field(False, description="-d")

    # --- Output files ---
    # NOTE: LTESniffer_Core.cc always uses hardcoded filenames regardless of -F
    # (ltesniffer_dl_mode.pcap / ltesniffer_dual_mode.pcap / ltesniffer_ul_mode.pcap
    # + api_collector.pcap).  The -F flag sets args.pcap_file which is never read
    # back by the Core.  We do NOT pass -F to avoid confusion; captures are
    # separated by per-run timestamped subdirectory (see sniffer.py).
    dci_file_name: str = Field("", description="-D (empty = stdout)")
    stats_file_name: str = Field("", description="-E")
    keys_file: str = Field("", description="-K")
    pcap_stream_fifo: str = Field(
        "",
        description=(
            "Optional named-pipe path. When set, every decoded MAC PDU is also "
            "mirrored to this FIFO so Wireshark can dissect packets live. "
            "Backend mkfifos the path on capture start; passed through to the "
            "C++ child as LTESNIFFER_PCAP_STREAM via `sudo env` so it survives "
            "sudo env_reset. Typical value: /tmp/lte.pcap."
        ),
    )

    # --- GUI-only ---
    binary_path: str = Field(
        "../../build/src/LTESniffer",
        description="Path to the LTESniffer executable. Relative paths resolve from gui/backend/ — the default points at the repo's own build.",
    )
    captures_dir: str = Field(
        "~/ltesniffer-captures",
        description="Directory the sniffer runs in (pcaps land here). Created if missing.",
    )
    sudo: bool = Field(True, description="Wrap invocation in sudo (USRP usually needs it).")

    # Auto-split: when a capture finishes, divide its pcap along these dimensions
    # (see captures.split_dimensions). Empty list / disabled = no auto-split.
    auto_split_enabled: bool = Field(False, description="Split each finished capture automatically.")
    auto_split_dims: list[str] = Field(default_factory=list, description="Ordered split dimensions, e.g. ['identity','packet_type'].")

    def to_argv(self, json_output_path: str) -> list[str]:
        """Render to argv for subprocess.Popen.

        Always appends `-J <json_output_path>` so the GUI receives events.
        """
        argv: list[str] = []
        if self.sudo:
            argv += ["sudo", "-n"]
        # NOTE: LTESNIFFER_PCAP_STREAM is passed via the child's environment (set
        # by the runner) and preserved across sudo's env_reset by a scoped
        # `env_keep` sudoers rule — NOT via a `sudo env VAR=… binary` prefix.
        # `env` under sudo is an unrestricted-root primitive and must never be
        # whitelisted, so we do not invoke it here.
        argv.append(self.binary_path)

        if self.rf_freq > 0:
            argv += ["-f", str(int(self.rf_freq))]
        if self.ul_freq > 0:
            argv += ["-u", str(int(self.ul_freq))]
        if self.rf_gain >= 0:
            argv += ["-g", str(self.rf_gain)]
        if self.ul_rf_gain >= 0:                 # independent UL (rf_b) gain; lower with an LNA
            argv += ["-G", str(self.ul_rf_gain)]
        if self.rf_nof_rx_ant != 1:
            argv += ["-A", str(self.rf_nof_rx_ant)]
        # clock_source is the single source of truth for the RX clock + time
        # reference (the GUI dropdown). Inject it as clock=<source> into every
        # device-args string (-a/-X/-Z), stripping any embedded clock= so the
        # dropdown always wins — the args string used to bury clock= where it
        # went stale or got dropped, silently breaking UL sync. internal =
        # onboard; gpsdo = onboard GPSDO; external = REF IN + PPS IN (shared ref).
        def _with_clock(rfargs: str) -> str:
            toks = [t for t in (rfargs or "").split(",")
                    if t.strip() and not t.strip().startswith("clock=")]
            if self.clock_source:
                toks = [f"clock={self.clock_source}", *toks]
            return ",".join(toks)

        if self.rf_args:
            argv += ["-a", _with_clock(self.rf_args)]
        if self.usrp_a_args:
            argv += ["-X", _with_clock(self.usrp_a_args)]
        if self.usrp_b_args:
            argv += ["-Z", _with_clock(self.usrp_b_args)]
        if self.decimate:
            argv += ["-Y", str(self.decimate)]
        if self.cpu_affinity >= 0:
            argv += ["-y", str(self.cpu_affinity)]

        argv += ["-m", str(self.sniffer_mode)]
        if self.api_mode >= 0:
            argv += ["-z", str(self.api_mode)]
        if self.cell_search:
            argv.append("-C")
            if self.force_n_id_2 >= 0:      # target a PCI group during search (fast + selective)
                argv += ["-l", str(self.force_n_id_2)]
            if self.force_n_id_1 >= 0:      # force the SSS too => lock an EXACT PCI
                argv += ["-N", str(self.force_n_id_1)]
        else:
            argv += ["-I", str(self.cell_id), "-p", str(self.nof_prb)]
        if self.target_rnti:
            argv += ["-r", str(self.target_rnti)]

        argv += ["-W", str(self.nof_sniffer_thread)]
        if self.skip_secondary_meta_formats:
            argv.append("-s")
        argv += ["-S", str(self.dci_format_split_ratio)]
        argv += ["-T", str(self.dci_format_split_update_interval_ms)]
        if not self.enable_shortcut_discovery:
            argv.append("-L")
        if self.rnti_histogram_threshold:
            argv += ["-H", str(self.rnti_histogram_threshold)]
        argv += ["-q", str(self.mcs_tracking_mode)]
        if self.en_debug:
            argv.append("-d")

        if self.dci_file_name:
            argv += ["-D", self.dci_file_name]
        if self.stats_file_name:
            argv += ["-E", self.stats_file_name]
        if self.keys_file:
            argv += ["-K", self.keys_file]

        argv += ["-J", json_output_path]
        return argv


def load() -> SnifferConfig:
    if CONFIG_PATH.exists():
        try:
            return SnifferConfig.model_validate_json(CONFIG_PATH.read_text())
        except Exception as e:
            # Don't silently revert to defaults — the operator loses their whole
            # config (incl. clock=gpsdo, freqs) with no signal otherwise.
            log.warning("config %s failed to parse (%s); using defaults", CONFIG_PATH, e)
    return SnifferConfig()


def save(cfg: SnifferConfig) -> None:
    """Persist config with 0600 perms (it points at the keys file)."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = cfg.model_dump_json(indent=2)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(CONFIG_PATH, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(payload)
    finally:
        try:
            os.chmod(CONFIG_PATH, 0o600)
        except OSError:
            pass
