"""Persisted GUI/sniffer configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


CONFIG_PATH = Path.home() / ".config" / "ltesniffer-gui" / "config.json"


class SnifferConfig(BaseModel):
    """Mirror of every CLI flag LTESniffer accepts.

    Field names match the underlying `Args` struct where possible; the GUI form
    binds 1:1 to this model.
    """

    # --- RF / hardware ---
    rf_freq: float = Field(0.0, description="Downlink centre frequency (Hz). -f")
    ul_freq: float = Field(0.0, description="Uplink centre frequency (Hz). -u")
    rf_gain: float = Field(-1.0, description="RX gain dB; -1 enables AGC. -g")
    rf_nof_rx_ant: int = Field(1, ge=1, le=4, description="Number of RX antennas. -A")
    rf_args: str = Field("", description="Free-form rfargs for single-USRP mode. -a")
    usrp_a_args: str = Field("", description="Override USRP A rfargs (dual mode). -X")
    usrp_b_args: str = Field("", description="Override USRP B rfargs (dual mode). -Z")
    decimate: int = Field(0, description="Decimation factor. -Y")
    cpu_affinity: int = Field(-1, description="CPU affinity bitmask; -1 disables. -y")

    # --- Cell / modes ---
    sniffer_mode: int = Field(0, ge=0, le=2, description="0 DL, 1 UL, 2 dual. -m")
    api_mode: int = Field(-1, ge=-1, le=3, description="-1 off, 0 identity, 1 IMSI, 2 UECapa, 3 all. -z")
    cell_search: bool = Field(True, description="Enable PSS/SSS cell search. -C")
    cell_id: int = Field(0, description="Fixed cell ID when -C disabled. -I")
    nof_prb: int = Field(50, description="PRBs of fixed cell. -p")
    target_rnti: int = Field(0, description="Only decode this RNTI; 0 = all. -r")

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

    def to_argv(self, json_output_path: str) -> list[str]:
        """Render to argv for subprocess.Popen.

        Always appends `-J <json_output_path>` so the GUI receives events.
        """
        argv: list[str] = []
        if self.sudo:
            argv += ["sudo", "-n"]
        # If the user opted into the live-stream FIFO, prepend
        #   env LTESNIFFER_PCAP_STREAM=<path>
        # so the env var survives sudo's env_reset (the C++ PcapWriter reads
        # this var to decide whether to fork a copy of every MAC PDU to the FIFO).
        if self.pcap_stream_fifo:
            argv += ["env", f"LTESNIFFER_PCAP_STREAM={self.pcap_stream_fifo}"]
        argv.append(self.binary_path)

        if self.rf_freq > 0:
            argv += ["-f", str(int(self.rf_freq))]
        if self.ul_freq > 0:
            argv += ["-u", str(int(self.ul_freq))]
        if self.rf_gain >= 0:
            argv += ["-g", str(self.rf_gain)]
        if self.rf_nof_rx_ant != 1:
            argv += ["-A", str(self.rf_nof_rx_ant)]
        if self.rf_args:
            argv += ["-a", self.rf_args]
        if self.usrp_a_args:
            argv += ["-X", self.usrp_a_args]
        if self.usrp_b_args:
            argv += ["-Z", self.usrp_b_args]
        if self.decimate:
            argv += ["-Y", str(self.decimate)]
        if self.cpu_affinity >= 0:
            argv += ["-y", str(self.cpu_affinity)]

        argv += ["-m", str(self.sniffer_mode)]
        if self.api_mode >= 0:
            argv += ["-z", str(self.api_mode)]
        if self.cell_search:
            argv.append("-C")
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
        except Exception:
            pass
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
