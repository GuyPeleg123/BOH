#!/bin/bash
# Configure chrony to use the GPSDO inside the USRP as a stratum-1 refclock.
# Required for sub-millisecond host log timestamps that line up with
# sample-time inside the USRP — the foundation for cross-sniffer ToA / TDoA
# work later (Phase 5: F7 LTrack-style localization, F8 dual-sniffer TDoA).
#
# Run once on the capture host:
#   sudo bash scripts/setup-chrony-gpsdo.sh
#
# Idempotent: refuses to add the refclock line if it's already there.

set -euo pipefail

CHRONY_CONF="/etc/chrony/chrony.conf"
LINE="refclock SHM 0 refid GPS poll 4 precision 1e-9 prefer"

if [[ $EUID -ne 0 ]]; then
    echo "Re-run with sudo: sudo bash $0" >&2
    exit 1
fi

if ! command -v chronyd >/dev/null; then
    echo "chrony not installed. Install with:"
    echo "  sudo apt install chrony"
    exit 1
fi

if [[ ! -f "$CHRONY_CONF" ]]; then
    echo "Expected chrony config at $CHRONY_CONF — not found. Aborting."
    exit 1
fi

if grep -qF "$LINE" "$CHRONY_CONF"; then
    echo "Refclock line already present in $CHRONY_CONF — no change."
else
    echo "Appending refclock line to $CHRONY_CONF"
    {
        echo ""
        echo "# Added by ltesniffer-gui $(date -Iseconds) — GPSDO refclock via SHM segment 0"
        echo "# (USRP's gpsd writes PPS into /dev/shm/NTP0 when configured properly)"
        echo "$LINE"
    } >> "$CHRONY_CONF"
fi

echo
echo "Restarting chronyd..."
systemctl restart chrony

echo
echo "chronyc tracking:"
chronyc tracking || true
echo
echo "chronyc sources:"
chronyc sources || true
echo
echo "If GPS is not yet a candidate source, ensure gpsd is running and"
echo "the USRP's GPSDO is locked (uhd_usrp_probe should show 'GPSDO locked')."
