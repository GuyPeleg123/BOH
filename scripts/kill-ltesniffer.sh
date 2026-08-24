#!/bin/bash
# Signal all running LTESniffer processes.
# Called by the GUI backend to ensure clean teardown when sudo is in use.
# This script is whitelisted in /etc/sudoers.d/ltesniffer so the non-root
# backend process can signal the root-owned LTESniffer subprocess.
#
# Usage: kill-ltesniffer.sh [SIGNAL]
#   SIGNAL defaults to KILL (back-compat with callers that pass no arg).
#   Use TERM for graceful shutdown (lets the binary flush PCAP + free RF).
#
# The GUI sends:
#   1. kill-ltesniffer.sh TERM    → graceful, lets PCAP flush
#   2. wait up to ~15s for exit
#   3. kill-ltesniffer.sh KILL    → only if still alive (data loss)
#
# Why we don't just signal `sudo` directly: sudo with `-n` and no controlling
# terminal does NOT reliably forward SIGINT/SIGTERM to its child — sudo
# exits, the child gets reparented to init, and the polite signal vanishes.
# Signalling LTESniffer directly is the only way the binary's SignalGate
# handlers (which DO catch SIGTERM, since commit 2e1619a) actually fire.
SIG="${1:-KILL}"
pkill --signal="$SIG" -x LTESniffer 2>/dev/null || true
exit 0
