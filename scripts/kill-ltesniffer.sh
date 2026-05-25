#!/bin/bash
# Kill all running LTESniffer processes.
# Called by the GUI backend to ensure clean teardown when sudo is in use.
# This script is whitelisted in /etc/sudoers.d/ltesniffer so the non-root
# backend process can kill the root-owned LTESniffer subprocess.
pkill -KILL -x LTESniffer 2>/dev/null || true
exit 0
