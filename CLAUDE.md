# LTESniffer — project context for all agents

This file is auto-loaded into every (non-Explore/Plan) agent's context. Keep it
short and factual; role-specific behavior lives in `.claude/agents/*.md`.

## What this is
A FALCON/srsRAN-based dual-mode LTE sniffer (this fork = `GuyPeleg123/BOH`,
branch `multi-usrp`; local clone at `~/work/LTESniffer`). Captures DL+UL with two
USRP B210s and writes MAC-LTE pcaps.

**This branch (`sniffer-nodecrypt`) is CAPTURE-ONLY: all key-management and PDCP
decryption/deciphering has been removed from the frontend, backend, and C++
core.**

## Stack & layout
- **C++ core** (`src/`, `lib/`, srsRAN/FALCON under `build/srsRAN-src`): PHY/MAC
  decode, `PcapWriter`.
- **GUI backend** `gui/backend/` — FastAPI + uvicorn (HTTPS on 127.0.0.1:8443),
  session-cookie auth. Key modules: `captures.py` (pcap discovery, organize,
  **split engine**), `sniffer.py` (subprocess lifecycle), `config.py`,
  `main.py` (routes).
- **GUI frontend** `gui/frontend/` — React + TypeScript + Vite + Tailwind.
  Build with `npm run build`; the backend serves `dist/`.
- **Analysis**: `scripts/ta_report.py` (TA→distance). Post-capture work uses
  `tshark` (Wireshark 3.6.2 on the target).

## Hard-won facts (don't relearn these)
- **tshark protocol filter for RRC is `lte_rrc` (underscore); FIELDS are
  `lte-rrc.*` (hyphen).** `lte-rrc` as a bare protocol errors out.
- RNTI ≠ UE identity. Real UEs = recurring C-RNTIs (rnti-type 3) + any RNTI that
  announced a TMSI/IMSI. SI/P/RA are broadcast/paging/RACH, not UEs.
- Dual-mode needs a shared 10 MHz **and** a shared 1 PPS; the recurring failure
  is GPSDO with no GPS lock (`gps_locked=false`). DL-only single-USRP tuning is
  broken in this build.

## Offline appliance (critical constraint)
The deliverable is a prebuilt **GUI appliance** installed at `/opt/ltesniffer`
on an air-gapped Ubuntu 22.04.5 box (no internet, no compiler, may lack `curl`).
Builder scripts live in `~/lte-bundle/`. GUI/Python/frontend changes ship via a
small **upgrade bundle** (`install-new-ver.sh`, auto-rollback) — no recompile.
C++ changes require rebuilding + re-shipping the full ~600 MB appliance, so
**prefer post-capture Python/tshark over C++ when feasible.**

## Working norms
- **Verify everything against real artifacts** — run it, test on real captures /
  known vectors, show the output. No "looks correct" without evidence.
- Match surrounding code style; no unrequested scope or dependencies.
- **Commit/push only when the user asks.** Branch is `multi-usrp` on origin
  `GuyPeleg123/BOH`. End commit messages with the Co-Authored-By trailer.
- Keep `dist/` rebuilt when frontend changes; restart the backend to serve it.
