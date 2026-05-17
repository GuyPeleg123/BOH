# Project44 — LTESniffer Setup Notes

Personal working notes for the fork of LTESniffer running on a USRP B210.
Built on top of FALCON + srsRAN.  These notes are oriented toward someone
picking this up fresh.

---

## Environment

| Item | Details |
|------|---------|
| OS | Ubuntu 22.04 LTS (x86-64) |
| SDR hardware | Ettus USRP B210, connected via USB 3.0 |
| UHD driver | UHD 4.x, built and installed from source |
| srsRAN | built from source as part of the LTESniffer dependency chain |
| CPU | Any modern x86-64; 4+ cores recommended (-W flag controls worker threads) |

Verify UHD sees the B210 before running:

```
uhd_find_devices
uhd_usrp_probe
```

---

## Build

```bash
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

The main binary is built to `build/src/LTESniffer`.

If CMake cannot find srsRAN or FALCON headers, set `CMAKE_PREFIX_PATH`:

```bash
cmake .. -DCMAKE_PREFIX_PATH=/usr/local
```

---

## Running (Downlink — basic test)

```bash
sudo ./build/src/LTESniffer \
    -f 806000000 \
    -A 2 \
    -m 0 \
    -C \
    -W 4 \
    -a "num_recv_frames=512,recv_frame_size=4096"
```

| Flag | Meaning |
|------|---------|
| `-f 806000000` | DL centre frequency in Hz (806 MHz — adjust for your target cell) |
| `-A 2` | Use both RX antennas on the B210 for diversity |
| `-m 0` | Downlink mode |
| `-C` | Automatic PSS/SSS cell search |
| `-W 4` | 4 parallel SubframeWorker threads |
| `-a "..."` | UHD transport hints — increase USB buffer depth to reduce overflows |

Output: `ltesniffer_dl_mode.pcap` in the current directory.
The console prints a one-line summary every 1000 subframes (1 second).

---

## Running (Uplink)

Uplink mode requires both the downlink frequency (for synchronisation) and the
uplink frequency (for actual UL capture).  Two RX antenna ports are used: port 0
receives DL for timing reference, port 1 receives UL traffic.

```bash
sudo ./build/src/LTESniffer \
    -f 806000000 \
    -u 761000000 \
    -A 2 \
    -m 1 \
    -C \
    -W 4 \
    -a "num_recv_frames=512,recv_frame_size=4096"
```

| Flag | Meaning |
|------|---------|
| `-f 806000000` | DL frequency (Hz) — used for PSS/MIB sync |
| `-u 761000000` | UL frequency (Hz) — typically DL freq minus the FDD duplex spacing |
| `-m 1` | Uplink mode |

Output: `ltesniffer_ul_mode.pcap`.

---

## Wireshark

1. Open `ltesniffer_dl_mode.pcap` (or `ltesniffer_ul_mode.pcap`) in Wireshark.
2. If Wireshark shows raw bytes instead of decoded MAC-LTE frames, force the
   link-layer type:
   - Edit > Preferences > Protocols > DLT_USER > Encapsulations table
   - Add: DLT = 147, Payload protocol = `mac-lte-framed`
3. Useful display filters:

| Filter | Shows |
|--------|-------|
| `mac-lte.direction == 1` | Downlink MAC PDUs (eNB to UE) |
| `mac-lte.direction == 0` | Uplink MAC PDUs (UE to eNB) |
| `mac-lte.rnti == 0x1234` | Traffic for a specific RNTI |
| `mac-lte.lcid == 3` | LCID 3 (first DRB, typically user data) |

---

## Key files

| File | Purpose |
|------|---------|
| `src/src/LTESniffer_Core.cc` | Top-level run loop: RF open, cell search, ue_sync, subframe dispatch |
| `src/include/LTESniffer_Core.h` | Class declaration and private member descriptions |
| `src/src/ArgManager.cc` | All CLI argument parsing (getopt) |
| `src/include/ArgManager.h` | `Args` struct — every configurable parameter with flag annotations |
| `src/include/SubframeWorker.h` | Worker thread that blindly decodes PDCCH/PDSCH/PUSCH for one subframe |
| `src/include/Phy.h` | Manages the pool of SubframeWorkers and common PHY state |
| `src/include/MCSTracking.h` | Per-RNTI MCS and 256-QAM modulation order tracker |
| `src/include/HARQ.h` | Downlink HARQ retransmission database |
| `src/include/PcapWriter.h` | Writes MAC-LTE PDUs in pcap format to disk |
| `src/include/ULSchedule.h` | Maps downlink DCI grants to uplink PUSCH resources |

---

## Known working commands

Commands confirmed working on this hardware (B210, Ubuntu 22.04, UHD 4.x):

### Downlink capture with auto cell search

```bash
sudo ./build/src/LTESniffer \
    -f 806000000 \
    -A 2 -m 0 -C -W 4 \
    -a "num_recv_frames=512,recv_frame_size=4096"
```

### Downlink capture with manual cell config (skip cell search, faster start)

```bash
sudo ./build/src/LTESniffer \
    -f 806000000 -I 42 -p 100 \
    -A 2 -m 0 -W 4 \
    -a "num_recv_frames=512,recv_frame_size=4096"
```

(`-I 42` = physical cell ID 42, `-p 100` = 100 PRBs / 20 MHz)

### Uplink capture

```bash
sudo ./build/src/LTESniffer \
    -f 806000000 -u 761000000 \
    -A 2 -m 1 -C -W 4 \
    -a "num_recv_frames=512,recv_frame_size=4096"
```

### Target a single RNTI (reduces CPU and clutter)

```bash
sudo ./build/src/LTESniffer \
    -f 806000000 -A 2 -m 0 -C -W 4 \
    -r 0x3ABC \
    -a "num_recv_frames=512,recv_frame_size=4096"
```

---

*Last updated: 2026-05-17 — Project44*
