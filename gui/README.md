# LTESniffer GUI

An operator-facing web GUI for the [LTESniffer](../README.md) C++ tool. Adds
a live JSON event stream from the sniffer, a configuration page covering every
CLI flag, a built-in spectrum analyzer launcher, and a captures browser.

> **Capture-only build** (branch `sniffer-nodecrypt`): all PDCP decryption /
> key-management features have been removed. Everything else — capturing
> pcaps, config, sessions, dashboard, spectrum, Wireshark, and logs — is
> unchanged.

```
┌──────────────────────────────────────────────────────────────────────────┐
│ LTESniffer  Dashboard  Config               ● connected  ● running       │
├──────────────────────────────────────────────────────────────────────────┤
│ [▶ Start] [■ Stop] [⟳ Restart] [📡 Spectrum]   ● Cell PCI 271  50 PRB    │
├──────────────────────────────────────────────────────────────────────────┤
│   UEs seen │ DCIs decoded │ DL / UL │ Throughput │ RB/s │ Health        │
├────────────────────────────────┬────────────────────┬───────────────────┤
│  Packets · live DCI feed       │  RB waterfall      │  Active RNTIs     │
│  …per-DCI table…               │  …PRB × time…      │  …per-UE totals…  │
├────────────────────────────────┴────────────────────┴───────────────────┤
│  Logs / Captures / Identities  (tabs)                                   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Architecture

```
┌───────────┐  JSON over FIFO   ┌────────────┐   WebSocket   ┌────────────┐
│ LTESniffer│ ────────────────▶ │  FastAPI   │ ◀──────────▶  │   React    │
│  (C++)    │                   │  backend   │   REST        │  frontend  │
└───────────┘                   └────────────┘               └────────────┘
      │                               │
      ▼                               ▼
   pcap files          ~/.config/ltesniffer-gui/config.json
   (in captures_dir)
```

- C++ accepts `-J <path>` (a FIFO) and emits one JSON object per line for every
  decoded subframe + cell / MIB / stats / lifecycle events. See
  [PROTOCOL.md](./PROTOCOL.md) for the schema.
- Backend (Python / FastAPI) manages the sniffer subprocess, reads its FIFO,
  broadcasts events over a WebSocket, persists config, and exposes a
  small REST control plane.
- Frontend (React + Vite + Tailwind) consumes the WebSocket, renders the live
  dashboard, and POSTs config / capture-control changes.

## Dependencies

### Build the C++ patch (one time)

The GUI requires a patched LTESniffer binary with the JSON emitter wired in.
The patch is included in this branch (`src/include/JSONEmitter.{h,cc}` +
edits to `ArgManager.*` and `LTESniffer_Core.*`). Build it with the same
toolchain as upstream:

```
sudo apt install build-essential cmake libuhd-dev libboost-all-dev libfftw3-dev
cd LTESniffer
cmake -S . -B build
cmake --build build -j$(nproc)
# binary: build/src/LTESniffer
```

(Hint: this CMakeLists uses `file(GLOB …)` for sources — if you ever drop a
new `.cc` into `src/src/`, run `cmake .` from `build/` once so it picks it up.)

### Backend (Python 3.10+)

```
sudo apt install python3-pip python3-venv
cd gui/backend
python3 -m venv .venv
.venv/bin/pip install -e .
```

`pip install -e .` installs FastAPI, Uvicorn, and Pydantic (see
`pyproject.toml`).

### Frontend (Node 18+)

```
cd gui/frontend
npm install
npm run build      # produces dist/, served by the backend at /
```

### Optional: spectrum analyzer tools

The "📡 Spectrum" button launches a native UHD GUI tool on the backend host's
desktop. The pre-flight panel in the popover tells you what's missing if it
won't launch. Install any of:

```
sudo apt install gnuradio-uhd     # provides uhd_fft + uhd_siggen_gui
sudo apt install gqrx-sdr         # provides gqrx
```

And run once to download the USRP firmware images that UHD needs:

```
sudo /lib/x86_64-linux-gnu/uhd/utils/uhd_images_downloader.py
```

## Running

The backend serves the pre-built frontend over HTTPS with HTTP Basic Auth.
Use the launcher script — it handles cert + credential generation for you.

### Standard launch (HTTPS + Basic Auth)

```
cd gui/backend
.venv/bin/python serve.py
# in another shell, only when frontend code changes:
cd gui/frontend && npm run build
```

Open <https://192.168.20.12:8443/> in Firefox (use *your* LAN IP — the
launcher prints it to stderr at startup).

**First-time setup (one-time, ~30 seconds):**

1. The launcher generates a self-signed TLS cert + key (`~/.config/ltesniffer-gui/{cert.pem,key.pem}`) and a bcrypt-hashed credentials file (`~/.config/ltesniffer-gui/auth.json`).
2. The auto-generated `admin` password is printed to **stderr ONCE** — capture it now. After the line scrolls off, only the bcrypt hash on disk remains; you cannot recover the plaintext.
3. Firefox shows a "Warning: Potential Security Risk Ahead" page on first visit (self-signed cert). Click **Advanced** → **Accept the Risk and Continue**. Subsequent visits are silent.
4. Firefox shows its native username/password dialog. Enter `admin` and the captured password. Click **Save Password** if you want the password manager to remember it.

To rotate credentials: `rm ~/.config/ltesniffer-gui/auth.json && restart serve.py`.
To rotate cert (e.g. you moved to a different LAN IP): `rm ~/.config/ltesniffer-gui/{cert,key}.pem && restart`.

**Custom credentials at first start:** set the username/password explicitly via env vars (consumed once, then ignored):

```
LTESNIFFER_GUI_USER=alice LTESNIFFER_GUI_PASS='super secret' .venv/bin/python serve.py
```

**Custom bind / port:**

```
.venv/bin/python serve.py --host 10.0.0.5 --port 9443
# or via env (overrides autodetect):
LTESNIFFER_GUI_BIND=10.0.0.5 .venv/bin/python serve.py
```

### Frontend development with hot-reload (HTTP-only, for dev only)

The Vite dev server proxies `/api` to a backend running on HTTP/8000:

```
# shell A — backend on HTTP for the vite proxy
cd gui/backend && .venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000

# shell B — Vite dev server
cd gui/frontend && npm run dev
```

Open <http://localhost:5173/>. Basic Auth still applies; Firefox will prompt.

### Mock mode (no SDR / no sudo needed)

Useful for previewing the dashboard or developing the UI on a machine without
USRPs:

```
LTESNIFFER_GUI_MOCK=1 .venv/bin/python serve.py
```

The backend replaces `SnifferRunner` with `MockRunner`, which emits a
hand-crafted event stream (cell, DCIs, RB allocations, occasional identity
events) at ~50 subframes / second.

## Permissions: sudo for USRP

LTESniffer needs root for USB / USRP access. Either:

- Run uvicorn under `sudo` (simple, but the whole backend runs as root), or
- Allow passwordless sudo for just the `LTESniffer` binary in
  `/etc/sudoers.d/ltesniffer`:

  ```
  yourusername ALL=(root) NOPASSWD: /path/to/LTESniffer/build/src/LTESniffer
  ```

  Then leave **Run via `sudo -n`** enabled in the Config page (default).

## Features

### Dashboard

- **Cell card** — PCI, DL / UL freq, sample rate, bandwidth, MIB SFN, CFO,
  worker count, % subframes skipped. Updates only on real cell / stats events.
- **Metrics tiles** — UEs seen, DCIs decoded (with rate), DL / UL DCI split,
  throughput, RB rate, decoding health. Values are quantized and re-rendered
  at 1 Hz so they don't flicker.
- **Packets · live DCI feed** — every DCI as it's decoded, with direction,
  SFN.sf, RNTI (colored), format, MCS, PRB count, TBS bytes, NDI, HARQ
  process, raw hex. Filter by ALL / DL / UL and by RNTI; hover or ❚❚ pause to
  freeze for reading (shows `+N while paused`).
- **RB waterfall** — canvas-based heat map of PRB × time. Toggle Alloc (per-
  RNTI colors) vs Power (RSRP gradient), DL vs UL. Throttled to 5 Hz.
- **Active RNTIs** — per-UE totals: DCI counts, RB totals, throughput bytes,
  last-seen age. Sorted by RNTI by default (stable; doesn't shuffle); toggle
  "show only active (last 5s)" to focus on live UEs. Rows fade as UEs go idle.
- **Bottom tabs** — **Logs** (sniffer stderr + GUI messages), **Captures**
  (pcap files with download buttons), **Identities** (IMSI / TMSI / UECapa
  collected via API mode `-z`).

### Spectrum

A "📡 Spectrum" button launches a native UHD GUI (uhd_fft, uhd_siggen_gui,
or gqrx) on the backend host's display, prefilled with the current DL freq +
sample rate. The popover includes:

- **Pre-flight panel** — green / red checks for `$DISPLAY`, UHD firmware
  images, and tool availability, with the exact apt / installer command to
  fix each red item inline.
- **USRP picker** — radio buttons for every USRP detected by
  `uhd_find_devices`. Detects which serial(s) the running sniffer is holding
  (parsed from its argv) and labels them "HELD BY SNIFFER" + disables the
  launch buttons if that USRP is picked.
- **Error surfacing** — if the spawned tool dies within 2.5 s, its stderr
  tail is captured and shown in a red box. The button turns red ("⚠ Spectrum
  failed") with the error in its title; clicking re-opens the popover with
  the last error pinned so you don't lose it.

### Configuration

A form covering every LTESniffer CLI flag (`-f`, `-u`, `-g`, `-W`, `-S`,
`-X`/`-Z` USRP rfargs, etc.) plus GUI-only fields (binary path, captures
directory, run-via-sudo toggle). Detected USRPs appear as clickable chips at
the top of the page (clicking copies a sample rfargs string into the field).
"Save" persists to `~/.config/ltesniffer-gui/config.json`; "Save & Restart"
also restarts the capture with the new args.

### Captures

`/api/captures` enumerates `.pcap` files in the captures directory plus
`~/work/captures/` and `~/work/LTESniffer/pcap_file_example/`. The Captures
tab shows file name, source, size, age, and a download link per file. The
download endpoint is restricted to those allowed roots — paths outside them
are rejected with 403.

## REST API

| Method | Path                            | Purpose                                  |
| ------ | ------------------------------- | ---------------------------------------- |
| GET    | `/api/health`                   | Liveness + mock-mode flag                |
| GET    | `/api/status`                   | Sniffer state, pid, argv                 |
| GET / PUT | `/api/config`                | SnifferConfig pydantic model             |
| POST   | `/api/capture/start`            | Start sniffer (optional body: SnifferConfig) |
| POST   | `/api/capture/stop`             | SIGINT, then SIGKILL after 5 s           |
| POST   | `/api/capture/restart`          | Stop + start                             |
| GET    | `/api/usrps`                    | Result of `uhd_find_devices`             |
| GET    | `/api/captures`                 | List pcaps in allowed roots              |
| GET    | `/api/captures/download?path=…` | Stream a pcap (allowlist-checked)        |
| GET    | `/api/spectrum`                 | Status + pre-flight checks               |
| POST   | `/api/spectrum/launch`          | Spawn uhd_fft / gqrx (body: freq, sr, tool, device_args) |
| POST   | `/api/spectrum/stop`            | Terminate the spectrum process           |
| WS     | `/api/events`                   | Live JSONL event stream (sticky replay + live) |

## Event protocol

See [PROTOCOL.md](./PROTOCOL.md) for the full schema. Summary:

| Type        | When                                         |
| ----------- | -------------------------------------------- |
| `hello`     | Once at sniffer startup; carries Args dump   |
| `cell`      | After cell search completes                  |
| `mib`       | When MIB is decoded                          |
| `sf`        | Per processed subframe (≤ 1000 / s real LTE) |
| `stats`     | ~1 / s — sf processed / skipped, RNTI count, CFO |
| `identity`  | API mode (`-z`) finds IMSI / TMSI / UECapa   |
| `log`       | Free-form log line                           |
| `bye`       | Clean shutdown                               |
| `lifecycle` | Backend-injected: `started` / `exited`      |

`hello / cell / mib / lifecycle / stats` are also tracked as "sticky" by the
backend and replayed on every WebSocket reconnect so refreshing the page
doesn't lose cell info.

## File layout

```
gui/
├── PROTOCOL.md                 # JSON event schema
├── README.md                   # this file
├── backend/
│   ├── pyproject.toml
│   ├── main.py                 # FastAPI app, REST + WS, SPA static mount
│   ├── sniffer.py              # Subprocess + FIFO reader (real mode)
│   ├── mock.py                 # Synthetic events (no SDR needed)
│   ├── config.py               # SnifferConfig + argv builder + persistence
│   ├── captures.py             # Pcap discovery + safe download
│   ├── spectrum.py             # uhd_fft / gqrx launcher + preflight
│   └── usrp.py                 # uhd_find_devices wrapper
└── frontend/
    ├── package.json, vite.config.ts, tailwind.config.js, tsconfig.json
    ├── index.html
    └── src/
        ├── App.tsx, main.tsx, index.css
        ├── pages/
        │   ├── Dashboard.tsx
        │   └── Config.tsx
        ├── components/
        │   ├── StatusBar.tsx
        │   ├── CaptureControls.tsx
        │   ├── SpectrumButton.tsx
        │   ├── CellCard.tsx
        │   ├── MetricsTiles.tsx
        │   ├── PacketFeed.tsx
        │   ├── RBWaterfall.tsx
        │   ├── RNTITable.tsx
        │   ├── LogPanel.tsx
        │   ├── CapturesPanel.tsx
        │   └── IdentitiesPanel.tsx
        └── lib/
            ├── store.ts        # context + reducer + WS connection
            ├── api.ts          # REST client
            ├── types.ts        # Event / Config types
            ├── color.ts        # Deterministic RNTI / power color maps
            └── useStableTick.ts# Slow-render hook for calmer numeric tiles
```

C++ side (in the parent repo):

```
src/include/JSONEmitter.h   src/src/JSONEmitter.cc      ← new
src/include/ArgManager.h    src/src/ArgManager.cc       ← + -J/-X/-Z flags
src/include/LTESniffer_Core.h src/src/LTESniffer_Core.cc ← register emitter,
                                                          emit cell/MIB/bye,
                                                          override USRP serials
```

## Troubleshooting

| Symptom                                        | Cause / fix                                                                                  |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Dashboard shows "stopped" but events flowing   | Stale browser tab — Ctrl+Shift+R (the SPA is served with `Cache-Control: no-store`).         |
| "Waiting for cell discovery…" forever          | LTESniffer can't find a cell at the configured freq, or the sniffer crashed — check the Logs tab. |
| Spectrum button red ("⚠ Spectrum failed")      | Hover for tooltip + click to see the inline error. Most commonly: UHD images missing or USRP held. |
| `No devices found for ----->Empty Device Address` | Pick a specific USRP in the spectrum popover; the picker passes `-a serial=…`.            |
| `Could not find path for image: usrp_b200_fw.hex` | `sudo /lib/x86_64-linux-gnu/uhd/utils/uhd_images_downloader.py`                          |
| Captures tab is empty                          | The sniffer runs with cwd=`captures_dir` (Config page). Pcaps from previous runs in other dirs only appear if those dirs are under one of the allowed roots in `captures.py`. |
| `sudo: a password is required`                 | Either run uvicorn under `sudo`, or set up a passwordless sudoers entry as documented above. |
