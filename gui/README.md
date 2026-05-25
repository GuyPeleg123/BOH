# LTESniffer GUI

A web dashboard for the LTE sniffer: config page, live RNTI/RB/cell views,
capture controls. Designed to be visually rich and operator-friendly.

```
┌────────────────────────────────────────────────────────────┐
│ LTESniffer  Dashboard  Config        ● connected ● running │
├──────────┬─────────────────────────────────┬───────────────┤
│ Capture  │       RB Waterfall (DL)          │ RNTI table   │
│ Cell     │                                  │              │
│ Identity ├─────────────────────────────────┤              │
│          │             Logs                 │              │
└──────────┴─────────────────────────────────┴───────────────┘
```

## Architecture

```
   ┌───────────┐    JSON-lines (FIFO)   ┌───────────┐   WS   ┌───────────┐
   │ LTESniffer│ ─────────────────────▶ │  FastAPI  │ ◀────▶ │  React    │
   │  (C++)    │                        │  backend  │  REST  │  frontend │
   └───────────┘                        └───────────┘        └───────────┘
        │                                     │
        ▼                                     ▼
      pcap                            ~/.config/ltesniffer-gui/config.json
```

The sniffer accepts a new `-J <path>` flag to emit newline-delimited JSON
events. The backend creates a FIFO, launches the sniffer, and streams events
to every connected browser via WebSocket.

Schema: see [PROTOCOL.md](./PROTOCOL.md).

## Setup

### 1) Build the patched LTESniffer

```bash
cd /home/project44/work/LTESniffer
cmake --build build -j$(nproc)
# binary lands at build/src/LTESniffer
```

### 2) Backend

```bash
cd gui/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Mock mode (no SDR hardware required):
```bash
LTESNIFFER_GUI_MOCK=1 uvicorn main:app --reload
```

### 3) Frontend

Dev (Vite hot-reload, proxies API to localhost:8000):
```bash
cd gui/frontend
npm install
npm run dev          # http://localhost:5173
```

Build for production (backend serves the static bundle from `/`):
```bash
npm run build
# then visit http://localhost:8000/
```

## Running with a USRP

LTESniffer needs root for USRP access. Either:

- Run `sudo uvicorn ...` (simple, but the whole backend is root),
- Or enable passwordless `sudo` for the LTESniffer binary and keep the
  default `sudo: true` in the GUI config.

Then in the Config page:
1. Set DL freq (and UL freq if dual-mode)
2. Pick sniffer mode
3. For dual-USRP, set the USRP A/B rfargs (the page suggests them from
   `uhd_find_devices`)
4. Save & Restart

## API

- `GET  /api/config`            current saved config
- `PUT  /api/config`            persist config
- `GET  /api/status`            running state, pid, argv
- `POST /api/capture/start`     start sniffer (body: optional SnifferConfig)
- `POST /api/capture/stop`
- `POST /api/capture/restart`
- `GET  /api/usrps`             `uhd_find_devices` results
- `GET  /api/captures`          discovered pcap files
- `WS   /api/events`            JSONL event stream (replay buffer first, then live)

## Files

```
gui/
├── PROTOCOL.md              # JSON event schema
├── backend/
│   ├── main.py              # FastAPI app, REST + WS
│   ├── sniffer.py           # subprocess + FIFO reader
│   ├── mock.py              # synthetic events (no hardware needed)
│   ├── config.py            # SnifferConfig pydantic model + argv builder
│   ├── usrp.py              # uhd_find_devices wrapper
│   └── pyproject.toml
└── frontend/
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.js
    └── src/
        ├── App.tsx
        ├── pages/{Dashboard,Config}.tsx
        ├── components/{CellPanel,CaptureControls,RNTITable,RBWaterfall,
        │              LogPanel,IdentitiesPanel,StatusBar}.tsx
        └── lib/{types,api,store,color}.ts
```

C++ changes (in the parent repo):

- `src/include/JSONEmitter.h`, `src/src/JSONEmitter.cc` — new emitter
- `src/include/ArgManager.h`, `src/src/ArgManager.cc` — `-J/-X/-Z` flags
- `src/include/LTESniffer_Core.h`, `src/src/LTESniffer_Core.cc` — wire it in
