"""FastAPI app — REST control plane + WebSocket event stream for the GUI."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import config as config_mod
from config import SnifferConfig
from sniffer import SnifferRunner
from mock import MockRunner
from usrp import find_devices, auto_config_patch
from spectrum import SpectrumLauncher
import captures as captures_mod
import keys as keys_mod
from keys import KeysFile, KEYS_PATH

log = logging.getLogger(__name__)

MOCK = os.environ.get("LTESNIFFER_GUI_MOCK", "").lower() in {"1", "true", "yes"}
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


_KILL_SCRIPT = (
    Path(__file__).resolve().parent.parent.parent / "scripts" / "kill-ltesniffer.sh"
)


def _kill_stale_ltesniffers() -> None:
    """Kill any LTESniffer processes left over from a previous session.

    This handles the case where the backend was killed without a clean shutdown
    (SIGKILL, OOM-killer, power loss) and the LTESniffer subprocess (which runs
    under sudo) was orphaned and left consuming memory.

    Uses the dedicated kill-wrapper script (whitelisted in sudoers NOPASSWD)
    so root-owned processes can be reached from the non-root backend.
    """
    try:
        result = subprocess.run(
            ["pgrep", "-x", "LTESniffer"],
            capture_output=True, text=True, timeout=3
        )
        pids = result.stdout.strip().split()
        if not pids:
            return
        log.warning(
            "Startup: found %d stale LTESniffer process(es) (PIDs: %s) — killing.",
            len(pids), " ".join(pids)
        )
        # First try unprivileged SIGKILL (works if process runs as same user).
        subprocess.run(["pkill", "-KILL", "-x", "LTESniffer"], capture_output=True, timeout=3)
        # Then use the sudoers-whitelisted script to reach root-owned processes.
        if _KILL_SCRIPT.exists():
            subprocess.run(["sudo", "-n", str(_KILL_SCRIPT)], capture_output=True, timeout=5)
    except Exception as exc:
        log.debug("_kill_stale_ltesniffers: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---- startup ----
    _kill_stale_ltesniffers()
    yield
    # ---- shutdown ----
    # Stop all subprocesses so nothing is orphaned when the server exits.
    # This runs when uvicorn receives SIGINT / SIGTERM or is programmatically stopped.
    log.info("Shutdown: stopping sniffer and spectrum processes…")
    try:
        await runner.stop()
    except Exception as exc:
        log.warning("Error stopping runner on shutdown: %s", exc)
    try:
        await spectrum.stop()
    except Exception as exc:
        log.warning("Error stopping spectrum on shutdown: %s", exc)
    log.info("Shutdown: all subprocesses stopped.")


runner = MockRunner() if MOCK else SnifferRunner()
spectrum = SpectrumLauncher()

app = FastAPI(title="LTESniffer GUI Backend", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "mock": MOCK}


@app.get("/api/config", response_model=SnifferConfig)
async def get_config() -> SnifferConfig:
    return config_mod.load()


@app.put("/api/config", response_model=SnifferConfig)
async def put_config(cfg: SnifferConfig) -> SnifferConfig:
    config_mod.save(cfg)
    return cfg


@app.get("/api/status")
async def status() -> dict[str, Any]:
    return {"state": runner.state(), "mock": MOCK}


@app.post("/api/capture/start")
async def capture_start(cfg: SnifferConfig | None = None) -> dict[str, Any]:
    if cfg is None:
        cfg = config_mod.load()
    else:
        config_mod.save(cfg)
    if runner.running:
        raise HTTPException(409, "sniffer already running")
    try:
        await runner.start(cfg)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"failed to start: {e}")
    return {"ok": True, "state": runner.state()}


@app.post("/api/capture/stop")
async def capture_stop() -> dict[str, Any]:
    await runner.stop()
    return {"ok": True, "state": runner.state()}


@app.post("/api/capture/restart")
async def capture_restart(cfg: SnifferConfig | None = None) -> dict[str, Any]:
    if cfg is None:
        cfg = config_mod.load()
    else:
        config_mod.save(cfg)
    try:
        await runner.restart(cfg)
    except Exception as e:
        raise HTTPException(500, f"failed to restart: {e}")
    return {"ok": True, "state": runner.state()}


@app.get("/api/usrps")
async def list_usrps() -> dict[str, Any]:
    return {"devices": await find_devices()}


@app.get("/api/usrps/autoconfig")
async def usrps_autoconfig() -> dict[str, Any]:
    """Detect connected USRPs and return a suggested config patch.

    The frontend can apply this patch to pre-fill serial numbers without the
    user having to type them manually.  Keys starting with '_' are metadata
    (not SnifferConfig fields) and should not be written to the config.
    """
    return await auto_config_patch()


@app.get("/api/keys")
async def get_keys() -> dict[str, Any]:
    kf = keys_mod.load()
    return {
        "entries": [e.model_dump() for e in kf.entries],
        "path": str(KEYS_PATH),
        "exists": KEYS_PATH.exists(),
    }


@app.put("/api/keys")
async def put_keys(body: KeysFile) -> dict[str, Any]:
    path = keys_mod.save(body)
    # Auto-point the saved sniffer config at our keys file so the next
    # capture launch will use it (only if the user hasn't set their own path).
    cfg = config_mod.load()
    if not cfg.keys_file or cfg.keys_file == str(KEYS_PATH):
        cfg.keys_file = str(path)
        config_mod.save(cfg)
    return {
        "ok": True,
        "path": str(path),
        "wired_into_config": cfg.keys_file == str(path),
        "n_entries": len(body.entries),
    }


@app.get("/api/spectrum")
async def spectrum_status() -> dict[str, Any]:
    return spectrum.status()


@app.post("/api/spectrum/launch")
async def spectrum_launch(body: dict[str, Any]) -> dict[str, Any]:
    freq = float(body.get("freq_hz") or 0)
    sr = float(body.get("sample_rate_hz") or 0)
    tool = body.get("tool")
    device_args = body.get("device_args") or None
    if freq <= 0:
        raise HTTPException(400, "freq_hz required")
    try:
        return await spectrum.launch(freq, sr, tool, device_args)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except RuntimeError as e:
        # 422 keeps the body (with the stderr-derived message) for the UI to display.
        raise HTTPException(422, str(e))


@app.post("/api/spectrum/stop")
async def spectrum_stop() -> dict[str, Any]:
    return await spectrum.stop()


@app.get("/api/captures")
async def list_captures() -> dict[str, Any]:
    cfg = config_mod.load()
    roots = [str(r) for r in captures_mod.allowed_roots(cfg)]
    return {
        "captures": captures_mod.list_pcaps(cfg),
        "roots": roots,
        "captures_dir": str(Path(cfg.captures_dir).expanduser()),
    }


@app.get("/api/captures/download")
async def download_capture(path: str) -> FileResponse:
    cfg = config_mod.load()
    try:
        p = captures_mod.resolve_for_download(cfg, path)
    except FileNotFoundError:
        raise HTTPException(404, "pcap not found")
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return FileResponse(p, media_type="application/vnd.tcpdump.pcap", filename=p.name)


@app.websocket("/api/events")
async def events_ws(ws: WebSocket) -> None:
    await ws.accept()
    q = runner.subscribe()
    try:
        # Send buffered history first so a refreshed client doesn't see a blank screen.
        for ev in runner.replay():
            await ws.send_text(json.dumps(ev))
        while True:
            ev = await q.get()
            await ws.send_text(json.dumps(ev))
    except WebSocketDisconnect:
        pass
    finally:
        runner.unsubscribe(q)


# --- Static frontend (served only if `npm run build` has been run) ----------

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str) -> FileResponse:
        # no-store on the HTML so a fresh tab always picks up new hashed JS;
        # the /assets/* files are content-hashed and safe to cache normally.
        index = FRONTEND_DIST / "index.html"
        return FileResponse(index, headers={"Cache-Control": "no-store, must-revalidate"})
