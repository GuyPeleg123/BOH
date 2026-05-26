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

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
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
from auth import BIND, TOKEN, TOKEN_PATH, REQUIRE_LOCAL_TOKEN, require_token, require_token_ws
import zmq_pub
from metrics import MetricsBus
from recorder import SessionRecorder, ReplayRunner
from state_tracker import StateTracker
import analytics
import known_cells as known_cells_mod
from known_cells import KnownCellsFile, KnownCell, KNOWN_CELLS_PATH

log = logging.getLogger(__name__)

MOCK = os.environ.get("LTESNIFFER_GUI_MOCK", "").lower() in {"1", "true", "yes"}
REPLAY = os.environ.get("LTESNIFFER_GUI_REPLAY", "").strip()
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


# UHD on Linux drops samples ("O"/"D" in stderr) when the kernel socket buffer
# is smaller than what the streamer needs at the configured sample rate. The
# Ettus knowledge base recommends 24MB for 20-MHz LTE captures.
_RMEM_MIN = 24 * 1024 * 1024


def _check_rmem_max() -> None:
    """Read /proc/sys/net/core/rmem_max and warn (with fix command) if low.

    Only relevant for Ethernet-attached USRPs (X310/N310) — B210 is USB so
    this knob doesn't affect it — but it's a one-liner to surface either way.
    """
    try:
        with open("/proc/sys/net/core/rmem_max") as f:
            current = int(f.read().strip())
    except OSError as exc:
        log.debug("rmem_max probe failed: %s", exc)
        return
    if current < _RMEM_MIN:
        log.warning(
            "net.core.rmem_max=%d (need >=%d for clean UHD streaming at >=20MHz). "
            "Fix:  sudo sysctl -w net.core.rmem_max=%d "
            "(persist by adding the line to /etc/sysctl.d/99-uhd.conf)",
            current, _RMEM_MIN, _RMEM_MIN,
        )


_zmq = zmq_pub.maybe_create()
_metrics = MetricsBus()
_state_tracker = StateTracker(cell_id=0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---- startup ----
    _kill_stale_ltesniffers()
    _check_rmem_max()
    await _metrics.start(runner)
    await _state_tracker.start(runner)
    if _zmq is not None:
        await _zmq.start(runner)
    if not REPLAY:
        # Don't record a replay session — we'd double-write history with no value.
        await _recorder.start(runner)
    # If REPLAY is set, kick the replay off immediately so the dashboard sees data.
    if REPLAY:
        await runner.start(None)
    # Auth banner so the operator can't miss the security posture they're in.
    if BIND in ("0.0.0.0", "::"):
        log.warning(
            "==================================================================\n"
            "  GUI exposed on %s (LTESNIFFER_GUI_BIND=%s).\n"
            "  Every REST + WebSocket request must carry a bearer token from\n"
            "    %s\n"
            "  (Loopback requests still work without it unless\n"
            "   LTESNIFFER_GUI_REQUIRE_TOKEN_LOCAL=1 is set.)\n"
            "==================================================================",
            BIND, BIND, TOKEN_PATH,
        )
    else:
        log.info(
            "GUI bound to %s (loopback only). Set LTESNIFFER_GUI_BIND=0.0.0.0 "
            "to expose to LAN. Token at %s.", BIND, TOKEN_PATH,
        )
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
    if _zmq is not None:
        try:
            await _zmq.stop()
        except Exception as exc:
            log.warning("Error stopping zmq on shutdown: %s", exc)
    try:
        await _metrics.stop()
    except Exception as exc:
        log.warning("Error stopping metrics on shutdown: %s", exc)
    try:
        await _recorder.stop()
    except Exception as exc:
        log.warning("Error stopping recorder on shutdown: %s", exc)
    try:
        await _state_tracker.stop()
    except Exception as exc:
        log.warning("Error stopping state_tracker on shutdown: %s", exc)
    log.info("Shutdown: all subprocesses stopped.")


if REPLAY:
    runner = ReplayRunner(Path(REPLAY).expanduser())
elif MOCK:
    runner = MockRunner()
else:
    runner = SnifferRunner()
spectrum = SpectrumLauncher()
_recorder = SessionRecorder()

app = FastAPI(title="LTESniffer GUI Backend", lifespan=lifespan)
# Tightened CORS: spec-compliant, only allows the bind host + dev server.
_allowed_origins = [
    f"http://{BIND}:8000" if BIND not in ("0.0.0.0", "::") else "http://127.0.0.1:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://localhost:5173",  # vite dev server
    "http://127.0.0.1:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(dict.fromkeys(_allowed_origins)),  # dedupe, preserve order
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Routes that don't require a token. /api/health stays open so a misconfigured
# client can tell "wrong token" (401) apart from "server down" (no response).
_AUTH_FREE_PREFIXES = ("/api/health", "/assets/", "/metrics")
_AUTH_FREE_EXACT = {"/"}  # SPA index — token check happens via the WS instead


@app.middleware("http")
async def _auth_gate(request, call_next):
    """Block /api/* without a bearer token unless we're on loopback (and
    REQUIRE_LOCAL_TOKEN isn't set). Static + index are always served so the
    SPA can prompt the user for the token."""
    path = request.url.path
    if path in _AUTH_FREE_EXACT or any(path.startswith(p) for p in _AUTH_FREE_PREFIXES) or not path.startswith("/api/"):
        return await call_next(request)
    try:
        await require_token(request)
    except HTTPException as exc:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return await call_next(request)


# /api/health is intentionally token-free: lets a misconfigured client tell
# the difference between "wrong token" (401) and "server down" (no response).
@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "mock": MOCK, "auth_required": BIND in ("0.0.0.0", "::") or REQUIRE_LOCAL_TOKEN}


@app.get("/metrics")
async def metrics_endpoint():
    from fastapi.responses import Response
    body, content_type = _metrics.render()
    return Response(content=body, media_type=content_type)


@app.get("/api/config", response_model=SnifferConfig)
async def get_config() -> SnifferConfig:
    return config_mod.load()


@app.put("/api/config", response_model=SnifferConfig)
async def put_config(cfg: SnifferConfig) -> SnifferConfig:
    # Security gate: anything that becomes argv to a root-owned process must
    # be validated server-side, not just sanitized client-side.
    if cfg.keys_file:
        try:
            # validate_keys_path tolerates non-existing files (only blocks
            # symlinks / escapes), so a not-yet-created keys.json is OK.
            cfg.keys_file = str(keys_mod._validate_keys_path(Path(cfg.keys_file)))
        except PermissionError as e:
            raise HTTPException(403, f"keys_file rejected: {e}")
    if cfg.binary_path:
        try:
            from sniffer import _resolve_and_validate_binary
            _resolve_and_validate_binary(cfg.binary_path)
        except PermissionError as e:
            raise HTTPException(403, f"binary_path rejected: {e}")
        except FileNotFoundError:
            # Tolerate not-yet-built binary at save time; start will reject later.
            pass
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
    except PermissionError as e:
        raise HTTPException(403, str(e))
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
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
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
    try:
        path = keys_mod.save(body)
    except PermissionError as e:
        raise HTTPException(403, str(e))
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


@app.get("/api/known-cells")
async def get_known_cells() -> dict[str, Any]:
    kcf = known_cells_mod.load()
    return {"cells": [c.model_dump() for c in kcf.cells], "path": str(KNOWN_CELLS_PATH)}


@app.put("/api/known-cells")
async def put_known_cells(body: KnownCellsFile) -> dict[str, Any]:
    try:
        path = known_cells_mod.save(body)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return {"ok": True, "path": str(path), "n_cells": len(body.cells)}


@app.post("/api/known-cells/{idx}/load")
async def load_known_cell_into_config(idx: int) -> dict[str, Any]:
    """Copy a known cell's freq/USRP/mode settings into the active SnifferConfig.
    Returns the updated config so the GUI can refresh the form."""
    kcf = known_cells_mod.load()
    if idx < 0 or idx >= len(kcf.cells):
        raise HTTPException(404, f"known cell index {idx} out of range (have {len(kcf.cells)})")
    cell = kcf.cells[idx]
    cfg = config_mod.load()
    cfg.rf_freq = cell.dl_freq_mhz * 1e6
    cfg.ul_freq = cell.ul_freq_mhz * 1e6
    cfg.nof_prb = cell.nof_prb
    cfg.sniffer_mode = cell.sniffer_mode
    cfg.usrp_a_args = cell.usrp_a_args
    cfg.usrp_b_args = cell.usrp_b_args
    cfg.rf_gain = cell.rf_gain
    config_mod.save(cfg)
    return {"ok": True, "loaded": cell.label, "config": cfg.model_dump()}


@app.get("/api/analytics/rnti-churn")
async def analytics_rnti_churn(path: str) -> dict[str, Any]:
    """Run the RNTI churn analyzer against a recorded session.

    `path` must point to a .jsonl.zst file under the session dir or the
    pcap-allowed roots — same allowlist used by /api/captures/download.
    """
    p = Path(path).expanduser().resolve()
    sessions_dir = (Path.home() / ".local" / "share" / "ltesniffer-gui" / "sessions").resolve()
    cfg = config_mod.load()
    allowed_roots = captures_mod.allowed_roots(cfg) + [sessions_dir]
    if not any(str(p).startswith(str(r)) for r in allowed_roots):
        raise HTTPException(403, f"path '{p}' outside allowed roots")
    if not p.exists():
        raise HTTPException(404, str(p))
    if not str(p).endswith(".jsonl.zst"):
        raise HTTPException(415, "expected .jsonl.zst session file")
    return analytics.analyze_rnti_churn(p)


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
    # Token check BEFORE accept(): we don't want to give an unauthed peer a
    # 101 upgrade response with our subprotocol/server info.
    if not await require_token_ws(ws):
        return
    await ws.accept()
    # Subscribe *after* capturing the replay snapshot so events that arrive
    # during the replay send (which could be hundreds of frames at real-LTE
    # rates) don't fill the new subscriber's queue before it starts draining.
    replay_events = runner.replay()
    q = runner.subscribe()
    try:
        # Single envelope instead of N send_text calls — one frame, one parse
        # on the frontend, one reducer dispatch.
        if replay_events:
            await ws.send_text(json.dumps({"t": "replay", "events": replay_events}))
        while True:
            # Each queue item is (event_dict, encoded_str). Use the cached
            # encoding so we don't re-json.dumps per subscriber.
            _ev, encoded = await q.get()
            await ws.send_text(encoded)
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
