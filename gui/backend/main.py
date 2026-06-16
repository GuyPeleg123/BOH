"""FastAPI app — REST control plane + WebSocket event stream for the GUI."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import shutil
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse

import config as config_mod
from config import SnifferConfig
from sniffer import SnifferRunner
import sniffer as sniffer_mod
from mock import MockRunner
from usrp import find_devices, auto_config_patch, probe_all_gpsdo
from spectrum import SpectrumLauncher
import captures as captures_mod
import runlogs
import keys as keys_mod
from keys import KeysFile, KEYS_PATH
from auth import (
    BIND, AUTH_PATH, COOKIE_NAME, SESSION_TTL_S,
    require_session, require_session_ws,
    verify_credentials, create_session, drop_session, session_user,
)
import https as https_mod
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
    # HTTPS + session-cookie auth, no loopback bypass — every request authenticates.
    log.warning(
        "==================================================================\n"
        "  GUI bound to %s — HTTPS + in-app Login page (no loopback bypass).\n"
        "  Credentials: %s\n"
        "  First start prints the auto-generated password to stderr ONCE.\n"
        "  Sessions: in-memory, 8h idle timeout, HttpOnly Secure SameSite=Strict cookie.\n"
        "  To rotate creds: delete %s and restart.\n"
        "==================================================================",
        BIND, AUTH_PATH, AUTH_PATH,
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
# HTTPS is the production posture; HTTP is only listed for the vite dev server
# during frontend hacking (it talks to the backend through the vite proxy).
_allowed_origins = [
    f"https://{BIND}:8443",
    f"https://{BIND}:8000",  # if operator chose 8000 for HTTPS
    "https://127.0.0.1:8443",
    "https://localhost:8443",
]
# Plaintext vite dev origins are only allowed when explicitly developing — they
# must never ship enabled on a credentialed-CORS admin console.
if os.environ.get("LTESNIFFER_GUI_DEV") == "1":
    _allowed_origins += ["http://localhost:5173", "http://127.0.0.1:5173"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(dict.fromkeys(_allowed_origins)),  # dedupe, preserve order
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Auth-free routes. /api/login is obviously needed (you can't auth in if
# you can't reach the login endpoint). /api/health stays open so operators
# can distinguish "auth failed" (401) from "server down" (no response).
# The SPA index at `/` is ALSO auth-free so the React app can boot, render
# the Login.tsx page, and POST credentials. /assets/* serves the bundled
# JS/CSS the SPA needs to render at all.
_AUTH_FREE_PREFIXES = ("/api/health", "/api/login", "/assets/")
_AUTH_FREE_EXACT: set[str] = {"/"}


@app.middleware("http")
async def _auth_gate(request, call_next):
    """Block every /api/* request without a valid session cookie.

    No WWW-Authenticate header on 401 — we explicitly DON'T want the
    browser's native popup; the SPA's <Login> page handles auth UI.

    The SPA shell (`/`) and its assets are served unauthenticated so the
    React app can render the Login page; every /api/* call from that
    Login page (except /api/login itself) requires a valid session
    cookie."""
    path = request.url.path
    if path in _AUTH_FREE_EXACT or any(path.startswith(p) for p in _AUTH_FREE_PREFIXES):
        return await call_next(request)
    # Only gate /api/*; static SPA routes (catch-all in spa()) also flow
    # through here, but if they're not in the auth-free list we still let
    # them through so the SPA can render its own Login UI.
    if not path.startswith("/api/"):
        return await call_next(request)
    try:
        await require_session(request)
    except HTTPException as exc:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return await call_next(request)


# ── Auth endpoints (the only /api/* paths the SPA can hit unauthenticated) ──

class _LoginBody(BaseModel):
    username: str
    password: str


# Per-IP failed-login throttle (in-memory). bcrypt is slow but a strong password
# can still be online-guessed without a rate limit; lock out an IP after too many
# failures in a window.
_LOGIN_FAILS: dict[str, list[float]] = {}
_LOGIN_WINDOW_S = 300.0
_LOGIN_MAX_FAILS = 10


def _login_throttled(ip: str) -> bool:
    now = time.monotonic()
    fails = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < _LOGIN_WINDOW_S]
    _LOGIN_FAILS[ip] = fails
    return len(fails) >= _LOGIN_MAX_FAILS


@app.post("/api/login")
async def login(body: _LoginBody, request: Request, response: Response) -> dict[str, Any]:
    """Validate credentials, mint a session, set the cookie.

    On wrong creds we return 401 with a generic message ("invalid
    credentials") rather than distinguishing wrong-user from wrong-pass —
    enumeration defense in depth, layered on the constant-time verify."""
    ip = request.client.host if request.client else "?"
    if _login_throttled(ip):
        raise HTTPException(status_code=429, detail="too many attempts, try again later")
    # bcrypt(12) takes ~250ms; run it off the event loop so a login (or a flood
    # of them) can't stall the live WS event stream.
    if not await asyncio.to_thread(verify_credentials, body.username, body.password):
        _LOGIN_FAILS.setdefault(ip, []).append(time.monotonic())
        raise HTTPException(status_code=401, detail="invalid credentials")
    _LOGIN_FAILS.pop(ip, None)  # reset on success
    token = create_session(body.username)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_S,
        httponly=True,            # JS can't read it (XSS exfiltration defense)
        secure=True,              # only over TLS (we're HTTPS-only)
        samesite="strict",        # never sent on cross-site requests
        path="/",
    )
    return {"ok": True, "username": body.username}


@app.post("/api/logout")
async def logout(request: Request, response: Response) -> dict[str, Any]:
    """Drop the server-side session and clear the cookie. Idempotent —
    works whether or not the caller had a valid session."""
    drop_session(request.cookies.get(COOKIE_NAME))
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/whoami")
async def whoami(request: Request) -> dict[str, Any]:
    """Cheap auth probe for the SPA: returns 200 + username if the cookie
    is valid, 401 otherwise. The SPA calls this on mount to decide
    whether to show Login or Dashboard."""
    user = session_user(request.cookies.get(COOKIE_NAME))
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return {"username": user}


# /api/health is intentionally token-free: lets a misconfigured client tell
# the difference between "wrong token" (401) and "server down" (no response).
@app.get("/api/health")
async def health() -> dict[str, Any]:
    # auth_required is always True with the new HTTP Basic Auth model — no
    # loopback bypass. Field kept for client-side compatibility.
    return {"ok": True, "mock": MOCK, "auth_required": True}


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
    if cfg.pcap_stream_fifo:
        # Fail fast on out-of-allowlist paths so the user gets a useful error
        # at Save time, not 30s later when they hit ▶ Start. We don't actually
        # mkfifo here (that happens at capture/start); just validate the path
        # shape via the same helper. tolerates the path not existing yet.
        try:
            from sniffer import _STREAM_FIFO_ALLOWED_ROOTS
            p = Path(cfg.pcap_stream_fifo).expanduser()
            if not p.is_absolute() or p.is_symlink() or \
               not any(str(p).startswith(str(r) + os.sep) for r in _STREAM_FIFO_ALLOWED_ROOTS):
                raise PermissionError(
                    f"must be an absolute non-symlink path under one of: "
                    f"{', '.join(str(r) for r in _STREAM_FIFO_ALLOWED_ROOTS)}"
                )
        except PermissionError as e:
            raise HTTPException(403, f"pcap_stream_fifo rejected: {e}")
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
    # NEVER enumerate USB (uhd_find_devices) while a capture holds the USRPs —
    # the scan resets the bus and disconnects the running radios.
    if runner.running:
        return {"devices": [], "running": True, "skipped": "capture running"}
    return {"devices": await find_devices()}


@app.get("/api/usrps/autoconfig")
async def usrps_autoconfig() -> dict[str, Any]:
    """Detect connected USRPs and return a suggested config patch.

    The frontend can apply this patch to pre-fill serial numbers without the
    user having to type them manually.  Keys starting with '_' are metadata
    (not SnifferConfig fields) and should not be written to the config.
    """
    # Auto-detect runs uhd_find_devices — skip entirely while capturing so it
    # can't reset the bus out from under the live radios.
    if runner.running:
        return {"_running": True,
                "_message": "Capture running — USRP auto-detect skipped to avoid disturbing the radios."}
    return await auto_config_patch()


@app.get("/api/usrps/gpsdo")
async def probe_usrps_gpsdo() -> dict[str, Any]:
    """Probe all connected USRPs for GPSDO presence via uhd_usrp_probe.

    Slow endpoint (~3-8 s per device, run concurrently).  The frontend calls
    this in the background after auto-config and uses the result to
    conditionally add clock=gpsdo to usrp_a_args / usrp_b_args.
    """
    # uhd_usrp_probe OPENS each device — absolutely must not run during a
    # capture or it yanks the USRP away from the running sniffer.
    if runner.running:
        return {"devices": [], "running": True,
                "message": "Capture running — GPSDO probe skipped (uhd_usrp_probe would reset the radios)."}
    devices = await find_devices()
    if not devices:
        return {"devices": [], "message": "No USRPs detected."}
    probed = await probe_all_gpsdo(devices)
    with_gpsdo = [d["serial"] for d in probed if d.get("gpsdo") and d.get("serial")]
    without_gpsdo = [d["serial"] for d in probed if not d.get("gpsdo") and d.get("serial")]
    if not without_gpsdo:
        msg = f"GPSDO detected on all {len(probed)} device(s) — clock=gpsdo applied."
    elif not with_gpsdo:
        msg = (
            f"No GPSDO detected on any device ({', '.join(without_gpsdo)}). "
            "Dual mode may have sync issues without a shared clock reference."
        )
    else:
        msg = (
            f"GPSDO found on {', '.join(with_gpsdo)}; "
            f"NOT found on {', '.join(without_gpsdo)}."
        )
    return {"devices": probed, "message": msg}


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
    # Optional tuning knobs forwarded to the spectrum tool's argv. Each is
    # passed through unchanged when set, omitted (tool default) when not.
    extras = {
        k: body.get(k)
        for k in ("gain_db", "antenna", "fft_size", "fft_average", "update_rate")
        if body.get(k) not in (None, "")
    }
    try:
        return await spectrum.launch(freq, sr, tool, device_args, extras)
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


@app.post("/api/known-cells/save-current")
async def save_current_as_known_cell(body: dict[str, Any]) -> dict[str, Any]:
    """Snapshot the active SnifferConfig + a label/notes into a new KnownCell.

    The label is required; notes/PCI are optional. Other fields are copied from
    the live SnifferConfig (freq, mode, USRP rfargs, gain, PRB).
    """
    import time as _t
    label = (body.get("label") or "").strip()
    if not label:
        raise HTTPException(400, "label is required")
    cfg = config_mod.load()
    kcf = known_cells_mod.load()
    cell = KnownCell(
        label=label,
        dl_freq_mhz=cfg.rf_freq / 1e6,
        ul_freq_mhz=cfg.ul_freq / 1e6,
        bandwidth_mhz=body.get("bandwidth_mhz"),
        nof_prb=cfg.nof_prb,
        pci=body.get("pci"),
        sniffer_mode=cfg.sniffer_mode,
        usrp_a_args=cfg.usrp_a_args,
        usrp_b_args=cfg.usrp_b_args,
        rf_gain=cfg.rf_gain,
        last_success_iso=_t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime()),
        notes=(body.get("notes") or "").strip(),
    )
    kcf.cells.append(cell)
    path = known_cells_mod.save(kcf)
    return {"ok": True, "path": str(path), "idx": len(kcf.cells) - 1, "cell": cell.model_dump()}


@app.put("/api/known-cells/{idx}")
async def update_known_cell(idx: int, cell: KnownCell) -> dict[str, Any]:
    kcf = known_cells_mod.load()
    if idx < 0 or idx >= len(kcf.cells):
        raise HTTPException(404, f"known cell idx {idx} out of range")
    kcf.cells[idx] = cell
    known_cells_mod.save(kcf)
    return {"ok": True, "cell": cell.model_dump()}


@app.delete("/api/known-cells/{idx}")
async def delete_known_cell(idx: int) -> dict[str, Any]:
    kcf = known_cells_mod.load()
    if idx < 0 or idx >= len(kcf.cells):
        raise HTTPException(404, f"known cell idx {idx} out of range")
    removed = kcf.cells.pop(idx)
    known_cells_mod.save(kcf)
    return {"ok": True, "removed_label": removed.label, "n_remaining": len(kcf.cells)}


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


@app.get("/api/logs/history")
async def list_log_history() -> dict[str, Any]:
    """List past sniffer-run logs (one per capture run), newest first."""
    cfg = config_mod.load()
    return {"runs": runlogs.list_run_logs(cfg)}


@app.get("/api/logs/content")
async def get_log_content(path: str) -> dict[str, Any]:
    """Return the text of one run's sniffer.log (restricted to captures_dir)."""
    cfg = config_mod.load()
    try:
        return {"path": path, "text": runlogs.read_run_log(cfg, path)}
    except FileNotFoundError:
        raise HTTPException(404, f"log not found: {path}")
    except PermissionError as e:
        raise HTTPException(403, str(e))


@app.get("/api/captures")
async def list_captures() -> dict[str, Any]:
    cfg = config_mod.load()
    roots = [str(r) for r in captures_mod.allowed_roots(cfg)]
    return {
        "captures": captures_mod.list_pcaps(cfg, sniffer_running=runner.running),
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


class _BruteforceBody(BaseModel):
    path: str
    kasme: str
    nas_lo: int
    nas_hi: int
    rnti: int | None = None
    cipher_algo: str = "EEA2"
    integ_algo: str = "EIA2"


@app.post("/api/keys/bruteforce-nas")
async def bruteforce_nas(body: _BruteforceBody) -> dict[str, Any]:
    """Brute-force the NAS uplink COUNT over a range, deriving keys from K_ASME
    and testing which count actually decrypts the target UE. Blocking (many
    tshark runs) → off the event loop; bad input returns ok=False, not a 500."""
    cfg = config_mod.load()
    return await asyncio.to_thread(
        captures_mod.bruteforce_nas, cfg, body.path, body.kasme,
        body.nas_lo, body.nas_hi, body.rnti, body.cipher_algo, body.integ_algo,
    )


@app.get("/api/fs/browse")
async def fs_browse(path: str | None = None) -> dict[str, Any]:
    """Directory listing for the decrypt file picker. Defaults to captures_dir;
    can navigate anywhere on the machine (authenticated local admin GUI)."""
    cfg = config_mod.load()
    return await asyncio.to_thread(captures_mod.browse_dir, cfg, path)


class _DecryptEntryBody(BaseModel):
    rnti: int
    # Supply the ciphering keys directly, OR a K_eNB, OR K_ASME + NAS uplink
    # count — the backend derives K_RRCenc/K_UPenc (TS 33.401) when the raw
    # keys are absent. Keys default to "" so a derive-only entry validates.
    rrcenc_key: str = ""
    upenc_key: str = ""
    kasme: str | None = None
    nas_count: int | None = None
    kenb: str | None = None
    cipher_algo: str = "EEA2"
    integ_algo: str = "EIA2"


class _DecryptBody(BaseModel):
    path: str
    entries: list[_DecryptEntryBody]


@app.post("/api/captures/decrypt")
async def decrypt_capture(body: _DecryptBody) -> dict[str, Any]:
    """Post-capture PDCP decryption: per-RNTI keys -> readable decode + keyed
    pcap + .uat sidecar. tshark/IO is blocking, so run it off the event loop.
    Validation/tshark failures return ok=False (not a 500)."""
    cfg = config_mod.load()
    entries = [e.model_dump() for e in body.entries]
    return await asyncio.to_thread(captures_mod.decrypt_pcap, cfg, body.path, entries)


class _DeriveBody(BaseModel):
    kasme: str | None = None
    nas_count: int | None = None
    kenb: str | None = None
    cipher_algo: str = "EEA2"
    integ_algo: str = "EIA2"


@app.post("/api/keys/derive")
async def derive_keys(body: _DeriveBody) -> dict[str, Any]:
    """Derive the access-stratum keys (K_RRCenc/int, K_UPenc/int) from
    K_ASME + NAS uplink COUNT, or from a K_eNB directly (3GPP TS 33.401).
    Returns ok=False with an error message on bad input rather than a 500."""
    import keyderiv
    try:
        d = keyderiv.derive_keys(
            kasme=body.kasme, nas_count=body.nas_count, kenb=body.kenb,
            cipher_algo=body.cipher_algo, integ_algo=body.integ_algo,
        )
        return {"ok": True, "error": None, **d}
    except ValueError as e:
        return {"ok": False, "error": str(e)}


class _OrganizeEntryBody(BaseModel):
    # rnti optional: in auto mode keys are matched to UEs heuristically.
    # Keys may be given directly or derived from K_eNB / (K_ASME + NAS count).
    rnti: int | None = None
    rrcenc_key: str = ""
    upenc_key: str = ""
    kasme: str | None = None
    nas_count: int | None = None
    kenb: str | None = None
    cipher_algo: str = "EEA2"
    integ_algo: str = "EIA2"


class _OrganizeBody(BaseModel):
    path: str
    entries: list[_OrganizeEntryBody] = []
    mode: str = "auto"  # "auto" | "per-rnti"


@app.post("/api/captures/organize")
async def organize_session(body: _OrganizeBody) -> dict[str, Any]:
    """Build a per-session folder: full pcap + one sub-pcap per UE named by
    TMSI/IMSI (else RNTI). Keys (optional) are matched to UEs in 'auto' mode by
    best clean-decode heuristic, or by RNTI in 'per-rnti' mode. tshark/IO is
    blocking → run off the event loop; failures return ok=False (not a 500)."""
    cfg = config_mod.load()
    entries = [e.model_dump() for e in body.entries]
    return await asyncio.to_thread(
        captures_mod.organize_session, cfg, body.path, entries, body.mode
    )


@app.websocket("/api/events")
async def events_ws(ws: WebSocket) -> None:
    # Auth check BEFORE accept(): we don't want to give an unauthed peer a
    # 101 upgrade response with our subprotocol/server info. The browser
    # auto-sends the same-origin session cookie on WS upgrade, so this
    # works without any URL-side token.
    if not await require_session_ws(ws):
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


# --- Wireshark live-stream launcher ------------------------------------------
#
# `wireshark -k -i <fifo>` opens Wireshark and starts capturing immediately
# on the named pipe. Pairs with the cfg.pcap_stream_fifo / LTESNIFFER_PCAP_STREAM
# wiring on the C++ side so MAC PDUs are dissected as they are written.

@app.post("/api/wireshark/open")
async def open_wireshark() -> dict[str, Any]:
    cfg = config_mod.load()
    if not cfg.pcap_stream_fifo:
        raise HTTPException(
            400,
            "No pcap_stream_fifo set in config. Pick a path on the Config page "
            "(e.g. /tmp/lte.pcap) and Save first.",
        )
    if not shutil.which("wireshark"):
        raise HTTPException(404, "wireshark not on PATH. Install with: sudo apt install wireshark")
    # dumpcap is what Wireshark spawns under the hood to read from interfaces
    # (incl. FIFOs). On Debian/Ubuntu it's mode 0754 group=wireshark, so the
    # invoking user must be in the wireshark group OR dumpcap must have the
    # right caps + be world-executable. Detect this up-front and surface a
    # clear fix — otherwise Wireshark opens, fails internally, and the user
    # just sees a cryptic GUI dialog ("Couldn't run /usr/bin/dumpcap in
    # child process: Permission denied").
    dumpcap = shutil.which("dumpcap") or "/usr/bin/dumpcap"
    if os.path.exists(dumpcap) and not os.access(dumpcap, os.X_OK):
        raise HTTPException(
            403,
            f"dumpcap ({dumpcap}) is not executable by the backend user. "
            "Wireshark would die inside with 'Couldn't run dumpcap'. Fix:\n\n"
            "  sudo usermod -aG wireshark $USER\n"
            "  # then log out + back in, and restart the GUI backend\n\n"
            "Or run:  sudo dpkg-reconfigure wireshark-common  (answer YES)."
        )
    disp = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    if not disp:
        raise HTTPException(
            400,
            "No $DISPLAY on the backend host; Wireshark needs a desktop session.",
        )
    # Make sure the FIFO exists *before* Wireshark opens it (Wireshark blocks
    # on open until a writer connects, which is exactly what we want — but it
    # needs the path to exist first).
    try:
        sniffer_mod._ensure_stream_fifo(cfg.pcap_stream_fifo)
    except (PermissionError, OSError) as e:
        raise HTTPException(400, f"pcap_stream_fifo rejected: {e}")
    proc = await asyncio.create_subprocess_exec(
        "wireshark", "-k", "-i", cfg.pcap_stream_fifo,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return {"ok": True, "pid": proc.pid, "fifo": cfg.pcap_stream_fifo}


# --- User guide (auth-free; it's the same content as on disk in the repo) ----

_USER_GUIDE = Path(__file__).resolve().parent.parent / "USER_GUIDE.txt"

@app.get("/api/help", response_class=PlainTextResponse)
async def help_text() -> PlainTextResponse:
    if not _USER_GUIDE.exists():
        raise HTTPException(404, f"USER_GUIDE.txt not found at {_USER_GUIDE}")
    return PlainTextResponse(_USER_GUIDE.read_text(encoding="utf-8"))


# --- Static frontend (served only if `npm run build` has been run) ----------

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str) -> FileResponse:
        # no-store on the HTML so a fresh tab always picks up new hashed JS;
        # the /assets/* files are content-hashed and safe to cache normally.
        index = FRONTEND_DIST / "index.html"
        return FileResponse(index, headers={"Cache-Control": "no-store, must-revalidate"})
