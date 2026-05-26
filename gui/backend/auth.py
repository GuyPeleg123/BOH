"""Bearer-token authentication for the GUI's REST + WebSocket endpoints.

Threat model: the GUI is local-first (binds 127.0.0.1 by default). When the
operator explicitly opens it to a LAN with LTESNIFFER_GUI_BIND=0.0.0.0, any
request without a valid bearer token is rejected with 401.

A per-install token is generated on first run and stored at
~/.config/ltesniffer-gui/token (mode 0600). The operator copies it into
their browser via ?token=<hex> URL fragment (the frontend persists it to
localStorage) or via Authorization: Bearer <hex> header for direct curl.

Loopback exception: requests originating from 127.0.0.1 / ::1 bypass the
token check so the local dashboard "just works". The exception is dropped
when LTESNIFFER_GUI_BIND_REQUIRE_TOKEN_LOCAL=1 is set, for paranoia mode.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, Request, WebSocket


TOKEN_PATH = Path.home() / ".config" / "ltesniffer-gui" / "token"


def _load_or_create_token() -> str:
    if TOKEN_PATH.exists():
        try:
            t = TOKEN_PATH.read_text().strip()
            if len(t) >= 32:
                return t
        except OSError:
            pass
    # Generate a fresh 256-bit token; 0600 perms.
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tok = secrets.token_hex(32)  # 64 hex chars = 256 bits
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(TOKEN_PATH, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(tok + "\n")
    try:
        os.chmod(TOKEN_PATH, 0o600)
    except OSError:
        pass
    return tok


TOKEN: str = _load_or_create_token()
BIND: str = os.environ.get("LTESNIFFER_GUI_BIND", "127.0.0.1")
REQUIRE_LOCAL_TOKEN: bool = os.environ.get("LTESNIFFER_GUI_REQUIRE_TOKEN_LOCAL", "").lower() in {"1", "true", "yes"}


def _is_loopback(host: Optional[str]) -> bool:
    if not host:
        return False
    return host in ("127.0.0.1", "::1", "localhost")


def _extract_token(req_headers, query_params) -> Optional[str]:
    """Pull the token from Authorization header or ?token= query string."""
    auth = req_headers.get("authorization") or req_headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip()
    tok = query_params.get("token") if query_params else None
    return tok


async def require_token(request: Request) -> None:
    """FastAPI dependency: rejects requests without a valid bearer token.

    Loopback requests skip the check unless REQUIRE_LOCAL_TOKEN is set.
    """
    client_host = request.client.host if request.client else None
    if _is_loopback(client_host) and not REQUIRE_LOCAL_TOKEN:
        return
    presented = _extract_token(request.headers, request.query_params)
    if presented and secrets.compare_digest(presented, TOKEN):
        return
    raise HTTPException(401, "missing or invalid bearer token (see ~/.config/ltesniffer-gui/token)")


async def require_token_ws(ws: WebSocket) -> bool:
    """Equivalent for WebSocket handshake. Returns True if accepted, else
    closes the socket with code 4401 and returns False."""
    client_host = ws.client.host if ws.client else None
    if _is_loopback(client_host) and not REQUIRE_LOCAL_TOKEN:
        return True
    presented = _extract_token(ws.headers, ws.query_params)
    if presented and secrets.compare_digest(presented, TOKEN):
        return True
    await ws.close(code=4401)
    return False
