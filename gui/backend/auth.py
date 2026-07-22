"""Session-cookie authentication for the GUI's REST + WebSocket endpoints.

The login UX is an in-app React form (not the browser's native Basic Auth
popup). The form POSTs username + password to /api/login; the server
verifies bcrypt-hashed credentials from disk and replies with a
Set-Cookie: ltesniffer_session=<token>; HttpOnly; Secure; SameSite=Strict.

Subsequent requests — REST AND WebSocket — auto-include the cookie because
the browser sends cookies on same-origin requests. WebSocket upgrades to
the same origin include cookies too (this is the whole reason we picked
cookie auth instead of putting a token in the URL).

Threat model: GUI binds an LTESNIFFER_GUI_BIND-detected LAN IP. Every
request (loopback included) requires a valid session cookie. The cookie
is HttpOnly so JS can't exfiltrate it via XSS; Secure so it only flows
over TLS; SameSite=Strict so it never leaks via a third-party site.

Credentials live at:
  ~/.config/ltesniffer-gui/auth.json    (mode 0600)

JSON shape:
  { "username": "admin", "password_bcrypt": "$2b$12$..." }

On first start the file is auto-generated with username=admin and a
24-character random password. The plaintext password is printed ONCE
to stderr with a banner; after that, the operator either remembers it,
records it somewhere safe, or regenerates by deleting auth.json.

Custom initial credentials: set LTESNIFFER_GUI_USER and
LTESNIFFER_GUI_PASS env vars on first start. They're consumed once
(written to auth.json as a bcrypt hash), then ignored.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import string
import time
from pathlib import Path
from typing import Optional

import bcrypt
from fastapi import HTTPException, Request, WebSocket


_CONFIG_DIR = (Path.home() / ".config" / "ltesniffer-gui").resolve()
AUTH_PATH = _CONFIG_DIR / "auth.json"

# Cookie name + sliding-window TTL. In-memory store — server restart kicks
# everyone out, which is fine for self-hosted gear (and removes any need
# for a session-revocation mechanism: a restart IS the revocation).
COOKIE_NAME    = "ltesniffer_session"
SESSION_TTL_S  = 8 * 60 * 60   # 8 hours of inactivity → expire
SESSION_RENEW_THRESHOLD_S = 60  # only update last_seen if >60s since last update (avoid mutex thrash)

log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────
# Bind address — autodetect LAN IP, with env override
# ────────────────────────────────────────────────────────────────────────

def _autodetect_lan_ip() -> str:
    """Pick the IP the OS would use to reach the public internet — that's
    almost always the LAN-facing one, even on a multi-NIC box.

    Returns "127.0.0.1" if we can't figure it out (no network), which
    keeps the backend startable in airplane mode."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))  # UDP — no packet actually sent
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def _resolve_bind() -> str:
    """Default to loopback. The GUI is a root-capable admin/capture console;
    it must not be reachable from the LAN unless the operator explicitly opts in.
    - LTESNIFFER_GUI_BIND=<ip>  : explicit bind (warned if not loopback)
    - LTESNIFFER_GUI_LAN=1       : auto-pick the LAN IP (warned)
    - otherwise                  : 127.0.0.1
    """
    env = os.environ.get("LTESNIFFER_GUI_BIND")
    if env:
        if env not in ("127.0.0.1", "localhost", "::1"):
            log.warning("LTESNIFFER_GUI_BIND=%s — admin GUI reachable beyond loopback!", env)
        return env
    if os.environ.get("LTESNIFFER_GUI_LAN") == "1":
        ip = _autodetect_lan_ip()
        log.warning("LTESNIFFER_GUI_LAN=1 — binding admin GUI to LAN IP %s (other hosts can reach it)", ip)
        return ip
    return "127.0.0.1"


BIND: str = _resolve_bind()


# ────────────────────────────────────────────────────────────────────────
# Credentials
# ────────────────────────────────────────────────────────────────────────

def _random_password(n: int = 24) -> str:
    # ASCII letters + digits — friendly to type from a phone if needed,
    # and avoids shell-escaping pain when pasting into curl -u.
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _load_or_create_credentials() -> tuple[str, bytes]:
    """Return (username, password_bcrypt). Creates the file on first start.

    Emits a one-shot banner on stderr if the credentials are freshly
    generated — that's the operator's only chance to see the plaintext
    password (after this, only the bcrypt hash is on disk).
    """
    if AUTH_PATH.exists():
        try:
            raw = json.loads(AUTH_PATH.read_text())
            username = raw.get("username") or ""
            hashed_str = raw.get("password_bcrypt") or ""
            if username and hashed_str.startswith("$2"):
                return username, hashed_str.encode("ascii")
        except (OSError, ValueError, KeyError):
            # Corrupt file — regenerate. We'd rather lock the user out of
            # an unparseable creds file than silently honor a no-op auth.
            pass

    env_user = os.environ.get("LTESNIFFER_GUI_USER")
    env_pass = os.environ.get("LTESNIFFER_GUI_PASS")
    username = env_user if env_user else "admin"
    password = env_pass if env_pass else _random_password()

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(AUTH_PATH, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"username": username, "password_bcrypt": hashed.decode("ascii")}, f)
        f.write("\n")
    try:
        os.chmod(AUTH_PATH, 0o600)
    except OSError:
        pass

    # ── ONE-SHOT BANNER ── only chance to see the plaintext password ──
    # stderr only, so it doesn't double up when uvicorn captures both streams.
    import sys as _sys
    banner = (
        "\n" + "═" * 78 + "\n"
        f" LTESniffer GUI — initial credentials generated → {AUTH_PATH}\n"
        f"   username: {username}\n"
        f"   password: {password}\n"
        f" {'(from LTESNIFFER_GUI_USER/PASS env)' if (env_user or env_pass) else '(auto-generated; only shown ONCE)'}\n"
        " Use these in the in-app Login page. To rotate: delete the file and restart.\n"
        + "═" * 78 + "\n"
    )
    try:
        _sys.stderr.write(banner)
        _sys.stderr.flush()
    except Exception:
        pass

    return username, hashed


_USERNAME, _PASSWORD_BCRYPT = _load_or_create_credentials()


# ────────────────────────────────────────────────────────────────────────
# Credential check — only used by /api/login
# ────────────────────────────────────────────────────────────────────────

def verify_credentials(user: str, pwd: str) -> bool:
    """Constant-time username compare + bcrypt password verify.

    Constant-time on the username avoids leaking which usernames are
    accepted via response-timing; bcrypt's checkpw is internally
    constant-time on the password.
    """
    if not secrets.compare_digest(user, _USERNAME):
        # Still hash the supplied password so the wrong-user path takes
        # ~the same time as the right-user-wrong-password path. Defends
        # against username enumeration via timing differences.
        try:
            bcrypt.checkpw(pwd.encode("utf-8"), _PASSWORD_BCRYPT)
        except ValueError:
            pass
        return False
    try:
        return bcrypt.checkpw(pwd.encode("utf-8"), _PASSWORD_BCRYPT)
    except ValueError:
        return False


# ────────────────────────────────────────────────────────────────────────
# Session store (in-memory)
# ────────────────────────────────────────────────────────────────────────
#
# {token: {"username": str, "last_seen": float}}.  Server restart kicks
# everyone out — which is the revocation mechanism. For a self-hosted
# tool that's the right trade-off (no Redis, no DB, no migration).

_SESSIONS: dict[str, dict] = {}


def create_session(username: str) -> str:
    """Mint a new session token. Caller sets it as a cookie on the response."""
    token = secrets.token_urlsafe(32)  # 256-bit, URL-safe
    _SESSIONS[token] = {"username": username, "last_seen": time.time()}
    return token


def drop_session(token: Optional[str]) -> None:
    """Idempotent — safe to call with a stale or unknown token."""
    if token:
        _SESSIONS.pop(token, None)


def session_user(token: Optional[str]) -> Optional[str]:
    """Return the username for a still-valid session token, else None.

    Also enforces idle-expiry (8h sliding window) and updates last_seen
    on the cheap (only when the existing last_seen is stale enough to
    matter, to avoid pointlessly churning the dict on bursty traffic).
    """
    if not token:
        return None
    info = _SESSIONS.get(token)
    if not info:
        return None
    now = time.time()
    if now - info["last_seen"] > SESSION_TTL_S:
        _SESSIONS.pop(token, None)
        return None
    # Sliding renewal — only touch the dict if the last touch was a while ago.
    if now - info["last_seen"] > SESSION_RENEW_THRESHOLD_S:
        info["last_seen"] = now
    return info["username"]


# ────────────────────────────────────────────────────────────────────────
# FastAPI dependencies
# ────────────────────────────────────────────────────────────────────────

async def require_session(request: Request) -> str:
    """Reject requests without a valid session cookie. Returns the username.

    No loopback bypass — every request authenticates. We return JSON 401
    with NO WWW-Authenticate header so the browser does not show its
    native Basic Auth popup (the in-app login form is the only UI).
    """
    user = session_user(request.cookies.get(COOKIE_NAME))
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


async def require_session_ws(ws: WebSocket) -> bool:
    """WebSocket equivalent. Returns True if accepted, else closes the
    socket with code 4401 (well-known 'auth failed' for WS) and returns
    False. The browser auto-sends the same-origin session cookie on the
    WS upgrade, so no separate token-in-URL is needed."""
    if session_user(ws.cookies.get(COOKIE_NAME)):
        return True
    await ws.close(code=4401)
    return False
