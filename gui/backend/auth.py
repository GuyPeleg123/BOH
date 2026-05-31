"""HTTP Basic Auth over HTTPS for the GUI's REST + WebSocket endpoints.

Replaces the previous bearer-token-in-URL model. The browser handles the
auth UI natively (native username/password dialog on first visit), and
the same Authorization header is auto-included on every subsequent
request — REST and WebSocket — to the same origin.

Threat model: GUI binds an LTESNIFFER_GUI_BIND-detected LAN IP. Every
request (loopback included) requires a valid `Authorization: Basic`
header. No tokens-in-URL means nothing leaks via shoulder-surf, browser
history, or referer headers. TLS prevents the bcrypt-protected password
from going over the wire in cleartext.

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

import base64
import json
import logging
import os
import secrets
import socket
import string
from pathlib import Path
from typing import Optional

import bcrypt
from fastapi import HTTPException, Request, WebSocket


_CONFIG_DIR = (Path.home() / ".config" / "ltesniffer-gui").resolve()
AUTH_PATH = _CONFIG_DIR / "auth.json"

REALM = "LTESniffer GUI"

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


BIND: str = os.environ.get("LTESNIFFER_GUI_BIND") or _autodetect_lan_ip()


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
        " Use these in the Firefox login dialog. To rotate: delete the file and restart.\n"
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
# Basic Auth checks
# ────────────────────────────────────────────────────────────────────────

def _parse_basic(header_value: Optional[str]) -> Optional[tuple[str, str]]:
    """Parse 'Basic <base64>' → (username, password); None on any malformation."""
    if not header_value:
        return None
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(parts[1], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    user, pwd = decoded.split(":", 1)
    return user, pwd


def _verify(user: str, pwd: str) -> bool:
    """Constant-time username compare + bcrypt password verify.

    Constant-time on the username avoids leaking which RNTI of usernames
    are accepted; bcrypt's checkpw is internally constant-time.
    """
    if not secrets.compare_digest(user, _USERNAME):
        # Still hash the password so the wrong-user path takes ~the same
        # time as the right-user-wrong-password path. Defends against
        # username enumeration via timing.
        try:
            bcrypt.checkpw(pwd.encode("utf-8"), _PASSWORD_BCRYPT)
        except ValueError:
            pass
        return False
    try:
        return bcrypt.checkpw(pwd.encode("utf-8"), _PASSWORD_BCRYPT)
    except ValueError:
        return False


def _challenge() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="authentication required",
        headers={"WWW-Authenticate": f'Basic realm="{REALM}", charset="UTF-8"'},
    )


async def require_basic_auth(request: Request) -> None:
    """FastAPI dependency: rejects requests without valid Basic credentials.

    No loopback bypass — even 127.0.0.1 requests must authenticate. The
    backend may run inside containers or behind a local proxy where the
    apparent client host is loopback but the real source isn't; not worth
    the foot-gun.
    """
    parsed = _parse_basic(request.headers.get("authorization"))
    if not parsed or not _verify(parsed[0], parsed[1]):
        raise _challenge()


async def require_basic_auth_ws(ws: WebSocket) -> bool:
    """Equivalent for the WebSocket upgrade.

    Modern browsers auto-include the cached Authorization header on a WS
    upgrade to the same origin where Basic Auth was just satisfied for an
    HTTP request, so this works without a separate auth step.

    Returns True if accepted, else closes the socket with code 4401 (per
    the well-known "auth failed" convention for WS) and returns False.
    """
    parsed = _parse_basic(ws.headers.get("authorization"))
    if parsed and _verify(parsed[0], parsed[1]):
        return True
    await ws.close(code=4401)
    return False


# ────────────────────────────────────────────────────────────────────────
# Public symbols kept stable so main.py imports don't churn
# ────────────────────────────────────────────────────────────────────────

# Back-compat shims for code that still imports TOKEN / require_token. The
# token model is gone; these exist only so import-time fails loudly with a
# clear error rather than via an AttributeError at request time.
TOKEN = None
TOKEN_PATH = AUTH_PATH  # what should appear in error messages / banners
REQUIRE_LOCAL_TOKEN = True  # vestige — always-on auth, no bypass

async def require_token(request: Request) -> None:  # alias for transition
    return await require_basic_auth(request)

async def require_token_ws(ws: WebSocket) -> bool:  # alias for transition
    return await require_basic_auth_ws(ws)
