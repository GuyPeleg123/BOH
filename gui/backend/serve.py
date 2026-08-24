#!/usr/bin/env python3
"""One-command launcher for the LTESniffer GUI.

Auto-generates the self-signed TLS cert (if missing) and the bcrypt-hashed
credentials file (if missing), prints the banner, then runs uvicorn on
the autodetected LAN IP over HTTPS. The first-time launch is the only
chance to see the generated password — read stderr.

Usage:
  .venv/bin/python serve.py                  # auto IP, port 8443
  .venv/bin/python serve.py --port 9999      # custom port
  LTESNIFFER_GUI_BIND=10.0.0.5 .venv/bin/python serve.py   # force IP

To rotate credentials: delete ~/.config/ltesniffer-gui/auth.json and restart.
To rotate cert (e.g. moved to a new LAN IP): delete cert.pem + key.pem.
"""

import argparse
import sys

import uvicorn

import auth
import https as https_mod


def main() -> int:
    p = argparse.ArgumentParser(description="LTESniffer GUI launcher (HTTPS + Basic Auth)")
    p.add_argument("--port", type=int, default=8443, help="HTTPS port (default: 8443)")
    p.add_argument("--host", default=auth.BIND,
                   help=f"Bind address (default: autodetected LAN IP, currently {auth.BIND}). "
                        "Use 127.0.0.1 to restrict to loopback, or 0.0.0.0 to listen on every interface.")
    args = p.parse_args()

    # Materialize cert + key BEFORE uvicorn opens the files. Both cert
    # generation and credentials creation are idempotent — they only
    # write when the corresponding file is missing.
    cert_path, key_path = https_mod.load_or_create_cert(args.host)

    print(f"[serve] cert={cert_path}", file=sys.stderr)
    print(f"[serve] key ={key_path}", file=sys.stderr)
    print(f"[serve] binding https://{args.host}:{args.port}/", file=sys.stderr)
    print("[serve] (if creds were freshly generated they printed above; capture them now)",
          file=sys.stderr, flush=True)

    uvicorn.run(
        "main:app",
        host=args.host,
        port=args.port,
        ssl_keyfile=str(key_path),
        ssl_certfile=str(cert_path),
        # uvicorn picks reasonable TLS defaults (TLS 1.2+ via OpenSSL); we
        # don't lock ciphers here because cert.pem regeneration is the only
        # security knob the operator needs to touch.
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
