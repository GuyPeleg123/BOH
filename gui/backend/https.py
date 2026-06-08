"""Self-signed TLS cert + key generation for the GUI's HTTPS bind.

The GUI is a single-host LAN tool, so a publicly-signed cert would be
overkill (and impossible without a public DNS name). Instead we generate
a self-signed RSA-2048 cert on first start, valid for 365 days, with the
backend's bind address baked into both the CN and a SubjectAltName so
modern browsers don't reject it outright.

Cert/key live at:
  ~/.config/ltesniffer-gui/cert.pem  (public — 0644)
  ~/.config/ltesniffer-gui/key.pem   (private — 0600)

The operator accepts the self-signed warning in Firefox once; subsequent
visits are silent until cert expiry. To force regeneration, delete both
files and restart the backend.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


_CONFIG_DIR = (Path.home() / ".config" / "ltesniffer-gui").resolve()
CERT_PATH = _CONFIG_DIR / "cert.pem"
KEY_PATH  = _CONFIG_DIR / "key.pem"


def _build_san(bind_ip: str) -> x509.SubjectAlternativeName:
    """Subject Alt Names: the configured IP + always loopback + always
    'localhost'. Without SAN the browser ignores CN entirely (RFC 2818
    was deprecated by RFC 6125 — Chrome/Firefox enforce SAN-only now)."""
    sans: list[x509.GeneralName] = [x509.DNSName("localhost")]
    # 127.0.0.1 is always a valid path to ourselves; include it so a curl
    # from the same box works without --resolve gymnastics.
    sans.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address(bind_ip)))
    except (ValueError, ipaddress.AddressValueError):
        # bind_ip was a hostname, not an IP — treat as DNS SAN.
        if bind_ip and bind_ip != "localhost":
            sans.append(x509.DNSName(bind_ip))
    return x509.SubjectAlternativeName(sans)


def _generate(cert_path: Path, key_path: Path, bind_ip: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, bind_ip or "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LTESniffer GUI (self-signed)"),
    ])
    now = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))   # small backdate avoids clock-skew rejects
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(_build_san(bind_ip), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # key.pem must be 0600 — leaking the private key defeats the entire point.
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(key_path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    # cert.pem is public — 0644 is fine.
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    fd = os.open(cert_path, flags, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(cert_pem)
    try:
        os.chmod(cert_path, 0o644)
    except OSError:
        pass


def load_or_create_cert(bind_ip: str, cert_path: Path = CERT_PATH, key_path: Path = KEY_PATH) -> tuple[Path, Path]:
    """Ensure cert+key exist on disk for `bind_ip`. Returns (cert_path, key_path).

    If either file is missing, both are regenerated together — the cert's
    SAN is keyed to bind_ip, so re-running the backend on a different IP
    requires a regen anyway. Operator-driven regen: delete the files and
    restart.
    """
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    _generate(cert_path, key_path, bind_ip)
    return cert_path, key_path
