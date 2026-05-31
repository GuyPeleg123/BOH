"""PDCP decryption keys persistence.

Operator-facing pydantic model (KeyEntry) is friendlier than the raw
flat-string JSON LTESniffer expects via -K. We serialize to the C++ format
on save and reverse the mapping on load.

File format (what LTESniffer reads — gui/backend/keys.py controls it; see
src/include/KeyAttaching.h for the parser contract):

    [
      { "rnti":"0x1234",
        "kenb":"<64 hex>"            // OR  "kasme":"<64 hex>" + "nas_count":"<int>"
        "cipher_algo":"EEA2",         // optional
        "integ_algo":"EIA2",          // optional
        "hfn_hint":"0"                // optional
      },
      ...
    ]
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


_KEYS_DIR = (Path.home() / ".config" / "ltesniffer-gui").resolve()
KEYS_PATH = _KEYS_DIR / "keys.json"


def _validate_keys_path(p: Path) -> Path:
    """Refuse paths outside the canonical keys directory and refuse symlinks.

    Without these checks the attacker who can edit the saved keys_file path
    in SnifferConfig can point LTESniffer (running as root via sudo) at
    /etc/shadow or any other root-readable file.
    """
    p = Path(p).expanduser()
    # Resolve via the parent so a non-existent leaf file is OK, but any symlink
    # along the way (including parent components) is collapsed and checked.
    resolved = (p.parent.resolve() / p.name)
    try:
        resolved.relative_to(_KEYS_DIR)
    except ValueError:
        raise PermissionError(
            f"keys_file '{p}' is outside the allowed directory {_KEYS_DIR}"
        )
    # If the file already exists and is a symlink, refuse.
    if resolved.is_symlink():
        raise PermissionError(f"keys_file '{p}' is a symlink; refusing")
    return resolved


HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


CipherAlgo = Literal["EEA0", "EEA1", "EEA2", "EEA3"]
IntegAlgo  = Literal["EIA0", "EIA1", "EIA2", "EIA3"]


class KeyEntry(BaseModel):
    rnti: int = Field(..., ge=0, le=0xFFFF, description="UE radio temp ID, 0..65535")
    kenb: Optional[str] = Field(None, description="K_eNB as 64 hex characters")
    kasme: Optional[str] = Field(None, description="KASME as 64 hex characters")
    nas_count: Optional[int] = Field(None, ge=0, description="NAS uplink count at attach")
    cipher_algo: Optional[CipherAlgo] = None
    integ_algo: Optional[IntegAlgo] = None
    hfn_hint: int = Field(0, ge=0, description="Starting HFN guess for mid-session join")
    label: Optional[str] = Field(None, description="Operator-friendly label, e.g. UE phone model")

    @model_validator(mode="after")
    def _validate(self) -> "KeyEntry":
        if self.kenb is not None and self.kenb != "":
            if not HEX64.match(self.kenb):
                raise ValueError("kenb must be exactly 64 hex characters")
        if self.kasme is not None and self.kasme != "":
            if not HEX64.match(self.kasme):
                raise ValueError("kasme must be exactly 64 hex characters")
        has_kenb  = bool(self.kenb)
        has_kasme = bool(self.kasme) and self.nas_count is not None
        if not has_kenb and not has_kasme:
            raise ValueError("must supply either 'kenb', or both 'kasme' and 'nas_count'")
        # If algos are partially specified, both or neither
        if (self.cipher_algo is None) != (self.integ_algo is None):
            raise ValueError("specify both cipher_algo and integ_algo, or neither")
        return self


class KeysFile(BaseModel):
    entries: list[KeyEntry] = Field(default_factory=list)


def _to_c_format(entries: list[KeyEntry]) -> list[dict]:
    """Render to the flat-string JSON the C++ parser expects."""
    out: list[dict] = []
    for e in entries:
        d: dict[str, str] = {"rnti": f"0x{e.rnti:04x}"}
        if e.kenb:
            d["kenb"] = e.kenb
        if e.kasme:
            d["kasme"] = e.kasme
        if e.nas_count is not None:
            d["nas_count"] = str(e.nas_count)
        if e.cipher_algo:
            d["cipher_algo"] = e.cipher_algo
        if e.integ_algo:
            d["integ_algo"] = e.integ_algo
        if e.hfn_hint:
            d["hfn_hint"] = str(e.hfn_hint)
        if e.label:
            # The C++ parser ignores unknown keys (KeyAttaching.cc:160-258 only
            # looks up rnti/kenb/kasme/nas_count/hfn_hint/cipher_algo/integ_algo),
            # so persisting `label` here is round-trip safe AND keeps the
            # operator-friendly hint visible after a reload — without it,
            # _from_c_format returned None and the UI lost the label.
            d["label"] = e.label
        out.append(d)
    return out


def _from_c_format(raw: list[dict]) -> list[KeyEntry]:
    """Best-effort reverse of `_to_c_format` for files written by us or by a
    user editing them by hand."""
    out: list[KeyEntry] = []
    for d in raw:
        try:
            rnti_str = str(d.get("rnti", "0"))
            rnti = int(rnti_str, 0)  # accepts "0x1234" or "4660"
            nas_count_raw = d.get("nas_count")
            entry = KeyEntry(
                rnti=rnti,
                kenb=d.get("kenb") or None,
                kasme=d.get("kasme") or None,
                nas_count=int(nas_count_raw) if nas_count_raw not in (None, "") else None,
                cipher_algo=d.get("cipher_algo") or None,
                integ_algo=d.get("integ_algo") or None,
                hfn_hint=int(d.get("hfn_hint") or 0),
                label=d.get("label") or None,
            )
            out.append(entry)
        except Exception:
            # Skip malformed entries silently — the UI shows what loaded successfully.
            continue
    return out


def load(path: Path = KEYS_PATH) -> KeysFile:
    if not path.exists():
        return KeysFile()
    try:
        raw = json.loads(path.read_text())
    except Exception:
        return KeysFile()
    if isinstance(raw, dict) and "entries" in raw:
        # Already in our pydantic shape (e.g. round-tripped via PUT).
        try:
            return KeysFile.model_validate(raw)
        except Exception:
            return KeysFile()
    if isinstance(raw, list):
        return KeysFile(entries=_from_c_format(raw))
    return KeysFile()


def save(keys: KeysFile, path: Path = KEYS_PATH) -> Path:
    """Write the file in the C++-compatible flat-string array format.
    Returns the absolute path actually written.

    Raises PermissionError if the path escapes the canonical keys directory
    or is a symlink.
    """
    path = _validate_keys_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = _to_c_format(keys.entries)
    # O_NOFOLLOW on the open so a TOCTOU symlink swap can't redirect the write.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(payload, indent=2) + "\n")
    finally:
        # If we already wrote, chmod is redundant; this catches umask anomalies.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path
