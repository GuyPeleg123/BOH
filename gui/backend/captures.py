"""Discover, list, and safely serve pcap files for the GUI."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from config import SnifferConfig


# Read-only "well-known" places pcaps tend to live in this user's tree.
# Add to this list rather than allowing arbitrary filesystem access.
EXTRA_ROOTS: list[Path] = [
    Path.home() / "work" / "captures",
    Path.home() / "work" / "LTESniffer" / "pcap_file_example",
]


def _safe_pcap_iter(root: Path) -> Iterable[Path]:
    """Yield pcap files under root, max depth 3, ignoring permission errors."""
    if not root.exists() or not root.is_dir():
        return
    try:
        for p in root.rglob("*.pcap"):
            # Bound depth to avoid wandering off into deep symlink loops
            try:
                rel = p.relative_to(root)
            except ValueError:
                continue
            if len(rel.parts) > 4:
                continue
            yield p
    except (PermissionError, OSError):
        return


def allowed_roots(cfg: SnifferConfig) -> list[Path]:
    """All directories the API is willing to serve pcaps from."""
    roots: list[Path] = []
    captures = Path(cfg.captures_dir).expanduser()
    if captures.exists():
        roots.append(captures.resolve())
    for r in EXTRA_ROOTS:
        if r.exists():
            roots.append(r.resolve())
    return roots


def list_pcaps(cfg: SnifferConfig) -> list[dict]:
    """Return descriptors for every pcap under each allowed root."""
    out: list[dict] = []
    seen: set[Path] = set()
    captures = Path(cfg.captures_dir).expanduser().resolve()
    for root in allowed_roots(cfg):
        for p in _safe_pcap_iter(root):
            rp = p.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            try:
                st = rp.stat()
            except OSError:
                continue
            source = (
                "active capture"
                if rp.parent == captures
                else str(root)
            )
            out.append({
                "path": str(rp),
                "name": rp.name,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "source": source,
                "active": rp.parent == captures,
            })
    out.sort(key=lambda d: d["mtime"], reverse=True)
    return out


def resolve_for_download(cfg: SnifferConfig, path: str) -> Path:
    """Resolve `path` and confirm it sits under one of the allowed roots.

    Raises PermissionError if the path escapes every allowed root, or
    FileNotFoundError if the file isn't there.
    """
    p = Path(path).expanduser().resolve()
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(path)
    if p.suffix.lower() != ".pcap":
        # Limit downloads to pcaps so a path-traversal can't leak /etc/passwd
        # even if the allowed-roots check has a bug.
        raise PermissionError("only .pcap files can be downloaded")
    for root in allowed_roots(cfg):
        try:
            p.relative_to(root)
            return p
        except ValueError:
            continue
    raise PermissionError(f"{p} is outside the allowed roots")
