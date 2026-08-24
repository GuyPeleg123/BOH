"""Discover, list, and safely serve pcap files for the GUI."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterable

from config import SnifferConfig


# A pcap is "live" only if a capture is currently running AND the file was
# modified within this many seconds. Generous enough for slow networks where
# DCIs are rare, tight enough that an old leftover doesn't claim to be active.
LIVE_MTIME_WINDOW_S = 20.0


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


def list_pcaps(cfg: SnifferConfig, sniffer_running: bool = False) -> list[dict]:
    """Return descriptors for every pcap under each allowed root.

    The `active` / "live capture" badge only lights up when:
      1. the sniffer subprocess is currently running, AND
      2. the pcap lives inside captures_dir, AND
      3. the pcap was modified within LIVE_MTIME_WINDOW_S seconds.
    Without (3), a stale pcap from a previous session that just happens
    to live in captures_dir would forever be tagged "live capture".
    """
    out: list[dict] = []
    seen: set[Path] = set()
    captures = Path(cfg.captures_dir).expanduser().resolve()
    now = time.time()
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
            # The live pcap lands in a per-run SUBDIRECTORY of captures_dir
            # (captures_dir/<run-tag>/ltesniffer_*.pcap), so "directly in
            # captures_dir" missed it — treat anything under the captures tree
            # as a capture-dir file so the active badge actually lights up.
            under_captures = (rp == captures) or (captures in rp.parents)
            fresh = (now - st.st_mtime) <= LIVE_MTIME_WINDOW_S
            active = sniffer_running and under_captures and fresh
            source = "active capture" if active else (
                str(captures) if under_captures else str(root)
            )
            out.append({
                "path": str(rp),
                "name": rp.name,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "source": source,
                "active": active,
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


_PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}


def resolve_input_pcap(cfg: SnifferConfig, path: str) -> Path:
    """Resolve a pcap to ORGANIZE/SPLIT. Unlike resolve_for_download this is
    not limited to the allowed roots — the operator can pick any capture file
    anywhere on the machine (this is an authenticated, local admin GUI). Still
    insists it's an existing pcap-type file, not a directory or arbitrary blob."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(path)
    if not p.is_file():
        raise PermissionError(f"{p} is not a file")
    if p.suffix.lower() not in _PCAP_SUFFIXES:
        raise PermissionError("not a capture file (expected .pcap/.pcapng/.cap)")
    return p


def browse_dir(cfg: SnifferConfig, path: str | None) -> dict:
    """List a directory for the GUI file picker. Defaults to captures_dir.
    Returns subdirectories + capture files so the operator can navigate from
    the pcap folder to anywhere on the machine. Never raises to the caller."""
    res: dict = {"cwd": None, "parent": None, "default": None, "entries": [], "error": None}
    default = Path(cfg.captures_dir).expanduser()
    if not default.exists():
        default = Path.home()
    res["default"] = str(default.resolve())
    try:
        d = (Path(path).expanduser() if path else default).resolve()
        if not d.exists():
            d = default.resolve()
        if not d.is_dir():
            d = d.parent
        res["cwd"] = str(d)
        res["parent"] = str(d.parent) if d.parent != d else None
        entries: list[dict] = []
        for child in sorted(d.iterdir(), key=lambda c: c.name.lower()):
            if child.name.startswith("."):
                continue
            try:
                is_dir = child.is_dir()
            except OSError:
                continue
            if is_dir:
                entries.append({"name": child.name, "path": str(child), "is_dir": True,
                                "size": 0, "is_pcap": False})
            elif child.suffix.lower() in _PCAP_SUFFIXES:
                try:
                    sz = child.stat().st_size
                except OSError:
                    sz = 0
                entries.append({"name": child.name, "path": str(child), "is_dir": False,
                                "size": sz, "is_pcap": True})
        # dirs first, then pcap files
        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        res["entries"] = entries
        return res
    except PermissionError:
        res["error"] = f"permission denied: {path}"; return res
    except Exception as ex:  # noqa: BLE001
        res["error"] = f"{type(ex).__name__}: {ex}"; return res


# ---------------------------------------------------------------------------
# Session organizer: split a whole sniff into a folder of per-UE sub-pcaps
# named by TMSI/IMSI (falling back to RNTI).
# ---------------------------------------------------------------------------

_MIN_FRAMES_PER_UE = 3   # ignore one-hit C-RNTI ghosts from blind search


def _tshark_fields(pcap: Path, dfilter: str, fields: list[str], timeout: int = 120) -> list[list[str]]:
    cmd = ["tshark", "-r", str(pcap)]
    if dfilter:
        cmd += ["-Y", dfilter]
    cmd += ["-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    rows = []
    for line in out.stdout.splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def read_cell_id(pcap: Path, max_packets: int = 20000) -> dict | None:
    """Extract the E-UTRAN Cell Identity (ECI) + eNB-ID/sector + TAC/PLMN from the
    most recent SIB1 in a pcap. This is what identifies WHICH cell/tower you are
    on (PCI only labels the physical layer and is widely reused).

    Bounded read (`-c`): SIB1 broadcasts from the moment the cell locks, so it is
    among the earliest frames — no need to scan a long/live pcap. Returns None if
    no SIB1 has been decoded yet."""
    cmd = ["tshark", "-r", str(pcap), "-c", str(max_packets),
           "-Y", "lte-rrc.systemInformationBlockType1_element", "-T", "fields",
           "-e", "lte-rrc.cellIdentity", "-e", "lte-rrc.trackingAreaCode",
           "-e", "lte-rrc.MCC_MNC_Digit"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return None
    last = None
    for line in out.stdout.splitlines():
        c = (line.split("\t") + ["", "", ""])[:3]
        ci = c[0].split(",")[0].strip()
        if ci:  # keep the most recent SIB1 with a cell identity
            last = (ci, c[1].split(",")[0].strip(), c[2].strip())
    if not last:
        return None
    ci_hex, tac_hex, digits = last
    try:
        eci = int(ci_hex, 16)
    except ValueError:
        return None
    try:
        tac_dec = int(tac_hex, 16) if tac_hex else None
    except ValueError:
        tac_dec = None
    # SIB1 plmn-IdentityList is a flat digit list (MCC=3 + MNC=2 per PLMN). Take
    # the FIRST PLMN, 2-digit MNC (the common case outside North America).
    d = [x for x in digits.split(",") if x.strip().isdigit()]
    mcc = "".join(d[0:3]) if len(d) >= 3 else None
    mnc = "".join(d[3:5]) if len(d) >= 5 else None
    # ECI (28-bit) = eNB-ID (top 20 bits) · Cell/sector (low 8 bits), per TS 36.413.
    return {
        "cell_identity": f"0x{eci:07X}",
        "eci": eci,
        "enb_id": eci >> 8,
        "enb_id_hex": f"0x{eci >> 8:X}",
        "sector": eci & 0xFF,
        "tac": tac_dec,
        "tac_hex": f"0x{tac_dec:04X}" if tac_dec is not None else None,
        "mcc": mcc,
        "mnc": mnc,
        "plmn": (mcc + mnc) if (mcc and mnc) else None,
    }


def _rnti_identity_map(pcap: Path) -> dict:
    """Best-effort rnti -> identity label ('imsi-<v>' / 'tmsi-<v>') from cleartext
    RRC in the pcap and a sibling sniffer.log API table. Empty if none found."""
    m: dict = {}
    # (1) RRC Connection Request carrying s-TMSI on the UE's (temp) C-RNTI
    try:
        for r in _tshark_fields(pcap,
                                "lte-rrc.rrcConnectionRequest_element and lte-rrc.m_TMSI",
                                ["mac-lte.rnti", "lte-rrc.m_TMSI"]):
            if len(r) >= 2 and r[0] and r[1]:
                rnti = int(r[0]); tmsi = r[1].split(",")[0]
                if 0x3D <= rnti <= 0xFFF3:
                    m.setdefault(rnti, f"tmsi-{tmsi}")
    except Exception:
        pass
    # (2) sibling sniffer.log API identity table (RNTI-mapped, from -z modes)
    log = pcap.parent / "sniffer.log"
    if log.exists():
        try:
            started = False
            for line in log.read_text(errors="ignore").splitlines():
                if "Detected Identity" in line:
                    started = True
                    continue
                if not started:
                    continue
                low = line.lower()
                kind = "imsi" if "imsi" in low else ("tmsi" if "tmsi" in low else None)
                if not kind:
                    continue
                # tokens: pick the long id value and a plausible C-RNTI int
                toks = line.split()
                value = next((t for t in toks if len(t) >= 8 and all(c in "0123456789abcdefABCDEF" for c in t)), None)
                rnti = next((int(t) for t in toks if t.isdigit() and 0x3D <= int(t) <= 0xFFF3), None)
                if value and rnti is not None:
                    m[rnti] = f"{kind}-{value}"  # imsi/explicit map wins over the tmsi guess
        except Exception:
            pass
    return m


def _safe_label(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)[:48]


def organize_session(cfg: SnifferConfig, input_path: str) -> dict:
    """Build a session folder: the full pcap + one sub-pcap per UE (recurring
    C-RNTI), named by TMSI/IMSI when known else by RNTI. Cleartext only — no
    key/decrypt step. Returns a structured manifest (never raises to the caller)."""
    res: dict = {"ok": False, "error": None, "folder": None, "ues": [], "note": None}
    try:
        src = resolve_input_pcap(cfg, input_path)
    except FileNotFoundError:
        res["error"] = "input pcap not found"; return res
    except PermissionError as e:
        res["error"] = str(e); return res
    if not shutil.which("tshark"):
        res["error"] = "tshark not found on PATH"; return res

    stem, d = src.stem, src.parent
    folder = d / f"{stem}_session"
    try:
        folder.mkdir(exist_ok=True)
        # Full pcap copy: byte-identical to the source, so its frame numbers are
        # the same indices as the original dual-sniff capture.
        full = folder / f"{stem}_full.pcap"
        shutil.copy(src, full)

        idmap = _rnti_identity_map(full)

        # recurring C-RNTIs only (skip SI/P/RA and one-hit ghosts) — PLUS any
        # RNTI we recovered an identity for, even a single-frame one: a UE that
        # announced its TMSI/IMSI is real, not a blind-search ghost.
        counts: dict = {}
        for r in _tshark_fields(full, "mac-lte", ["mac-lte.rnti", "mac-lte.rnti-type"]):
            if len(r) >= 2 and r[0] and r[1] == "3":
                rnti = int(r[0]); counts[rnti] = counts.get(rnti, 0) + 1
        keep = {rn for rn, c in counts.items() if c >= _MIN_FRAMES_PER_UE}
        keep |= {rn for rn in idmap if rn in counts}
        rntis = sorted(keep, key=lambda rn: counts.get(rn, 0), reverse=True)[:64]

        for rnti in rntis:
            ident = idmap.get(rnti)
            label = _safe_label(ident) if ident else f"rnti-{rnti:04x}"
            # Append the original-capture packet index range, e.g.
            # ue_rnti-1a2b_packets_2034-2042.pcap.
            _n, _lo, _hi = _frame_range(full, [], f"mac-lte.rnti=={rnti}")
            rng = f"_packets_{_lo}-{_hi}" if _n > 0 else ""
            sub = folder / f"ue_{label}{rng}.pcap"
            subprocess.run(["tshark", "-r", str(full), "-Y", f"mac-lte.rnti=={rnti}", "-w", str(sub)],
                           capture_output=True, text=True, timeout=180)
            ue = {"rnti": rnti, "rnti_hex": f"0x{rnti:04X}", "identity": ident,
                  "frames": counts[rnti], "sub_pcap": str(sub)}
            res["ues"].append(ue)

        named = sum(1 for u in res["ues"] if u["identity"])
        if res["ues"] and named == 0:
            res["note"] = ("No UE identities (TMSI/IMSI) were recoverable from this capture — "
                           "sub-pcaps are named by RNTI. Run with API mode (-z) and capture RRC "
                           "Connection Requests / paging to get identity names.")
        # session manifest
        import json as _json
        (folder / "session.json").write_text(_json.dumps({"source": str(src), "ues": res["ues"]}, indent=2))
        res["folder"] = str(folder)
        res["ok"] = True
        return res
    except subprocess.TimeoutExpired:
        res["error"] = "tshark timed out"; return res
    except Exception as ex:  # noqa: BLE001
        res["error"] = f"{type(ex).__name__}: {ex}"; return res


# ---------------------------------------------------------------------------
# Modular capture splitting
#
# Partition a capture into sub-pcaps along one or more ordered "dimensions".
# Each dimension yields a list of (bucket_label, tshark_filter); nesting ANDs
# the filters down a folder tree. Adding a new way to split = one entry in
# _SPLIT_DIMS.
# ---------------------------------------------------------------------------
_SPLIT_MAX_LEAVES = 300          # hard cap on output pcaps to avoid blow-ups
_SPLIT_RNTI_CAP = 64             # most-active C-RNTIs to keep for rnti/identity


def _dim_rnti(ctx) -> list[tuple[str, str]]:
    counts = ctx["rnti_counts"]
    rntis = sorted(counts, key=lambda r: counts[r], reverse=True)[:_SPLIT_RNTI_CAP]
    return [(f"rnti-{r:04x}", f"mac-lte.rnti=={r}") for r in rntis]


def _dim_identity(ctx) -> list[tuple[str, str]]:
    idmap, counts = ctx["idmap"], ctx["rnti_counts"]
    groups: dict[str, list[int]] = {}
    for r in sorted(counts, key=lambda r: counts[r], reverse=True)[:_SPLIT_RNTI_CAP]:
        ident = idmap.get(r)
        label = _safe_label(ident) if ident else f"rnti-{r:04x}"
        groups.setdefault(label, []).append(r)
    out = []
    for label, rs in groups.items():
        filt = " or ".join(f"mac-lte.rnti=={r}" for r in rs)
        out.append((label, f"({filt})"))
    return out


def _dim_direction(ctx) -> list[tuple[str, str]]:
    return [("DL", "mac-lte.direction==1"), ("UL", "mac-lte.direction==0")]


def _dim_rnti_class(ctx) -> list[tuple[str, str]]:
    return [("broadcast-SI", "mac-lte.rnti-type==4"),
            ("paging-P", "mac-lte.rnti-type==1"),
            ("rach-RA", "mac-lte.rnti-type==2"),
            ("ue-C", "mac-lte.rnti-type==3")]


def _dim_packet_type(ctx) -> list[tuple[str, str]]:
    # Buckets may overlap (NAS rides inside RRC) — a frame lands in each it matches.
    return [("rrc", "lte_rrc"), ("nas", "nas-eps"), ("ip", "ip"),
            ("rar", "mac-lte.rar"), ("mac-control", "mac-lte.control")]


def _dim_security(ctx) -> list[tuple[str, str]]:
    decoded = "(lte_rrc or nas-eps or ip)"
    return [("cleartext", f"pdcp-lte and {decoded}"),
            ("ciphered", f"pdcp-lte and not {decoded}")]


_SPLIT_DIMS = {
    "rnti":        {"label": "RNTI (per connection)",      "fn": _dim_rnti},
    "identity":    {"label": "UE identity (TMSI/IMSI)",    "fn": _dim_identity},
    "direction":   {"label": "Direction (UL/DL)",          "fn": _dim_direction},
    "rnti_class":  {"label": "RNTI class (SI/P/RA/UE)",    "fn": _dim_rnti_class},
    "packet_type": {"label": "Packet type (RRC/NAS/IP/…)", "fn": _dim_packet_type},
    "security":    {"label": "Cleartext vs ciphered",      "fn": _dim_security},
}


def split_dimensions() -> list[dict]:
    """Public catalog of split dimensions, for the GUI."""
    return [{"id": k, "label": v["label"]} for k, v in _SPLIT_DIMS.items()]


def _build_split_ctx(full: Path) -> dict:
    counts: dict = {}
    for r in _tshark_fields(full, "mac-lte", ["mac-lte.rnti", "mac-lte.rnti-type"]):
        if len(r) >= 2 and r[0] and r[1] == "3":
            rn = int(r[0]); counts[rn] = counts.get(rn, 0) + 1
    idmap = _rnti_identity_map(full)
    keep = {rn for rn, c in counts.items() if c >= _MIN_FRAMES_PER_UE} | {rn for rn in idmap if rn in counts}
    return {"rnti_counts": {rn: counts[rn] for rn in keep}, "idmap": idmap}


# MAC→PDCP dissection prefs so the packet_type / security dimensions can classify
# frames (cleartext SRB SDUs → RRC, user-plane → IP). No keys / no deciphering:
# ciphered frames stay ciphered and fall into the "ciphered" bucket.
_DISSECT_OARGS = [
    "-o", "pdcp-lte.show_user_plane_as_ip:TRUE", "-o", "mac-lte.attempt_to_dissect_srb_sdus:TRUE",
]


def _count_pcap(p: Path) -> int:
    out = subprocess.run(["tshark", "-r", str(p), "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True, timeout=180)
    return len([x for x in out.stdout.splitlines() if x.strip()])


def _frame_range(p: Path, oargs: list, filt: str):
    """Original-capture packet indices matching `filt` in `p`. `p` is the
    byte-identical <stem>_full.pcap, so its frame numbers are the same indices
    as the original dual-sniff capture. Returns (count, first, last); tshark
    emits frame.number in capture order so first<=last. (oargs must match the
    write so content-based filters like lte_rrc resolve identically.)"""
    out = subprocess.run(["tshark", "-r", str(p), *oargs, "-Y", filt,
                          "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True, timeout=180)
    nums = [int(x) for x in out.stdout.split() if x.strip().isdigit()]
    if not nums:
        return (0, None, None)
    return (len(nums), nums[0], nums[-1])


def _split_partition(full: Path, parent: Path, dims: list[str], depth: int, acc: str,
                     ctx: dict, oargs: list[str], res: dict, budget: list[int]) -> None:
    last = depth == len(dims) - 1
    for label, filt in _SPLIT_DIMS[dims[depth]]["fn"](ctx):
        if budget[0] <= 0:
            return
        combined = filt if not acc else f"({acc}) and ({filt})"
        if last:
            # Original-capture packet index range for this bucket (frame numbers
            # in <stem>_full.pcap == indices in the original dual-sniff pcap),
            # appended to the filename, e.g. rnti-1a2b_packets_2034-2042.pcap.
            n, lo, hi = _frame_range(full, oargs, combined)
            if n > 0:
                out = parent / f"{_safe_label(label)}_packets_{lo}-{hi}.pcap"
                subprocess.run(["tshark", "-r", str(full), *oargs, "-Y", combined, "-w", str(out)],
                               capture_output=True, text=True, timeout=300)
                res["files"].append({"path": str(out), "frames": n, "filter": combined,
                                     "pkt_first": lo, "pkt_last": hi})
                budget[0] -= 1
        else:
            sub = parent / _safe_label(label)
            sub.mkdir(exist_ok=True)
            before = len(res["files"])
            _split_partition(full, sub, dims, depth + 1, combined, ctx, oargs, res, budget)
            if len(res["files"]) == before:
                try: sub.rmdir()
                except OSError: pass


def split_capture(cfg: SnifferConfig, input_path: str, dims: list[str]) -> dict:
    """Partition a capture into nested sub-pcaps along the ordered `dims`.
    Returns a manifest (never raises to the caller)."""
    res: dict = {"ok": False, "error": None, "folder": None, "note": None, "files": [], "leaves": 0}
    dims = [d for d in (dims or [])]
    if not dims:
        res["error"] = "choose at least one split dimension"; return res
    bad = [d for d in dims if d not in _SPLIT_DIMS]
    if bad:
        res["error"] = f"unknown dimension(s): {', '.join(bad)}"; return res
    try:
        src = resolve_input_pcap(cfg, input_path)
    except FileNotFoundError:
        res["error"] = "input pcap not found"; return res
    except PermissionError as e:
        res["error"] = str(e); return res
    if not shutil.which("tshark"):
        res["error"] = "tshark not found on PATH"; return res

    stem, d = src.stem, src.parent
    folder = d / f"{stem}_split"
    try:
        folder.mkdir(exist_ok=True)
        # Full pcap copy: byte-identical to the source, so its frame numbers are
        # the same indices as the original dual-sniff capture.
        full = folder / f"{stem}_full.pcap"
        shutil.copy(src, full)
        ctx = _build_split_ctx(full)
        # Always enable MAC→PDCP dissection so packet_type/security classify
        # (ciphered frames stay ciphered → "ciphered" bucket).
        oargs = _DISSECT_OARGS
        budget = [_SPLIT_MAX_LEAVES]
        _split_partition(full, folder, dims, 0, "", ctx, oargs, res, budget)
        if budget[0] <= 0:
            res["note"] = (f"Hit the {_SPLIT_MAX_LEAVES}-pcap cap — some buckets weren't written. "
                           f"Use fewer/narrower dimensions.")
        if not res["files"]:
            res["note"] = (res["note"] or "") + " No non-empty buckets produced for these dimensions."
        import json as _json
        (folder / "split.json").write_text(_json.dumps(
            {"source": str(src), "dims": dims, "files": res["files"]}, indent=2))
        res["folder"] = str(folder); res["leaves"] = len(res["files"]); res["ok"] = True
        return res
    except subprocess.TimeoutExpired:
        res["error"] = "tshark timed out"; return res
    except Exception as ex:  # noqa: BLE001
        res["error"] = f"{type(ex).__name__}: {ex}"; return res
