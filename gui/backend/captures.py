"""Discover, list, and safely serve pcap files for the GUI."""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import tempfile
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
    """Resolve a pcap to DECRYPT/ORGANIZE. Unlike resolve_for_download this is
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
# Post-capture PDCP decryption
#
# Wireshark deciphers PDCP-LTE at dissection time using its `pdcp_lte_ue_keys`
# UAT, keyed by UEId. LTESniffer pcaps tag every frame UEId=0 (only RNTI set),
# so we first rewrite each frame's UEId tag to equal its RNTI, then feed tshark
# one UAT row per RNTI. tshark can't bake decryption into a pcap (-w keeps the
# ciphered bytes), so we emit (a) a readable verbose decode and (b) the
# UEId-rewritten pcap + a .uat sidecar the operator can load in their Wireshark.
# ---------------------------------------------------------------------------

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_CIPHER_ALGOS = {"EEA0", "EEA1", "EEA2", "EEA3"}
_INTEG_ALGOS = {"EIA0", "EIA1", "EIA2", "EIA3"}

import keyderiv


def _resolve_entry_keys(e: dict) -> tuple[str, str]:
    """Return (rrcenc, upenc) 32-hex ciphering keys for a key entry, deriving
    them from K_ASME+NAS_count (or K_eNB) when the raw keys aren't supplied.
    Raises ValueError with a user-facing message on bad input."""
    rrc = str(e.get("rrcenc_key", "") or "").strip().lower()
    up = str(e.get("upenc_key", "") or "").strip().lower()
    if _HEX32.match(rrc) and _HEX32.match(up):
        return rrc, up
    # not given directly — try to derive
    kasme = str(e.get("kasme", "") or "").strip()
    kenb = str(e.get("kenb", "") or "").strip()
    nas = e.get("nas_count", None)
    if kenb or (kasme and nas is not None):
        d = keyderiv.derive_keys(
            kasme=kasme or None, nas_count=nas, kenb=kenb or None,
            cipher_algo=str(e.get("cipher_algo", "EEA2")),
            integ_algo=str(e.get("integ_algo", "EIA2")),
        )
        return d["rrcenc_key"], d["upenc_key"]
    raise ValueError("provide K_RRCenc+K_UPenc (32 hex each), or K_eNB, "
                     "or K_ASME + NAS uplink count to derive them")

# MAC-LTE pcap framing (DLT 147): record data = radioType, direction, rntiType,
# then TLV tags until the 0x01 payload tag.
_MAC_LTE_PAYLOAD_TAG = 0x01
_MAC_LTE_RNTI_TAG = 0x02
_MAC_LTE_UEID_TAG = 0x03
_TAGS_2B = {0x02, 0x03, 0x04}              # RNTI, UEID, FRAME/SUBFRAME
_TAGS_1B = {0x05, 0x06, 0x07, 0x0A, 0x0F}  # predef, retx, crc, carrier, nb-mode


def _rewrite_ueid_eq_rnti(in_path: Path, out_path: Path) -> int:
    """Copy a MAC-LTE pcap setting each frame's UEId tag = its RNTI (in place,
    no length change) so the per-UEId pdcp_lte_ue_keys table keys per-RNTI.
    Returns frames rewritten. Frames missing either tag pass through unchanged."""
    with open(in_path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("pcap too short")
        magic = struct.unpack("<I", gh[:4])[0]
        endi = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        linktype = struct.unpack(endi + "I", gh[20:24])[0]
        if linktype != 147:
            raise ValueError(f"not a MAC-LTE pcap (linktype={linktype})")
        rewritten = 0
        with open(out_path, "wb") as o:
            o.write(gh)
            while True:
                rh = f.read(16)
                if len(rh) < 16:
                    break
                incl = struct.unpack(endi + "IIII", rh)[2]
                data = bytearray(f.read(incl))
                if len(data) < incl:
                    break
                i, n = 3, len(data)
                rnti = None
                ueid_pos = None
                while i < n:
                    tag = data[i]
                    if tag == _MAC_LTE_PAYLOAD_TAG:
                        break
                    if tag == _MAC_LTE_RNTI_TAG and i + 3 <= n:
                        rnti = (data[i + 1] << 8) | data[i + 2]
                        i += 3
                    elif tag == _MAC_LTE_UEID_TAG and i + 3 <= n:
                        ueid_pos = i + 1
                        i += 3
                    elif tag in _TAGS_2B:
                        i += 3
                    elif tag in _TAGS_1B:
                        i += 2
                    else:
                        break
                if rnti is not None and ueid_pos is not None:
                    data[ueid_pos] = (rnti >> 8) & 0xFF
                    data[ueid_pos + 1] = rnti & 0xFF
                    rewritten += 1
                o.write(rh)
                o.write(data)
        return rewritten


def decrypt_pcap(cfg: SnifferConfig, input_path: str, entries: list[dict]) -> dict:
    """Decrypt a captured pcap with per-RNTI keys. Produces a readable decode
    (.txt), a UEId-rewritten pcap, and a .uat keys sidecar. Returns a structured
    result (never raises to the caller; tshark failures come back as ok=False)."""
    res: dict = {
        "ok": False, "error": None, "stderr": "", "note": None,
        "keyed_pcap_path": None, "txt_path": None, "uat_path": None,
        "decoded_text": "", "uat_text": "", "frames_rewritten": 0, "ndecoded": 0,
    }
    try:
        src = resolve_input_pcap(cfg, input_path)
    except FileNotFoundError:
        res["error"] = "input pcap not found"; return res
    except PermissionError as e:
        res["error"] = str(e); return res

    if not entries:
        res["error"] = "no key entries provided"; return res
    norm = []
    for e in entries:
        try:
            rnti = int(e["rnti"])
        except (KeyError, ValueError, TypeError):
            res["error"] = "invalid rnti"; return res
        if not 0 <= rnti <= 0xFFFF:
            res["error"] = f"rnti {rnti} out of range (0..65535)"; return res
        try:
            rrc, up = _resolve_entry_keys(e)
        except ValueError as ke:
            res["error"] = f"RNTI {rnti}: {ke}"; return res
        cipher = str(e.get("cipher_algo", "EEA2"))
        integ = str(e.get("integ_algo", "EIA2"))
        if cipher not in _CIPHER_ALGOS:
            res["error"] = f"RNTI {rnti}: bad cipher_algo {cipher}"; return res
        if integ not in _INTEG_ALGOS:
            res["error"] = f"RNTI {rnti}: bad integ_algo {integ}"; return res
        norm.append({"rnti": rnti, "rrc": rrc.lower(), "up": up.lower(),
                     "cipher": cipher, "integ": integ})

    if len({e["cipher"] for e in norm}) > 1:
        res["note"] = ("Multiple cipher algorithms given; tshark applies one global "
                       "default, so mixed-algo UEs decrypt only if the capture also "
                       "contains their RRC SecurityModeCommand.")

    stem, d = src.stem, src.parent
    keyed = d / f"{stem}_keyed.pcap"
    txt = d / f"{stem}_decrypted.txt"
    uat = d / f"{stem}.pdcp_lte_ue_keys.uat"

    if not shutil.which("tshark"):
        res["error"] = "tshark not found on PATH"; return res

    tmp = None
    try:
        with tempfile.NamedTemporaryFile(prefix="lte-keyed-", suffix=".pcap", delete=False) as tf:
            tmp = Path(tf.name)
        res["frames_rewritten"] = _rewrite_ueid_eq_rnti(src, tmp)

        oargs = [
            "-o", "pdcp-lte.decipher_signalling:TRUE",
            "-o", "pdcp-lte.decipher_userplane:TRUE",
            "-o", f"pdcp-lte.default_ciphering_algorithm:{norm[0]['cipher']}",
            "-o", f"pdcp-lte.default_integrity_algorithm:{norm[0]['integ']}",
            "-o", "pdcp-lte.show_user_plane_as_ip:TRUE",
            "-o", "pdcp-lte.show_signalling_plane_as_rrc:TRUE",
            "-o", "mac-lte.attempt_to_dissect_srb_sdus:TRUE",
        ]
        uat_rows = []
        for e in norm:
            row = f'"{e["rnti"]}","{e["rrc"]}","{e["up"]}",""'  # rrcIntegrity left blank
            uat_rows.append(row)
            oargs += ["-o", f"uat:pdcp_lte_ue_keys:{row}"]
        uat_text = (
            "# Wireshark PDCP-LTE keys (pdcp_lte_ue_keys.uat)\n"
            "# Load: copy into ~/.config/wireshark/  then open the *_keyed.pcap\n"
            "# Columns: ueid(=RNTI), RRC cipher key, UP cipher key, RRC integrity key\n"
            + "\n".join(uat_rows) + "\n"
        )

        shutil.move(str(tmp), str(keyed)); tmp = None
        uat.write_text(uat_text)

        cmd = ["tshark", "-r", str(keyed), *oargs, "-Y", "pdcp-lte", "-V"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        res["stderr"] = (proc.stderr or "").strip()
        decoded = proc.stdout or ""
        max_bytes = 4 * 1024 * 1024
        if len(decoded) > max_bytes:
            decoded = decoded[:max_bytes] + "\n...[truncated]...\n"
        txt.write_text(decoded)

        res["ndecoded"] = decoded.count("PDCP-LTE")
        res["keyed_pcap_path"] = str(keyed)
        res["txt_path"] = str(txt)
        res["uat_path"] = str(uat)
        res["decoded_text"] = decoded
        res["uat_text"] = uat_text
        res["ok"] = proc.returncode == 0
        if proc.returncode != 0 and not res["error"]:
            res["error"] = "tshark exited non-zero — see stderr"
        return res
    except subprocess.TimeoutExpired:
        res["error"] = "tshark timed out (>300s)"; return res
    except Exception as ex:  # noqa: BLE001 - report any failure structurally
        res["error"] = f"{type(ex).__name__}: {ex}"; return res
    finally:
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Session organizer: split a whole sniff into a folder of per-UE sub-pcaps
# named by TMSI/IMSI (falling back to RNTI), optionally decrypting each UE.
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


def _decode_count(pcap: Path, rnti: int, key: dict | None) -> int:
    """Count frames of this RNTI that dissect cleanly to lte-rrc or ip. With the
    right key, ciphered SRB/DRB decode to RRC/IP; with a wrong key they're garbage."""
    oargs = [
        "-o", "pdcp-lte.decipher_signalling:TRUE",
        "-o", "pdcp-lte.decipher_userplane:TRUE",
        "-o", "pdcp-lte.show_user_plane_as_ip:TRUE",
        "-o", "mac-lte.attempt_to_dissect_srb_sdus:TRUE",
    ]
    if key:
        oargs += [
            "-o", f"pdcp-lte.default_ciphering_algorithm:{key['cipher']}",
            "-o", f"pdcp-lte.default_integrity_algorithm:{key['integ']}",
            "-o", f'uat:pdcp_lte_ue_keys:"{rnti}","{key["rrc"]}","{key["up"]}",""',
        ]
    cmd = ["tshark", "-r", str(pcap), "-Y", f"mac-lte.rnti=={rnti} and (lte-rrc or ip)", *oargs, "-T", "fields", "-e", "frame.number"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return len([x for x in out.stdout.splitlines() if x.strip()])


def organize_session(cfg: SnifferConfig, input_path: str, entries: list[dict] | None,
                     mode: str = "auto") -> dict:
    """Build a session folder: the full pcap + one sub-pcap per UE (recurring
    C-RNTI), named by TMSI/IMSI when known else by RNTI. If keys are given,
    decrypt each UE — `mode='auto'` heuristically matches keys to UEs by which
    one yields the most clean RRC/IP decodes; `mode='per-rnti'` uses the RNTI on
    each key entry. Returns a structured manifest (never raises to the caller)."""
    res: dict = {"ok": False, "error": None, "folder": None, "ues": [], "note": None}
    try:
        src = resolve_input_pcap(cfg, input_path)
    except FileNotFoundError:
        res["error"] = "input pcap not found"; return res
    except PermissionError as e:
        res["error"] = str(e); return res
    if not shutil.which("tshark"):
        res["error"] = "tshark not found on PATH"; return res

    entries = entries or []
    keys = []
    for e in entries:
        try:
            rrc, up = _resolve_entry_keys(e)
        except ValueError as ke:
            res["error"] = str(ke); return res
        keys.append({
            "rnti": int(e["rnti"]) if str(e.get("rnti", "")).strip() not in ("", "None") else None,
            "rrc": rrc, "up": up,
            "cipher": str(e.get("cipher_algo", "EEA2")), "integ": str(e.get("integ_algo", "EIA2")),
        })

    stem, d = src.stem, src.parent
    folder = d / f"{stem}_session"
    try:
        folder.mkdir(exist_ok=True)
        # ueid:=rnti rewrite -> keyed full pcap (the one we split + decrypt)
        full = folder / f"{stem}_full.pcap"
        _rewrite_ueid_eq_rnti(src, full)

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
            sub = folder / f"ue_{label}.pcap"
            subprocess.run(["tshark", "-r", str(full), "-Y", f"mac-lte.rnti=={rnti}", "-w", str(sub)],
                           capture_output=True, text=True, timeout=180)
            ue = {"rnti": rnti, "rnti_hex": f"0x{rnti:04X}", "identity": ident,
                  "frames": counts[rnti], "sub_pcap": str(sub),
                  "matched_key": None, "score": 0, "decoded_txt": None}

            # choose a key
            key = None
            if mode == "per-rnti":
                key = next((k for k in keys if k["rnti"] == rnti), None)
            elif keys:  # auto-match: best clean-decode delta over the no-key baseline
                base = _decode_count(sub, rnti, None)
                best, best_delta = None, 0
                for k in keys:
                    delta = _decode_count(sub, rnti, k) - base
                    if delta > best_delta:
                        best, best_delta = k, delta
                if best and best_delta >= 2:
                    key = best; ue["score"] = best_delta

            if key:
                ue["matched_key"] = f"{key['rrc'][:8]}…/{key['up'][:8]}…"
                txt = folder / f"ue_{label}_decrypted.txt"
                oargs = [
                    "-o", "pdcp-lte.decipher_signalling:TRUE", "-o", "pdcp-lte.decipher_userplane:TRUE",
                    "-o", f"pdcp-lte.default_ciphering_algorithm:{key['cipher']}",
                    "-o", f"pdcp-lte.default_integrity_algorithm:{key['integ']}",
                    "-o", "pdcp-lte.show_user_plane_as_ip:TRUE", "-o", "mac-lte.attempt_to_dissect_srb_sdus:TRUE",
                    "-o", f'uat:pdcp_lte_ue_keys:"{rnti}","{key["rrc"]}","{key["up"]}",""',
                ]
                dec = subprocess.run(["tshark", "-r", str(sub), *oargs, "-Y", "pdcp-lte", "-V"],
                                     capture_output=True, text=True, timeout=180).stdout
                txt.write_text(dec[:4 * 1024 * 1024])
                ue["decoded_txt"] = str(txt)
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
