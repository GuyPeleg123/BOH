"""UE session correlation — tie RNTI ↔ identity (M-TMSI/S-TMSI/GUTI/IMSI) ↔
Timing-Advance range, so a TA "location" can be attributed to a specific UE.

Post-capture only (tshark over a pcap) — no recompile, offline-appliance safe.

The chain (see CLAUDE.md):
  RACH → RAR (RA-RNTI): RAPID + absolute TA            ─┐ time-match (no temp-CRNTI
  Msg3 RRC ConnReq (C-RNTI): M-TMSI + MMEC             ─┤  field in tshark)
        SESSION { C-RNTI lifetime }  ◄─────────────────┘
  TA Command MAC CEs (C-RNTI): ongoing ±TA drift       ─┘
  SIB1: PLMN → completes the (partial) GUTI

Identity reality: over the air you reliably get M-TMSI; often MMEC; PLMN from
SIB1. Full GUTI/IMSI from NAS only when traffic is decrypted (opt-in keys).
Labels carry a `source`/`confidence` so nothing is overstated.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from config import SnifferConfig
import captures as C

# One TA step = 16·Ts, Ts = 1/(15000·2048) s; round-trip → halve for one-way range.
_TS = 1.0 / (15000 * 2048)
_C = 299_792_458.0
_METERS_PER_TA = 16 * _TS * _C / 2.0          # ≈ 78.07 m
_TA_CMD_NEUTRAL = 31                            # MAC TA Command value meaning "no change"
_RAR_MATCH_WINDOW_S = 0.5                       # RAR anchor must precede the C-RNTI's first frame within this


def _f(v: str) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _first(s: str) -> str:
    # tshark joins repeated field occurrences with ',' — take the first non-empty
    for part in (s or "").split(","):
        if part.strip():
            return part.strip()
    return ""


def _norm_mtmsi(v: str, decimal: bool) -> str:
    """Normalize M-TMSI to 8-hex lowercase. lte-rrc.m_TMSI renders as hex,
    nas_eps.emm.m_tmsi as decimal — unify so the same UE reads identically
    regardless of which source it came from."""
    v = (v or "").strip()
    if not v:
        return ""
    try:
        n = int(v, 10) if decimal else int(v, 16)
    except ValueError:
        return v.lower()
    return f"{n & 0xFFFFFFFF:08x}"


def _latest_pcap(cfg: SnifferConfig) -> str | None:
    pcaps = C.list_pcaps(cfg)
    for p in pcaps:                              # already sorted newest-first
        if p.get("size", 0) > 24:
            return p["path"]
    return None


def analyze_sessions(cfg: SnifferConfig, input_path: str | None,
                     entries: list[dict] | None = None, decrypt: bool = False) -> dict:
    """Build per-UE sessions with correlated identity + TA range from a pcap.
    Returns a manifest (never raises to the caller)."""
    res: dict = {"ok": False, "error": None, "note": None, "source": None,
                 "sessions": [], "unmatched_rar": 0, "paging": []}

    path = input_path or _latest_pcap(cfg)
    if not path:
        res["error"] = "no capture available to analyze"; return res
    try:
        src = C.resolve_input_pcap(cfg, path)
    except FileNotFoundError:
        res["error"] = "input pcap not found"; return res
    except PermissionError as e:
        res["error"] = str(e); return res
    if not __import__("shutil").which("tshark"):
        res["error"] = "tshark not found on PATH"; return res
    res["source"] = str(src)

    keys: list[dict] = []
    if decrypt:
        for e in (entries or []):
            try:
                rrc, up = C._resolve_entry_keys(e)
            except ValueError as ke:
                res["error"] = str(ke); return res
            rn = str(e.get("rnti", "")).strip()
            keys.append({"rnti": int(rn) if rn not in ("", "None") else None,
                         "rrc": rrc, "up": up,
                         "cipher": str(e.get("cipher_algo", "EEA2")),
                         "integ": str(e.get("integ_algo", "EIA2"))})
    do_decrypt = decrypt and bool(keys)

    tmp = None
    try:
        # Decryption needs UEId:=RNTI so the Wireshark UAT applies; cleartext can
        # read the source directly. SRB dissection is always on so RRC ConnReq
        # (Msg3, sent in the clear) parses out M-TMSI/MMEC.
        if do_decrypt:
            with tempfile.NamedTemporaryFile(prefix="lte-sess-", suffix=".pcap", delete=False) as tf:
                tmp = Path(tf.name)
            C._rewrite_ueid_eq_rnti(src, tmp)
            pcap = tmp
            oargs = C._split_oargs(keys)         # decipher prefs + UAT rows + SRB dissect
        else:
            pcap = src
            oargs = ["-o", "mac-lte.attempt_to_dissect_srb_sdus:TRUE"]

        # cell identity (ECI) + PLMN (MCC-MNC) from SIB1 — LTESniffer locks one cell
        # per capture, so every session's DL/UL belongs to this cell. Cell ID + PLMN
        # let you tell apart cells (and networks) that reuse the same PCI.
        _cell = C.read_cell_id(pcap) or {}
        _cellid = _cell.get("cell_identity")
        _plmn = (f"{_cell['mcc']}-{_cell['mnc']}"
                 if _cell.get("mcc") and _cell.get("mnc") else None)

        # ---- pass 1: C-RNTI activity (lifetime, frame counts) -----------------
        sess: dict[int, dict] = {}
        for r in C._tshark_fields(pcap, "mac-lte",
                                  ["frame.time_relative", "mac-lte.rnti",
                                   "mac-lte.rnti-type", "mac-lte.direction"]):
            r = (r + ["", "", "", ""])[:4]
            t, rnti_s, rtype, direction = r
            if rtype != "3" or not rnti_s:        # C-RNTI only
                continue
            rnti = int(rnti_s); t = _f(t)
            s = sess.get(rnti)
            if s is None:
                sess[rnti] = s = {"c_rnti": rnti, "start": t, "end": t,
                                  "dl": 0, "ul": 0, "frames": 0,
                                  "identity": {}, "ta": {}}
            s["start"] = min(s["start"], t); s["end"] = max(s["end"], t); s["frames"] += 1
            if direction == "1":
                s["dl"] += 1
            elif direction == "0":
                s["ul"] += 1

        # ---- pass 2: identities (RRC ConnReq on C-RNTI; paging on P-RNTI; NAS) -
        idf = ("lte-rrc.m_TMSI or lte-rrc.mmec or lte-rrc.randomValue "
               "or e212.imsi or nas_eps.emm.m_tmsi")
        for r in C._tshark_fields(pcap, idf,
                                  ["frame.time_relative", "mac-lte.rnti", "mac-lte.rnti-type",
                                   "lte-rrc.m_TMSI", "lte-rrc.mmec", "e212.imsi",
                                   "nas_eps.emm.m_tmsi"]):
            r = (r + [""] * 7)[:7]
            t, rnti_s, rtype, mtmsi, mmec, imsi, nas_mtmsi = r
            # lte-rrc.m_TMSI is hex; nas_eps.emm.m_tmsi is decimal — normalize both,
            # and record which layer the value actually came from.
            rrc_m = _norm_mtmsi(_first(mtmsi), decimal=False)
            nas_m = _norm_mtmsi(_first(nas_mtmsi), decimal=True)
            mtmsi = rrc_m or nas_m
            src = "rrc-connreq" if rrc_m else "nas" if nas_m else None
            imsi = _first(imsi); mmec = _first(mmec)
            if rtype == "3" and rnti_s:           # bound to a session's C-RNTI
                s = sess.get(int(rnti_s))
                if s is None:
                    continue
                idd = s["identity"]
                if mtmsi: idd["m_tmsi"] = mtmsi
                if mmec: idd["mmec"] = mmec
                if imsi: idd["imsi"] = imsi
                if src and "source" not in idd:
                    idd["source"] = src
                elif imsi and "source" not in idd:
                    idd["source"] = "nas"
            else:                                  # paging / broadcast identity pool
                if mtmsi or imsi:
                    res["paging"].append({"t": _f(t), "m_tmsi": mtmsi, "imsi": imsi})

        # ---- pass 3: SIB1 PLMN (for GUTI assembly) ---------------------------
        plmn = ""
        for r in C._tshark_fields(pcap, "lte-rrc.systemInformationBlockType1_element",
                                  ["e212.mcc", "e212.mnc"]):
            r = (r + ["", ""])[:2]
            mcc, mnc = _first(r[0]), _first(r[1])
            if mcc and mnc:
                plmn = f"{mcc}{mnc}"; break

        # ---- pass 4: RAR TA anchors (RAPID + absolute TA + time) -------------
        rar = []
        for r in C._tshark_fields(pcap, "mac-lte.rar.ta",
                                  ["frame.time_relative", "mac-lte.rar.rapid", "mac-lte.rar.ta"]):
            r = (r + ["", "", ""])[:3]
            for ta in (r[2] or "").split(","):
                ta = ta.strip()
                if ta.isdigit():
                    rar.append({"t": _f(r[0]), "rapid": _first(r[1]), "ta": int(ta), "used": False})
        rar.sort(key=lambda x: x["t"])

        # ---- pass 5: TA Command CEs per C-RNTI (relative drift) --------------
        cmds: dict[int, list] = {}
        for r in C._tshark_fields(pcap, "mac-lte.control.timing-advance.command",
                                  ["frame.time_relative", "mac-lte.rnti",
                                   "mac-lte.control.timing-advance.command"]):
            r = (r + ["", "", ""])[:3]
            if not r[1]:
                continue
            rnti = int(r[1])
            for cv in (r[2] or "").split(","):
                cv = cv.strip()
                if cv.isdigit():
                    cmds.setdefault(rnti, []).append({"t": _f(r[0]), "cmd": int(cv)})

        # ---- assemble sessions ----------------------------------------------
        out = []
        for rnti, s in sess.items():
            # keep real UEs: recurring C-RNTI OR one that exposed an identity
            if s["frames"] < C._MIN_FRAMES_PER_UE and not s["identity"]:
                continue

            # identity labels (honest about completeness)
            idd = s["identity"]
            m_tmsi, mmec, imsi = idd.get("m_tmsi"), idd.get("mmec"), idd.get("imsi")
            s_tmsi = (mmec + m_tmsi) if (mmec and m_tmsi) else None
            guti = None
            if m_tmsi:
                guti = (f"{plmn}-{mmec}-{m_tmsi}" if (plmn and mmec)
                        else f"{plmn}-{m_tmsi}" if plmn else None)
            label = (f"imsi-{imsi}" if imsi else f"guti-{guti}" if guti
                     else f"stmsi-{s_tmsi}" if s_tmsi else f"mtmsi-{m_tmsi}" if m_tmsi
                     else f"rnti-{rnti:04x}")
            confidence = "imsi" if imsi else "guti" if guti else "tmsi" if m_tmsi else "rnti-only"

            # TA anchor: most-recent unclaimed RAR just before this session started
            anchor = None
            for cand in reversed(rar):
                if cand["used"]:
                    continue
                if s["start"] - _RAR_MATCH_WINDOW_S <= cand["t"] <= s["start"] + 0.05:
                    anchor = cand; cand["used"] = True; break
            anchor_ta = anchor["ta"] if anchor else None
            anchor_range = round(anchor_ta * _METERS_PER_TA) if anchor_ta is not None else None

            # TA timeline = anchor + cumulative TA-Command drift on this C-RNTI
            samples = []
            if anchor_range is not None:
                samples.append({"t": round(anchor["t"], 3), "range_m": anchor_range, "src": "rar"})
            cur_ta = anchor_ta if anchor_ta is not None else 0
            base_known = anchor_ta is not None
            for c in sorted(cmds.get(rnti, []), key=lambda x: x["t"]):
                cur_ta += (c["cmd"] - _TA_CMD_NEUTRAL)
                samples.append({"t": round(c["t"], 3),
                                "range_m": (round(cur_ta * _METERS_PER_TA) if base_known else None),
                                "delta_m": round((c["cmd"] - _TA_CMD_NEUTRAL) * _METERS_PER_TA),
                                "src": "ta-cmd"})
            ranges = [x["range_m"] for x in samples if x.get("range_m") is not None]
            ta_block = {
                "anchor_ta": anchor_ta, "anchor_range_m": anchor_range,
                "has_absolute": base_known, "n_samples": len(samples), "samples": samples[:500],
                "min_range_m": min(ranges) if ranges else None,
                "median_range_m": sorted(ranges)[len(ranges) // 2] if ranges else None,
                "max_range_m": max(ranges) if ranges else None,
            }

            out.append({
                "session_id": f"{rnti:04x}-{int(s['start']*1000)}",
                "c_rnti": rnti, "c_rnti_hex": f"0x{rnti:04X}",
                "start": round(s["start"], 3), "end": round(s["end"], 3),
                "duration_s": round(s["end"] - s["start"], 3),
                "dl_frames": s["dl"], "ul_frames": s["ul"], "frames": s["frames"],
                "cell_identity": _cellid,
                "plmn": _plmn,
                "identity": {"label": label, "confidence": confidence, "m_tmsi": m_tmsi,
                             "mmec": mmec, "s_tmsi": s_tmsi, "guti": guti, "imsi": imsi,
                             "plmn": plmn or None, "source": idd.get("source")},
                "ta": ta_block,
            })

        out.sort(key=lambda x: x["start"], reverse=True)
        res["sessions"] = out
        res["unmatched_rar"] = sum(1 for c in rar if not c["used"])
        named = sum(1 for x in out if x["identity"]["confidence"] != "rnti-only")
        with_ta = sum(1 for x in out if x["ta"]["n_samples"] > 0)
        notes = []
        if out and named == 0:
            notes.append("No UE identities recovered in the clear — capture RRC Connection "
                         "Requests / paging (API mode -z) or enable decrypt with keys.")
        if not do_decrypt:
            notes.append("Cleartext mode: GUTI/IMSI from encrypted NAS not included. "
                         "Enable decrypt with keys to complete identities.")
        notes.append(f"{len(out)} sessions, {named} identified, {with_ta} with TA. "
                     f"RAR↔C-RNTI is time-matched (no Temp-CRNTI field); {res['unmatched_rar']} RAR TAs unmatched.")
        res["note"] = " ".join(notes)
        res["ok"] = True
        return res
    except __import__("subprocess").TimeoutExpired:
        res["error"] = "tshark timed out"; return res
    except Exception as ex:  # noqa: BLE001
        res["error"] = f"{type(ex).__name__}: {ex}"; return res
    finally:
        if tmp and tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
