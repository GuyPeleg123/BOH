"""LTE key derivation (3GPP TS 33.401) — turn K_ASME + NAS uplink COUNT (or a
K_eNB directly) into the per-bearer keys Wireshark/PDCP needs.

Hierarchy:  K_ASME --(NAS UL COUNT)--> K_eNB --(algo IDs)--> K_RRCenc / K_RRCint
                                                            / K_UPenc / K_UPint

Each KDF is HMAC-SHA256(key, S) with
    S = FC || P0 || len16(P0) [|| P1 || len16(P1)]
matching srsran::kdf_common byte-for-byte. The KDF emits 256 bits; the cipher
(EEA*) / integrity (EIA*) algorithms use the *least-significant 128 bits* — the
last 16 bytes — which is what srsRAN feeds as `k_*_enc + 16` and what the
Wireshark pdcp_lte_ue_keys UAT expects as a 32-hex value.

Pure stdlib (hashlib/hmac) — no external deps.
"""
from __future__ import annotations

import hmac
import hashlib

# FC octets (TS 33.401 Annex A)
_FC_K_ENB = 0x11
_FC_ALGO = 0x15
# algorithm-type distinguishers (P0 for the algo KDF)
_DIST_RRC_ENC = 0x03
_DIST_RRC_INT = 0x04
_DIST_UP_ENC = 0x05
_DIST_UP_INT = 0x06

# algorithm identity byte = numeric suffix of EEAn / EIAn
_CIPHER_ID = {"EEA0": 0, "EEA1": 1, "EEA2": 2, "EEA3": 3}
_INTEG_ID = {"EIA0": 0, "EIA1": 1, "EIA2": 2, "EIA3": 3}


def _kdf(key: bytes, fc: int, *params: bytes) -> bytes:
    """HMAC-SHA256(key, FC || (Pi || len16(Pi))...) -> 32 bytes."""
    s = bytes([fc])
    for p in params:
        s += p + len(p).to_bytes(2, "big")
    return hmac.new(key, s, hashlib.sha256).digest()


def _low128(k32: bytes) -> str:
    """The 128-bit key the cipher actually uses: last 16 bytes, as 32 hex."""
    return k32[16:].hex()


def derive_k_enb(kasme: bytes, nas_count: int) -> bytes:
    return _kdf(kasme, _FC_K_ENB, nas_count.to_bytes(4, "big"))


def _parse_hex(label: str, s: str, nbytes: int) -> bytes:
    s = (s or "").strip().lower().replace(" ", "")
    if s.startswith("0x"):
        s = s[2:]
    try:
        b = bytes.fromhex(s)
    except ValueError:
        raise ValueError(f"{label}: not valid hex")
    if len(b) != nbytes:
        raise ValueError(f"{label}: need {nbytes} bytes ({nbytes*2} hex chars), got {len(b)}")
    return b


def derive_keys(kasme: str | None = None,
                nas_count: int | None = None,
                kenb: str | None = None,
                cipher_algo: str = "EEA2",
                integ_algo: str = "EIA2") -> dict:
    """Derive the full set of access-stratum keys.

    Provide EITHER (kasme + nas_count) OR kenb directly. Returns a dict with the
    32-hex (128-bit) ciphering/integrity keys ready for the decrypt feature plus
    the intermediate K_eNB for reference. Raises ValueError on bad input."""
    cipher_algo = (cipher_algo or "EEA2").upper()
    integ_algo = (integ_algo or "EIA2").upper()
    if cipher_algo not in _CIPHER_ID:
        raise ValueError(f"unknown cipher_algo {cipher_algo!r} (EEA0..EEA3)")
    if integ_algo not in _INTEG_ID:
        raise ValueError(f"unknown integ_algo {integ_algo!r} (EIA0..EIA3)")

    if kenb:
        k_enb = _parse_hex("kenb", kenb, 32)
    elif kasme is not None and nas_count is not None:
        k_asme = _parse_hex("kasme", kasme, 32)
        try:
            nas_count = int(nas_count)
        except (TypeError, ValueError):
            raise ValueError("nas_count must be an integer")
        if not (0 <= nas_count <= 0xFFFFFFFF):
            raise ValueError("nas_count out of range (0..2^32-1)")
        k_enb = derive_k_enb(k_asme, nas_count)
    else:
        raise ValueError("provide kenb, or kasme + nas_count")

    enc_id = _CIPHER_ID[cipher_algo]
    int_id = _INTEG_ID[integ_algo]
    k_rrc_enc = _kdf(k_enb, _FC_ALGO, bytes([_DIST_RRC_ENC]), bytes([enc_id]))
    k_rrc_int = _kdf(k_enb, _FC_ALGO, bytes([_DIST_RRC_INT]), bytes([int_id]))
    k_up_enc = _kdf(k_enb, _FC_ALGO, bytes([_DIST_UP_ENC]), bytes([enc_id]))
    k_up_int = _kdf(k_enb, _FC_ALGO, bytes([_DIST_UP_INT]), bytes([int_id]))

    return {
        "k_enb": k_enb.hex(),
        "cipher_algo": cipher_algo,
        "integ_algo": integ_algo,
        # 128-bit keys for the decrypt feature / Wireshark UAT
        "rrcenc_key": _low128(k_rrc_enc),
        "rrcint_key": _low128(k_rrc_int),
        "upenc_key": _low128(k_up_enc),
        "upint_key": _low128(k_up_int),
    }


# --- self-test against srsRAN test_security_kdf.cc vectors -------------------
if __name__ == "__main__":
    KASME = "6144c681d1bea9dae1b8cf6cd10a686341db8046a1e7a9ab4d1ea0e33c994ac0"
    KENB_EXP = "c4c7bc798ab94e3d354cd6608e79aa92f5569df46519507850051e36f018ca5f"
    # srsRAN vector uses EEA0 / 128-EIA2
    RRC_ENC_FULL = "23afdd7b2e4a5a99c778827859cf451486a275788b6f36a5b9b810f5d472a24b"
    UP_ENC_FULL = "22bfb58761ca1dd3b20a281c7eab0c0b9c3c92e1ddc0c8c5706cbb8f955e8263"
    RRC_INT_FULL = "42f4f8c585ae8905a50d0f32a979d8b6fa1d6d1940f1d879cf0189342a8d73c2"

    fails = 0
    kenb = derive_k_enb(bytes.fromhex(KASME), 0).hex()
    ok = kenb == KENB_EXP
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] K_eNB from K_ASME(nas=0)\n      got {kenb}")

    d = derive_keys(kenb=KENB_EXP, cipher_algo="EEA0", integ_algo="EIA2")
    for name, full in (("rrcenc_key", RRC_ENC_FULL), ("upenc_key", UP_ENC_FULL),
                       ("rrcint_key", RRC_INT_FULL)):
        exp = full[32:]  # low 128 bits
        ok = d[name] == exp
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: got {d[name]} exp {exp}")

    # full chain K_ASME -> keys
    d2 = derive_keys(kasme=KASME, nas_count=0, cipher_algo="EEA0", integ_algo="EIA2")
    ok = d2["rrcenc_key"] == RRC_ENC_FULL[32:] and d2["k_enb"] == KENB_EXP
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] full K_ASME->keys chain")

    import sys
    print("ALL PASS" if not fails else f"{fails} FAILURES")
    sys.exit(1 if fails else 0)
