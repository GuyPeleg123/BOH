"""Live pcap receiving — accept the pcap-over-IP stream pushed by a remote
LTESniffer capture instance's PcapForwarder, and reconstruct it into a local
pcap file.

Counterpart to pcap_forward.py. Wire format (sender's rules, unchanged here):
  * Every (re)connect starts clean: a fresh 24-byte pcap global header
    followed by whole 16-byte-header pcap records, never a mid-record splice.
  * The sender doesn't declare compression out of band — the first bytes of
    a connection are recognizable either way (zstd frame magic vs pcap magic),
    so each connection is self-describing and we sniff it directly instead of
    requiring the receiver's config to match the sender's.
  * One connection = one output pcap file. The sender reconnects with capped
    backoff whenever the socket drops; we mirror that by closing the current
    file and going back to accepting a fresh connection.
"""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from pathlib import Path

from fastapi import APIRouter

import auth as auth_mod

log = logging.getLogger("ltesniffer.receive")

_GLOBAL_HDR_LEN = 24
_REC_HDR_LEN = 16
# Same table as pcap_forward.py: pcap magic (first 4 bytes of the global
# header) -> struct endianness prefix.
_MAGIC = {
    b"\xa1\xb2\xc3\xd4": ">",   # big-endian, microsecond
    b"\xd4\xc3\xb2\xa1": "<",   # little-endian, microsecond
    b"\xa1\xb2\x3c\x4d": ">",   # big-endian, nanosecond
    b"\x4d\x3c\xb2\xa1": "<",   # little-endian, nanosecond
}
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_MAX_REC = 10_000_000          # sanity guard: a record bigger than this = desync


def _idle_status() -> dict:
    return {
        "enabled": False, "state": "idle", "bind": "", "port": 0,
        "bytes_in": 0, "records": 0, "connections": 0,
        "peer": None, "connected_since": None, "last_file": None,
        "last_error": None,
    }


def _read_exact(stream, n: int) -> bytes | None:
    """Block until exactly n bytes are read, or return None on EOF."""
    if n == 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


class PcapReceiver:
    def __init__(self):
        self._srv_sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._status = _idle_status()
        self._output_dir: Path | None = None

    def status(self) -> dict:
        with self._lock:
            return dict(self._status)

    def _set(self, **kw) -> None:
        with self._lock:
            self._status.update(**kw)

    def start(self, bind: str, port: int, output_dir: str) -> None:
        self.stop()
        out_dir = Path(output_dir).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((bind, port))
            srv.listen(4)
            srv.settimeout(0.5)   # let the accept loop notice self._stop promptly
        except OSError as e:
            self._status = _idle_status()
            self._set(state="error", last_error=f"bind {bind}:{port}: {e}")
            return
        self._output_dir = out_dir
        self._srv_sock = srv
        self._stop.clear()
        self._status = _idle_status()
        self._set(enabled=True, state="listening", bind=bind, port=port)
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="pcap-receive-accept", daemon=True)
        self._accept_thread.start()
        log.info("pcap receive listening on %s:%d -> %s", bind, port, out_dir)

    def stop(self) -> None:
        self._stop.set()
        if self._srv_sock is not None:
            try:
                self._srv_sock.close()
            except OSError:
                pass
        t = self._accept_thread
        if t is not None and t.is_alive():
            t.join(timeout=3.0)
        self._accept_thread = None
        self._srv_sock = None
        with self._lock:
            self._status.update(enabled=False, state="idle", connected_since=None, peer=None)

    # ---- accept loop: one sender connection at a time, matching the
    # forwarder's single-connection push model ----
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._srv_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            log.info("pcap receive: connection from %s:%d", *addr)
            try:
                self._handle_conn(conn, addr)
            except Exception as e:
                log.warning("pcap receive: handler error: %s", e)
                self._set(state="error", last_error=str(e))
        self._set(state=("idle" if self._stop.is_set() else "error"))

    def _handle_conn(self, conn: socket.socket, addr) -> None:
        with self._lock:
            self._status["connections"] += 1
        self._set(state="connected", peer=f"{addr[0]}:{addr[1]}", connected_since=time.time())
        raw = conn.makefile("rb")
        try:
            peek = raw.peek(4)[:4]
            if peek == _ZSTD_MAGIC:
                import zstandard
                stream = zstandard.ZstdDecompressor().stream_reader(raw)
            else:
                stream = raw

            global_hdr = _read_exact(stream, _GLOBAL_HDR_LEN)
            if global_hdr is None:
                self._set(last_error="connection closed before global header")
                return
            endian = _MAGIC.get(global_hdr[:4])
            if endian is None:
                self._set(state="error", last_error="not a pcap stream (bad magic)")
                return

            ts = time.strftime("%Y%m%d_%H%M%S")
            out_path = self._output_dir / f"received_{ts}_{addr[0].replace('.', '-')}.pcap"
            nrec = 0
            nbytes = len(global_hdr)
            with open(out_path, "wb") as f:
                f.write(global_hdr)
                self._set(last_file=str(out_path))
                while not self._stop.is_set():
                    rec_hdr = _read_exact(stream, _REC_HDR_LEN)
                    if rec_hdr is None:
                        break
                    caplen = struct.unpack_from(endian + "I", rec_hdr, 8)[0]
                    if caplen > _MAX_REC:
                        self._set(state="error", last_error="record length insane; stream desynced")
                        break
                    payload = _read_exact(stream, caplen)
                    if payload is None:
                        self._set(last_error="connection closed mid-record")
                        break
                    f.write(rec_hdr)
                    f.write(payload)
                    nrec += 1
                    nbytes += _REC_HDR_LEN + caplen
                    with self._lock:
                        self._status["records"] += 1
                        self._status["bytes_in"] += _REC_HDR_LEN + caplen
                    if nrec % 50 == 0:
                        f.flush()
            log.info("pcap receive: closed %s:%d (%d records, %d bytes) -> %s",
                      addr[0], addr[1], nrec, nbytes, out_path)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._set(state="listening", connected_since=None, peer=None)


# process-wide singleton
receiver = PcapReceiver()

# Route lives HERE, not in main.py — main.py only app.include_router()s this
# module when GUI_ROLE=="decrypt". A capture-role deployment that omits this
# file has no /api/receive/status route at all, and never imports this module.
router = APIRouter()


@router.get("/api/receive/status")
async def get_receive_status() -> dict:
    """Live pcap-receiving status (state / bytes / peer) for a decrypt-role
    instance, plus this host's LAN IP — what a capture instance's Live pcap
    forwarding should be pointed at (bind is usually 0.0.0.0, not itself a
    reachable address)."""
    st = receiver.status()
    st["host_ip"] = auth_mod._autodetect_lan_ip()
    return st
