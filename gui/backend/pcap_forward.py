"""Live pcap forwarding — push the capture's live MAC-LTE pcap to a remote
collector DURING the run.

LTESniffer mirrors every decoded MAC PDU to a named pipe (`LTESNIFFER_PCAP_STREAM`
= cfg.pcap_stream_fifo). This module reads that libpcap byte stream, frames it
into whole records, and pushes them over a TCP connection it opens OUT to a
configured collector (host:port) — "PCAP-over-IP", optionally zstd-compressed.

Design points:
  * **Record-framed.** We parse the 24-byte pcap global header and each 16-byte
    record header, so we only ever forward COMPLETE records. Every (re)connect is
    therefore clean: a fresh global header followed by whole records — never a
    mid-record splice.
  * **Never stalls the capture.** The FIFO is drained continuously even while the
    collector is down; records are simply dropped until it reconnects. The on-disk
    pcap remains the complete record, so nothing is truly lost.
  * **Push / connect-out** with capped exponential backoff, and live status for
    the GUI.
"""
import logging
import os
import select
import socket
import struct
import threading
import time

log = logging.getLogger("ltesniffer.forward")

_GLOBAL_HDR_LEN = 24
_REC_HDR_LEN = 16
# pcap magic (first 4 bytes of the global header) -> struct endianness prefix.
_MAGIC = {
    b"\xa1\xb2\xc3\xd4": ">",   # big-endian, microsecond
    b"\xd4\xc3\xb2\xa1": "<",   # little-endian, microsecond
    b"\xa1\xb2\x3c\x4d": ">",   # big-endian, nanosecond
    b"\x4d\x3c\xb2\xa1": "<",   # little-endian, nanosecond
}
_MAX_REC = 10_000_000          # sanity guard: a record bigger than this = desync


def _idle_status() -> dict:
    return {
        "enabled": False, "state": "idle", "host": "", "port": 0, "compress": True,
        "bytes_in": 0, "records": 0, "bytes_out": 0,
        "connected_since": None, "connects": 0, "last_error": None,
    }


class _Sink:
    """A TCP sink, optionally wrapping the socket in a zstd stream compressor."""

    def __init__(self, sock: socket.socket, compress: bool):
        self._sock = sock
        self._writer = None
        self._sockfile = None
        if compress:
            import zstandard
            self._sockfile = sock.makefile("wb")
            self._writer = zstandard.ZstdCompressor(level=3).stream_writer(self._sockfile)

    def send(self, data: bytes) -> None:
        if self._writer is not None:
            self._writer.write(data)
            self._writer.flush()          # push promptly — this is a live stream
        else:
            self._sock.sendall(data)

    def close(self) -> None:
        try:
            if self._writer is not None:
                self._writer.close()       # flush + finish the zstd frame
                self._sockfile.close()
        except (OSError, ValueError):
            pass
        try:
            self._sock.close()
        except OSError:
            pass


class PcapForwarder:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._status = _idle_status()

    def status(self) -> dict:
        with self._lock:
            return dict(self._status)

    def _set(self, **kw) -> None:
        with self._lock:
            self._status.update(**kw)

    def start(self, fifo_path: str, host: str, port: int, compress: bool = True) -> None:
        self.stop()
        if not fifo_path or not host or not port:
            with self._lock:
                self._status = _idle_status()
                self._status.update(state="error", last_error="forward needs fifo + host + port")
            return
        # Open the FIFO read-end SYNCHRONOUSLY here (non-blocking, returns at once)
        # so a reader is present before the C++ child opens it O_WRONLY|O_NONBLOCK
        # (which would ENXIO with no reader). Then hand the fd to the worker.
        try:
            fifo_fd = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            with self._lock:
                self._status = _idle_status()
                self._status.update(state="error", last_error=f"FIFO open failed: {e}")
            return
        self._stop.clear()
        with self._lock:
            self._status = _idle_status()
            self._status.update(enabled=True, state="starting", host=host,
                                port=int(port), compress=bool(compress))
        self._thread = threading.Thread(
            target=self._run, args=(fifo_fd, host, int(port), bool(compress)),
            name="pcap-forward", daemon=True)
        self._thread.start()
        log.info("pcap forward started -> %s:%d (compress=%s)", host, port, compress)

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=3.0)
        self._thread = None
        with self._lock:
            self._status.update(enabled=False, state="idle", connected_since=None)

    # ---- worker thread ----
    def _run(self, fifo_fd, host, port, compress) -> None:
        buf = bytearray()
        endian = None
        global_hdr = None            # 24-byte pcap header, replayed per connection
        conn = None                  # _Sink | None
        last_connect = 0.0
        backoff = 1.0

        try:
            while not self._stop.is_set():
                r, _, _ = select.select([fifo_fd], [], [], 0.5)
                if r:
                    try:
                        chunk = os.read(fifo_fd, 262144)
                    except BlockingIOError:
                        chunk = b""
                    except OSError as e:
                        self._set(last_error=f"FIFO read: {e}")
                        break
                    if chunk:
                        buf += chunk
                        with self._lock:
                            self._status["bytes_in"] += len(chunk)
                    # An empty read on a FIFO just means no writer/data right now.

                # Parse the global header exactly once.
                if global_hdr is None:
                    if len(buf) < _GLOBAL_HDR_LEN:
                        continue
                    global_hdr = bytes(buf[:_GLOBAL_HDR_LEN])
                    endian = _MAGIC.get(global_hdr[:4])
                    if endian is None:
                        self._set(state="error", last_error="not a pcap stream (bad magic)")
                        break
                    del buf[:_GLOBAL_HDR_LEN]

                # Pull every COMPLETE record currently buffered into one batch.
                to_send = bytearray()
                nrec = 0
                desync = False
                while len(buf) >= _REC_HDR_LEN:
                    caplen = struct.unpack_from(endian + "I", buf, 8)[0]
                    if caplen > _MAX_REC:
                        desync = True
                        break
                    total = _REC_HDR_LEN + caplen
                    if len(buf) < total:
                        break
                    to_send += buf[:total]
                    del buf[:total]
                    nrec += 1
                if desync:
                    self._set(state="error", last_error="record length insane; stream desynced")
                    break
                if not to_send:
                    continue
                with self._lock:
                    self._status["records"] += nrec

                # Ensure a connection (throttled reconnect); drop the batch if down.
                if conn is None:
                    now = time.monotonic()
                    if now - last_connect < backoff:
                        continue
                    last_connect = now
                    conn = self._connect(host, port, compress, global_hdr)
                    if conn is None:
                        backoff = min(backoff * 2, 30.0)
                        continue
                    backoff = 1.0

                try:
                    conn.send(bytes(to_send))
                    with self._lock:
                        self._status["bytes_out"] += len(to_send)
                except OSError as e:
                    self._set(state="retrying", last_error=f"send: {e}", connected_since=None)
                    conn.close()
                    conn = None
                    last_connect = time.monotonic()
        finally:
            try:
                os.close(fifo_fd)
            except OSError:
                pass
            if conn is not None:
                conn.close()
            self._set(state=("idle" if self._stop.is_set() else "error"),
                      connected_since=None)

    def _connect(self, host, port, compress, global_hdr) -> "_Sink | None":
        try:
            s = socket.create_connection((host, port), timeout=5.0)
            s.settimeout(10.0)
        except OSError as e:
            self._set(state="retrying", last_error=f"connect {host}:{port}: {e}")
            return None
        try:
            sink = _Sink(s, compress)
            sink.send(global_hdr)          # fresh pcap header for this connection
        except OSError as e:
            self._set(state="retrying", last_error=f"handshake: {e}")
            try:
                s.close()
            except OSError:
                pass
            return None
        with self._lock:
            self._status.update(state="connected", connected_since=time.time())
            self._status["connects"] += 1
        log.info("pcap forward connected -> %s:%d", host, port)
        return sink


# process-wide singleton
forwarder = PcapForwarder()
