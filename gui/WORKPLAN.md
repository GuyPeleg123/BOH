# LTESniffer GUI — Phase 1-4 Work Plan

Detailed, executable breakdown of the improvement plan from the v2 inspection report. Items listed in execution order *within* each phase (later items often depend on earlier ones inside the same phase). Each item has:

- **ID** — matches inspection-report finding ID
- **Goal** — what changes for the operator after this lands
- **Files** — what gets touched
- **Approach** — concrete implementation sketch
- **Validation** — how to know it works
- **Dependencies** — other items that must be done first
- **Effort** — Claude-time / your-time / real-hardware-time

> "Claude-time" = the wall time of me coding it. "Your-time" = your effort to validate / review / iterate. "Hardware-time" = elapsed time for tests that need a real USRP capture, which I cannot do without you.

---

## Phase 1 — Hygiene & safety

**Goal of the phase:** the GUI can be left running on a research LAN without (a) handing out root, or (b) silently wedging after a few hours.

### 1.1 — B1+B2: `O_NONBLOCK` FIFO + `stdout=DEVNULL` (deadlock fix)
- **Files:** `src/include/JSONEmitter.h`, `src/src/JSONEmitter.cc`, `gui/backend/sniffer.py`
- **Approach:**
  - In `JSONEmitter::JSONEmitter`, after `fopen`, do `fcntl(fileno(fp), F_SETFL, O_NONBLOCK)`. Inside `writeLine`, catch `errno == EAGAIN`, bump a `dropped_events_` counter, surface it in the next `stats` event.
  - In `sniffer.py:132`, change `stdout=asyncio.subprocess.PIPE` → `asyncio.subprocess.DEVNULL`.
- **Validation:** mock-mode is fine; the fix is for failure paths. Force-kill the backend mid-capture; the C++ should exit cleanly within a few seconds (no orphan in `ps`).
- **Deps:** none.
- **Effort:** Claude 15 min · your 5 min · hardware-time 0.

### 1.2 — S1: allowlist `binary_path`
- **Files:** `gui/backend/config.py`, `gui/backend/sniffer.py`
- **Approach:**
  - Add `_ALLOWED_BINARY_PATHS` constant: repo `build/src/LTESniffer` (absolute) + `/usr/local/bin/LTESniffer`. In `SnifferRunner.start`, resolve `cfg.binary_path` to absolute; reject with 403 if not in allowlist.
- **Validation:** `PUT /api/config` with `binary_path: "/usr/bin/id"` → 403.
- **Deps:** none.
- **Effort:** Claude 30 min · your 10 min · hardware-time 0.

### 1.3 — S3: config 0600 file permissions
- **Files:** `gui/backend/config.py`
- **Approach:**
  - After `path.write_text()` in `config.save`, `os.chmod(path, 0o600)`. `mkdir(mode=0o700)` for parents.
- **Validation:** `stat -c %a ~/.config/ltesniffer-gui/config.json` → 600.
- **Deps:** none.
- **Effort:** Claude 15 min · your 5 min · hardware-time 0.

### 1.4 — S2: default `--host 127.0.0.1` + bearer token
- **Files:** `gui/backend/main.py`, `gui/backend/auth.py` (new), `gui/frontend/src/lib/api.ts`, `gui/frontend/src/lib/store.ts`
- **Approach:**
  - Read `LTESNIFFER_GUI_BIND` env var; default `127.0.0.1`. Print a red startup banner if `0.0.0.0` ("WARNING: exposed on all interfaces, no firewall managed by GUI").
  - On first run, generate a 256-bit token, write to `~/.config/ltesniffer-gui/token` mode 0600, log the path so the operator can copy it.
  - FastAPI dependency `require_token` that reads `Authorization: Bearer <hex>` for REST and `?token=<hex>` for WS upgrade. Skip when `LTESNIFFER_GUI_BIND=127.0.0.1` is in effect AND request comes from loopback (so the local dashboard doesn't need it).
  - Frontend: when fetch returns 401, read `?token=` from URL or `localStorage["gui_token"]`; prompt for it; persist.
  - CORS: restrict `allow_origins` to `["http://127.0.0.1:8000", "http://localhost:8000", "http://localhost:5173"]`. Drop `allow_credentials` if `*` is still wanted (it isn't).
- **Validation:** start without env var → bind only to 127.0.0.1. `curl http://192.168.x.x:8000/api/health` from another host → connection refused. With `LTESNIFFER_GUI_BIND=0.0.0.0` → reachable but every endpoint returns 401 without token; with token works.
- **Deps:** none (but pairs naturally with 1.2/1.3 since they're all the security cluster).
- **Effort:** Claude 1.5 hours · your 20 min (test loopback + LAN access) · hardware-time 0.

### 1.5 — B3+B4: drop-oldest queue + batched replay envelope
- **Files:** `gui/backend/sniffer.py`, `gui/backend/mock.py`, `gui/backend/main.py`, `gui/frontend/src/lib/store.ts`
- **Approach:**
  - In `_broadcast`, replace queue-full-evict with: `try q.put_nowait(event) except QueueFull: q.get_nowait(); q.put_nowait(event); dropped += 1`. Emit a `log` event every N drops.
  - In `main.py /api/events`, send replay as one envelope `{"t":"replay","events":[...]}` and only after that start the live loop on a fresh subscriber queue.
  - Frontend reducer: handle `{"t":"replay","events":[…]}` by recursing the event-apply loop on the inner array.
- **Validation:** subscribe a slow client (insert `await asyncio.sleep(0.5)` in WS loop) under mock at 50 sf/s → queue should never wedge; "dropped N events" log should appear; client keeps receiving newest.
- **Deps:** none.
- **Effort:** Claude 45 min · your 5 min · hardware-time 0.

**Phase 1 totals:** Claude ~3.5 hours · your ~45 min validation · hardware-time 0.

### Phase 1 — Validation & Sanity Check (run before moving to Phase 2)

**Automated** — re-run the existing Playwright verify script. Expect: still 41/42 PASS (the one timing-flaky hover test is unaffected).
```
.venv/bin/python /tmp/verify_full.py
```

**Backend regression checks**:
- `curl http://127.0.0.1:8000/api/health` → `{"ok":true, ...}`  *(loopback still works)*
- `curl http://192.168.x.x:8000/api/health` → **connection refused** *(LAN bind off by default)*
- `LTESNIFFER_GUI_BIND=0.0.0.0 .venv/bin/uvicorn ...` then from LAN: `curl …/api/health` → **401** without token, **200** with `Authorization: Bearer $(cat ~/.config/ltesniffer-gui/token)`.
- `stat -c %a ~/.config/ltesniffer-gui/config.json` → **600**
- `PUT /api/config '{"binary_path":"/usr/bin/id"}'` → **403** (allowlist)

**Orphan / wedge regression**:
- Start backend in real mode. Send `kill -9` to uvicorn. `pgrep -x LTESniffer` should return **nothing** within ~10 s (kill-script + lifespan shutdown).
- Start mock, force 4× simultaneous WS connections, insert artificial `asyncio.sleep(0.5)` in one of them → other 3 should keep receiving events without freezing.

**Manual smoke**:
- [ ] Dashboard loads, shows cell card with PCI (or "waiting for cell")
- [ ] Start/Stop/Restart capture buttons all work
- [ ] Captures tab lists pcaps, download link works
- [ ] Spectrum button: opens popover (still disabled in mock — that's intended)
- [ ] Config page: edit DL freq → Save → reload → value persists

**Go / no-go for Phase 2**: all automated checks PASS, all manual checks ✓, no new console errors in browser DevTools.

---

## Phase 2 — Performance foundation

**Goal of the phase:** the system can sustain real LTE rates (1000 sf/s + 100 PRB) without (a) the frontend hitting render storms, (b) the backend's WS fanout dominating CPU, or (c) USB-3 dropping samples.

### 2.1 — F24: UHD `num_recv_frames=512` + `rmem_max` sysctl
- **Files:** `gui/backend/config.py`, `gui/backend/sniffer.py`, `gui/SETUP.md` (new)
- **Approach:**
  - In `SnifferConfig.to_argv` (or wherever the rfargs string is assembled), if user didn't override, append `num_recv_frames=512,recv_frame_size=8000` to `rf_args` / `usrp_a_args` / `usrp_b_args`. **(Already partly present — verify.)**
  - At backend startup, read `/proc/sys/net/core/rmem_max`; if `< 24576000` print a warning with the fix command.
- **Validation:** `cat /proc/sys/net/core/rmem_max` should be >=24M after `sudo sysctl -w net.core.rmem_max=24576000`. With a USRP attached, run a stress capture and grep for "O" / "D" overflow markers in stderr.
- **Deps:** none.
- **Effort:** Claude 20 min · your 5 min · hardware-time 5 min stress capture.

### 2.2 — F39: PCFICH-aware decoder cost reduction
- **Files:** `src/src/LTESniffer_Core.cc`, possibly `falcon/src/lib/falcon/phy/falcon_ue/falcon_ue_dl.c`
- **Approach:** Inspect the PDCCH blind-search call site. If the search currently iterates AL × all 3 PCFICH symbol counts unconditionally, gate on the decoded `n_pdcch_symbols` value (PCFICH must be decoded first). Many cells run PCFICH=1 or 2 in low-load conditions → ~30% of the search-space work is skipped.
- **Validation:** run mock — no change (PCFICH always 2). With real capture, log "skipped X candidates due to PCFICH" counter; compare CPU usage with/without flag.
- **Deps:** none.
- **Effort:** Claude 1 hour · your 10 min · hardware-time 15 min comparison.

### 2.3 — B5: cache encoded JSON bytes for WS fanout
- **Files:** `gui/backend/sniffer.py`, `gui/backend/mock.py`, `gui/backend/main.py`
- **Approach:**
  - Backend already reads each FIFO line as bytes and `json.loads`-es it once to detect `t` for sticky. Hang the original `bytes` on a wrapper `class Event(dict): bytes_repr: bytes`. In WS loop, `await ws.send_text(event.bytes_repr.decode())` (no re-`dumps`).
  - For events the backend constructs internally (mock, lifecycle), `json.dumps` once at construction.
- **Validation:** in mock at 50 sf/s with 4 WS clients open, profile backend CPU before/after with `py-spy`. Expect ~70-80% drop in `json.dumps` time.
- **Deps:** 1.5 (replay envelope changes the path).
- **Effort:** Claude 1 hour · your 10 min · hardware-time 0.

### 2.4 — A1: tiered emission rate (C++ + protocol + frontend)
- **Files:** `src/include/JSONEmitter.h`, `src/src/JSONEmitter.cc`, `gui/PROTOCOL.md`, `gui/frontend/src/lib/store.ts`, `gui/frontend/src/lib/types.ts`
- **Approach:**
  - New event `sf_tick` (≤80 bytes: `t,ts,sfn,sf,cfi,dl_n,ul_n`) emitted every subframe.
  - Existing `sf` (with `dl[]`, `ul[]`, `rb_dl[]`, `rb_ul[]`, `pwr_dl[]`) downsampled to ≤50 Hz wall-clock. C++ side keeps a timestamp; emits the rich event when `(now - last_rich) > 20ms`; otherwise just `sf_tick`.
  - Frontend reducer adds a cheap path for `sf_tick` (totals, monotonic, no map churn).
- **Validation:** mock should still show ~50 sf events/sec (mock is already 50 Hz). Real-LTE capture: WS bytes/sec drops ~5x.
- **Deps:** 2.3 (caching).
- **Effort:** Claude 2 hours · your 15 min · hardware-time 15 min.

### 2.5 — A5/P1: external store with selectors (the big frontend lift)
- **Files:** `gui/frontend/package.json`, `gui/frontend/src/lib/store.ts`, every component that calls `useStore()` (`StatusBar`, `CellCard`, `CaptureControls`, `MetricsTiles`, `RNTITable`, `RBWaterfall`, `LogPanel`, `IdentitiesPanel`, `PacketFeed`, `SpectrumButton`)
- **Approach:**
  - Add `zustand` (~3 KB gzip) OR roll our own `useSyncExternalStore` + subscriber set. Decision factor: zustand has nicer middleware (devtools, persist) but adds a dep. Recommend zustand.
  - Each component converts `const { state } = useStore()` → `const cell = useStore(s => s.cell)`. Object slices use `shallow` equality.
  - Reducer becomes a single function on the store with `setState(prev => …)`.
- **Validation:** open React DevTools profiler with the dashboard idle → previously every batch caused 10 re-renders; now should be 0 when nothing changed in their slice. Visible smoothness improvement on RNTITable's "Last" column.
- **Deps:** none, but big surface — best done after Phase 1 is in main.
- **Effort:** Claude 2 hours · your 30 min QA pass · hardware-time 0.

**Phase 2 totals:** Claude ~7 hours · your ~1.5 hours validation · hardware-time ~35 min.

### Phase 2 — Validation & Sanity Check

**Performance baselines** — take these *before* Phase 2 and again *after*:
- Backend CPU under mock, 1 WS client: `top -p $(pgrep -f 'uvicorn main:app')` for 30 s. Before: ~X%. After 2.3: should drop noticeably.
- Backend CPU under mock, 4 WS clients open: should be roughly the same as 1 client (vs. ~4× before).
- Frontend React DevTools profiler, dashboard idle for 5 s: count "renders" on `RNTITable`, `CellCard`, `StatusBar`. Before 2.5: ~75 each. After 2.5: should be near 0 (only when their slice actually changes).
- Browser memory after 10 min of mock capture: shouldn't grow unbounded.

**Functional regression**:
- Re-run Playwright `/tmp/verify_full.py`. Still 41/42 PASS.
- All Phase 1 manual smoke items still tick.
- Mock-mode behavior unchanged: same UEs, same RB waterfall, same packet feed, same tile values (different *render cadence*, same content).
- Mock subframe rate after A1 tiered emission: still ~50/s of *something* (rich `sf` ≤ 50 Hz, `sf_tick` fills the rest). Backend log shows both event types.

**Real-hardware sanity** (if a USRP is plugged in):
- Start a 60 s real capture. Grep stderr for `O` / `D` overflow markers — should be substantially fewer than before F24's buffer-tuning.
- `dmesg | tail` — no USB resets during capture.

**Go / no-go for Phase 3**: zero functional regressions, perf baselines measurably improved on at least 2 of the 4 metrics above.

---

## Phase 3 — Pipeline expansion

**Goal of the phase:** capture data flows into the rest of your toolchain (Wireshark, Grafana, ZMQ consumers, ELK) and old sessions can be replayed offline.

### 3.1 — F25: overflow markers in pcap
- **Files:** `src/src/LTESniffer_Core.cc`, `src/src/PcapWriter.cc` (or wherever)
- **Approach:** subscribe to UHD's async-msg queue; when `EVENT_CODE_OVERFLOW` arrives, write a synthetic GSMTAP frame with a sentinel SubID so Wireshark filter `gsmtap.subid == 0xff && gsmtap.payload == "OVF"` finds them.
- **Validation:** stress capture → confirm markers appear in pcap, timestamps line up with stderr "O" log lines.
- **Deps:** none.
- **Effort:** Claude 30 min · your 5 min · hardware-time 10 min.

### 3.2 — F26: chrony + GPSDO PPS as refclock
- **Files:** `gui/SETUP.md`, `scripts/setup-chrony-gpsdo.sh` (new)
- **Approach:** documentation + one-shot script that appends `refclock SHM 0 refid GPS poll 4 precision 1e-9 prefer` to `/etc/chrony/chrony.conf`, restarts chronyd, prints `chronyc tracking` output.
- **Validation:** `chronyc sources` shows GPS as reference; `date +%N` resolution is sub-millisecond.
- **Deps:** USRP plugged in with GPSDO enabled (hardware).
- **Effort:** Claude 20 min · your 5 min · hardware-time 5 min.

### 3.3 — A4: pcap rotation
- **Files:** `src/include/PcapWriter.h`, `src/src/PcapWriter.cc`, `src/include/ArgManager.h`, `src/src/ArgManager.cc`
- **Approach:**
  - PcapWriter takes a `--pcap-rotate-mb N` (default 200) and `--pcap-rotate-min N` (default 0 = off). Tracks bytes-written; on rotation closes current file, opens new one named `ltesniffer_<mode>_<iso8601>_<seq>.pcap`.
  - On open emits a `lifecycle:pcap_rotated {old: path, new: path}` JSON event.
- **Validation:** force `--pcap-rotate-mb 1` and a busy capture → multiple files appear in captures_dir. Captures tab on dashboard lists all.
- **Deps:** none.
- **Effort:** Claude 1 hour · your 10 min · hardware-time 5 min.

### 3.4 — F13: GSMTAP UDP output
- **Files:** `src/include/GsmtapWriter.h` (new), `src/src/GsmtapWriter.cc` (new), wire-in inside LTESniffer_Core
- **Approach:** new optional output sink; binds a UDP socket to `127.0.0.1:4729` (configurable), wraps each MAC-LTE frame in GSMTAP per [Wireshark wiki spec](https://wiki.wireshark.org/GSMTAP), `sendto` per frame. CLI flag `--gsmtap host:port`.
- **Validation:** run capture, `sudo wireshark -k -i lo -f "udp port 4729"`. Live frames appear with RRC/NAS dissection.
- **Deps:** none.
- **Effort:** Claude 1 hour · your 10 min · hardware-time 10 min.

### 3.5 — F12: live PCAP-over-IP for Wireshark
- **Files:** `src/include/PcapStreamer.h` (new), `src/src/PcapStreamer.cc` (new), wire-in
- **Approach:** alternative to PcapWriter; listens on `127.0.0.1:19000` (configurable), accepts a single TCP client, writes libpcap global header on connect, frames thereafter.
- **Validation:** `wireshark -k -i tcp@127.0.0.1:19000` (Wireshark 4.x supports this natively) → live frames.
- **Deps:** 3.3 (sharing the format/sink design).
- **Effort:** Claude 45 min · your 10 min · hardware-time 5 min.

### 3.6 — A3: session recorder + replay
- **Files:** `gui/backend/recorder.py` (new), `gui/backend/mock.py` (extend to support replay-from-file), `gui/backend/main.py`
- **Approach:**
  - `recorder.py` provides a tee that subscribes to `runner._broadcast` events and writes them to `~/.local/share/ltesniffer-gui/sessions/<iso8601>.jsonl.zst`. Rolls every 50 MB.
  - New env var `LTESNIFFER_GUI_REPLAY=<file>` swaps `SnifferRunner` for `ReplayRunner` which reads the file with real-time pacing (or `--ff` for as-fast-as-possible).
- **Validation:** record a 5-minute mock session, then restart backend with `LTESNIFFER_GUI_REPLAY=<file>` → dashboard plays back identically.
- **Deps:** A1 tiered emission (cleaner replay if both event types coexist).
- **Effort:** Claude 1.5 hours · your 15 min · hardware-time 0.

### 3.7 — F27: Prometheus / Grafana exporter
- **Files:** `gui/backend/metrics.py` (new), `gui/backend/main.py`
- **Approach:** use `prometheus_client` (Python). Counters: `dci_decoded_total{dir}`, `pcap_bytes_total`, `rnti_active`, `subframes_skipped_total`, `overflow_events_total`. Gauges: `cfo_hz`, `mcs_histogram`. Expose at `/metrics`.
- **Validation:** `curl /metrics` → Prometheus exposition format. Hook up a local Prometheus + Grafana with the dashboards JSON checked into `grafana/`.
- **Deps:** A5 (so the backend isn't already CPU-bound).
- **Effort:** Claude 45 min · your 10 min · hardware-time 0.

### 3.8 — F43: ZeroMQ pub/sub publisher
- **Files:** `gui/backend/zmq_publisher.py` (new), `gui/backend/main.py`
- **Approach:** subscribe to runner events; PUB socket on `tcp://127.0.0.1:5555`; topic = event `t`. Skip large `sf` events when sample-rate would saturate (configurable).
- **Validation:** Python subscriber `zmq.Context().socket(zmq.SUB); s.connect("tcp://127.0.0.1:5555"); s.subscribe(b"sf");` prints subframes live.
- **Deps:** none.
- **Effort:** Claude 30 min · your 5 min · hardware-time 0.

**Phase 3 totals:** Claude ~6 hours · your ~1 hour validation · hardware-time ~30 min.

### Phase 3 — Validation & Sanity Check

**Pipeline smoke**:
- `curl http://127.0.0.1:8000/metrics | head` → valid Prometheus exposition format (lines like `dci_decoded_total{dir="dl"} 12345`).
- `wireshark -k -i tcp@127.0.0.1:19000` (or via menu) — frames stream live with MAC-LTE dissection. Stop a capture mid-stream → Wireshark continues showing the buffer.
- `wireshark -k -i lo -f "udp port 4729"` — GSMTAP frames decoded as RRC/NAS.
- Python ZMQ subscriber:
  ```python
  import zmq, json
  s = zmq.Context().socket(zmq.SUB)
  s.connect("tcp://127.0.0.1:5555"); s.subscribe(b"sf")
  while True: print(s.recv_multipart()[1][:80])
  ```
  → prints subframes live.
- Force pcap rotation with `--pcap-rotate-mb 1` and a busy capture: multiple files appear in captures_dir, Captures tab lists all, each is openable in Wireshark independently.

**Session recorder**:
- Run a 3-min mock capture; confirm `~/.local/share/ltesniffer-gui/sessions/<ts>.jsonl.zst` exists and `zstdcat … | wc -l` shows expected event count.
- Restart backend with `LTESNIFFER_GUI_REPLAY=<file>`; dashboard replays identically.
- `--ff` mode: same replay completes much faster (no real-time pacing).

**Functional regression**:
- Re-run `/tmp/verify_full.py`. Still 41/42 PASS.
- All Phase 1+2 manual smoke items still tick.
- Pcap files from before this phase still openable (no format breaking).
- Overflow markers visible in pcaps from real captures (stress test).

**Time / disk**:
- `chronyc tracking` shows GPS as reference, stratum 1.
- `df -h ~/.local/share/ltesniffer-gui/sessions/` — confirm session storage doesn't fill the disk (rotation working).
- Verify chrony didn't break system NTP for other consumers.

**Go / no-go for Phase 4**: every external consumer (Wireshark live, Prometheus, ZMQ, GSMTAP, session recorder/replay) sees expected data. No regression on the existing dashboard.

---

## Phase 4 — Statefulness & coverage

**Goal of the phase:** the sniffer no longer treats each subframe in isolation. UEs are tracked across their full session (RA → RRC setup → C-RNTI → S-TMSI → handover) and a single capture correctly handles carrier-aggregation and multi-cell scenarios.

### 4.1 — F21: PHICH decoder + per-RNTI link-quality timeseries
- **Files:** `src/src/LTESniffer_Core.cc`, `src/include/PhichDecoder.h` (new)
- **Approach:** use `srsran_phich_decode()` (already in srsRAN). Annotate each UE's per-subframe ACK/NACK; emit a new `phich` JSON event per detected ACK/NACK.
- **Validation:** any cell with active UL traffic should show ACKs flowing. Logs per-RNTI ACK rate.
- **Deps:** none.
- **Effort:** Claude 1 hour · your 15 min · hardware-time 15 min.

### 4.2 — F18: PRACH preamble logger + RA-RNTI ↔ C-RNTI binding
- **Files:** `src/include/RaEventLogger.h` (new), `src/src/RaEventLogger.cc` (new), hooks in PUSCH/PDSCH decoders
- **Approach:** intercept Msg2 (RAR), parse RA-RNTI and the TC-RNTI it contains; intercept Msg3 (PUSCH UL with TC-RNTI); intercept Msg4 (PDSCH with contention resolution); persist the full RA sequence as one JSON event `ra_event` with timestamps and TA value.
- **Validation:** with a UE attaching nearby (phone airplane-mode-toggle), see `ra_event` events in the log feed with sensible TA values. Real LTE: RAR / Msg3 timing is tight (3-4 ms); confirm we don't miss them.
- **Deps:** 4.1 (PHICH gives us a parallel signal to cross-check).
- **Effort:** Claude 2 hours · your 20 min · hardware-time 1 hour (need a phone to control).

### 4.3 — F6: RNTIChurnAnalyzer
- **Files:** `gui/backend/analytics.py` (new) or C++ side `src/include/RntiChurnAnalyzer.h`
- **Approach:** time-series of (RNTI activation → idle → reuse). Estimate per-cell median reuse timer from data. Surface in the dashboard as a stat ("avg RNTI lifetime: X.X min, reuse delay: Y.Y min").
- **Validation:** runs offline against any sufficiently long capture. The OWL paper publishes expected ranges (minutes, varies by operator).
- **Deps:** 4.2 (RA events give clean activations).
- **Effort:** Claude 1 hour · your 10 min · hardware-time 30 min.

### 4.4 — F11: UEStateTracker (RA → RRC → CRNTI → STMSI)
- **Files:** `src/include/UeStateTracker.h` (new), `src/src/UeStateTracker.cc` (new), hooks in RRC + NAS decoders
- **Approach:** state machine per C-RNTI: `IDLE → MSG3_SENT → RRC_SETUP → SECURITY_ACTIVE → DATA → IDLE`. On NAS S-TMSI / IMSI / GUTI seen, attach to the current state. Emits `ue_state` JSON events on transitions.
- **Validation:** with a phone attaching, see clean transitions through all states. Eventual binding RNTI → S-TMSI → IMSI.
- **Deps:** 4.2.
- **Effort:** Claude 3 hours · your 30 min · hardware-time 1-2 hours.

### 4.5 — F33: SCell inventory from RRC reconfig
- **Files:** `src/include/CarrierAggregationManager.h` (new), `src/src/CarrierAggregationManager.cc` (new), hook in RRCConnectionReconfiguration handler
- **Approach:** parse `sCellToAddModList` from the RRC blob; emit `scell_config` events. Store the SCells expected per UE.
- **Validation:** on an LTE-A network with active CA UEs, see SCell configs appear when UEs are on a CA-capable contract.
- **Deps:** 4.4.
- **Effort:** Claude 1 hour · your 10 min · hardware-time 30 min.

### 4.6 — F3: Carrier-Indicator-Field (CIF) cross-carrier decoding
- **Files:** `src/src/Dci/*.cc` (DCI parser), `src/src/LTESniffer_Core.cc`
- **Approach:** when cell config indicates CrossCarrierSchedulingConfig is on, parse the 3-bit CIF in DCIs; route grants to the appropriate per-carrier decoder.
- **Validation:** needs an LTE-A cell using CIF. Visible by comparing reported PRB utilization on SCells vs PCell.
- **Deps:** 4.5.
- **Effort:** Claude 1.5 hours · your 15 min · hardware-time 30 min.

### 4.7 — F2: NG-Scope-style multi-cell aggregator
- **Files:** `src/include/MultiCellAggregator.h` (new), `src/src/MultiCellAggregator.cc` (new), refactor of `src/main.cpp` to spawn N worker `LTESniffer` instances
- **Approach:**
  - Refactor the existing `LTESniffer` class to be reusable as a per-cell engine.
  - `MultiCellAggregator` owns N engines (configured via `--cell f1,prb1,... --cell f2,prb2,...`). Each engine has its own SDR (B210 per cell).
  - All emit into a shared event bus tagged with `cell_id`. Frontend store keys by `cell_id`.
  - GUI dashboard gets a cell selector / "view all cells" tab.
- **Validation:** with two B210s pointed at two different EARFCNs from the same operator, both should show RNTIs (likely overlapping if UE is in CA).
- **Deps:** 4.5, 4.6.
- **Effort:** Claude 4 hours (refactor heavy) · your 1 hour · hardware-time 2 hours (need known multi-cell scenario).

**Phase 4 totals:** Claude ~13.5 hours · your ~2.5 hours · hardware-time ~6 hours (the latter is the *real* gating factor — needs a phone you control + nearby cell + ideally CA service plan).

### Phase 4 — Validation & Sanity Check

**Statefulness smoke** (requires a phone you control + a B210 capturing the local cell):
- Toggle phone airplane-mode OFF → confirm a `ra_event` JSON event fires in the dashboard log feed within ~1s, with sensible TA (0-1282 range) and a TC-RNTI in the expected 0x003D-0xFFF3 range.
- Same toggle → confirm `ue_state` transitions appear in order: `IDLE → MSG3_SENT → RRC_SETUP → SECURITY_ACTIVE → DATA`.
- Toggle airplane-mode ON → state machine returns to `IDLE` within ~30s.
- Per-RNTI ACK counters (PHICH) tick up during phone data transfer; flat when phone is idle.
- Open a CA-capable app (any video streaming over LTE-A) — confirm `scell_config` events appear with the SCell EARFCN/PCI.

**Multi-cell smoke** (requires 2 B210s on separate USB-3 controllers, both pointed at known EARFCNs from the same operator):
- `--cell f=1842500000,prb=50 --cell f=816000000,prb=25` (or whatever your local network has).
- Dashboard shows two cell cards; switching tabs shows separate RNTI tables per cell.
- A phone that does CA: same RNTI value visible on both cells simultaneously (correctly correlated by `MultiCellAggregator`).
- Capture stats per cell are independent — stopping one cell doesn't affect the other.

**Functional regression**:
- Re-run `/tmp/verify_full.py`. Still 41/42 PASS.
- All Phase 1-3 manual smoke items still tick.
- Single-cell mode (no `--cell` flag) still works exactly as before.
- Mock mode still works (state tracker has a mock data path).

**Stability**:
- Run a 2-hour capture; CPU and memory shouldn't grow unbounded.
- No "stalled" warnings from the heartbeat (Phase 4 implies A6 from Tier 4 was also done).
- Force-stop mid-capture: clean exit, no orphan, all state files closed (`lsof | grep ltesniffer` empty after stop).

**Go / no-go for Phase 5 (if you choose to continue)**: every UE-attach event we can observe gets correctly bound through the state machine. Multi-cell aggregator doesn't double-count or drop traffic. No regression in any prior phase's flows.

---

## Universal regression baseline (run after every commit)

Before declaring any item "done":
1. `npm run build` in `gui/frontend/` exits 0 with no new warnings.
2. `python3 -c "import ast; ast.parse(open(f).read())" for f in gui/backend/*.py` — all parse cleanly.
3. `git status` is clean (no stray untracked files).
4. Backend starts in both real and mock mode within 5 s; `/api/health` returns ok.
5. WebSocket connects within 1 s of page load.
6. No new uncaught exceptions in either backend or browser console.

If any check fails, the item is not done and we roll back before continuing.

---

## Cumulative

| Phase | Claude | You | Hardware |
|---|---|---|---|
| 1 | 3.5 h | 45 min | 0 |
| 2 | 7 h | 1.5 h | 35 min |
| 3 | 6 h | 1 h | 30 min |
| 4 | 13.5 h | 2.5 h | 6 h |
| **Total** | **30 h** | **5.75 h** | **~7 h** |

In wall-clock: Phase 1 in one sitting, Phase 1+2 over a long day, all of 1-3 in a weekend, Phase 4 needs ~1 week of intermittent iteration because of real-RF validation loops.

## Suggested order of operations

1. **Commit the pending 4 files** so we're at a clean baseline.
2. **Phase 1** end-to-end in one session — security cluster is logically one unit.
3. **Phase 2.1, 2.2, 2.3** in one session — backend perf.
4. **Phase 2.4 + 2.5** in a second session — protocol + frontend store refactor (biggest single change).
5. **Phase 3** all in one session — most items are 30-min additions.
6. **Phase 4** broken into per-feature sittings, each with a hardware-validation step.

## Trigger commands you'll give me

You don't need to memorize anything — natural language like "start phase 1" or "do 1.1 and 1.2 first" works. Specific item IDs (e.g. "do 2.5") let you skip around.

Quick check before any phase: `git status` should be clean. After every item I'll show you the diff + propose a commit.
