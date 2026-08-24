# LTESniffer ↔ GUI event protocol

Newline-delimited JSON (one event per line). Written to the file path passed
via the new `-J <path>` CLI flag. The path is typically a FIFO created by the
GUI backend; can also be a regular file for offline replay.

All events share:

- `t`: event type (string)
- `ts`: monotonic seconds since process start (float, 6 decimals)

## Events

### `hello`
Emitted once at startup, before anything else.
```json
{"t":"hello","ts":0.001,"version":1,"args":{"rf_freq":1840000000.0,"ul_freq":0.0,"sniffer_mode":0,"nof_prb":50,"nof_threads":4,"rnti":65535,"target_rnti":0,"cell_search":true,"rf_args":"","rf_gain":-1.0,"nof_rx_ant":1,"api_mode":-1}}
```

### `log`
Free-form log line. Backend forwards to UI for the live log panel.
```json
{"t":"log","ts":0.123,"level":"info","msg":"Cell found PCI=42"}
```
`level`: `debug | info | warn | error`.

### `cell`
Emitted once cell search completes (or when reconfigured for a new cell).
```json
{"t":"cell","ts":1.234,"pci":42,"nof_prb":50,"nof_ports":2,"cp":"normal","mode":"FDD","dl_freq":1840000000.0,"ul_freq":1745000000.0,"sample_rate":11520000.0}
```

### `mib`
MIB decoded. May fire multiple times during initial sync.
```json
{"t":"mib","ts":1.500,"sfn":123,"sfn_offset":2,"phich_length":"normal","phich_resources":"1/6"}
```

### `sf_tick` — lightweight per-subframe heartbeat
Emitted every subframe (up to 1000/s at real LTE rates). Cheap to parse and
cheap to render — frontend uses it to keep totals and rate-per-second tiles
moving even when `sf` is throttled. ~80 bytes wire size.
```json
{"t":"sf_tick","ts":12.345,"sfn":123,"sf":4,"cfi":2,"dl_n":1,"ul_n":0}
```
`dl_n` / `ul_n` = number of DCIs in this subframe; no per-DCI detail. Use the
upcoming `sf` event for the rich payload.

### `sf` — the main live event (rich)
Emitted at most every 20 ms (≤50 Hz wall-clock). Drops in frequency when the
C++ emitter is busy or the FIFO is backpressuring, but `sf_tick` continues
at full rate so the dashboard never goes blind.
```json
{
  "t":"sf",
  "ts":12.345678,
  "sfn":123,
  "sf":4,
  "cfi":2,
  "dl":[{"rnti":12345,"fmt":"1A","mcs":7,"nprb":4,"tbs":1024,"ndi":0,"harq":3,"ncce":0,"L":1,"hist":12,"hex":"abcd"}],
  "ul":[{"rnti":54321,"fmt":"0","mcs":11,"nprb":6,"tbs":2048,"ndi":1,"ncce":2,"L":2,"hist":7,"hex":"1234"}],
  "rb_dl":[0,0,12345,12345,0,0,0,0,0,0],
  "rb_ul":[],
  "pwr_dl":[-95.2,-94.1,-90.0,-88.5,-92.0],
  "pwr_min":-100.0,
  "pwr_max":-80.0
}
```
`rnti=0` (FALCON_UNSET_RNTI) in `rb_dl`/`rb_ul` means unallocated. DCI `fmt` is the
LTE format name (`"1A"`, `"2"`, `"0"`, etc.). `tbs` is bytes (transport block size).

### `identity`
API-mode identity discovery (IMSI, UECapa, identity mapping).
```json
{"t":"identity","ts":30.0,"sfn":1234,"kind":"imsi","rnti":12345,"value":"310410123456789","from":"AttachRequest"}
```
`kind`: `imsi | tmsi | guti | ue_capa | identity_map`.

### `stats`
Periodic decode statistics (default: every 1s).
```json
{"t":"stats","ts":30.0,"sfn":1234,"sf_processed":1000,"sf_skipped":3,"nof_rnti":18,"rb_dl_total":4500,"rb_ul_total":1200,"cfo_hz":-120.5,"rsrp_dbm":-85.3,"cpu_pct":62.0}
```

### `bye`
Final event, just before clean shutdown.
```json
{"t":"bye","ts":120.0,"reason":"signal","stats":{"sf_processed":120000,"sf_skipped":42}}
```

## Concurrency notes

- DCI consumers may run on worker threads. The JSON emitter must serialize
  writes (mutex around the line write + `fflush`).
- Events are flushed line-by-line so a partial line is never visible to the
  reader.
- The emitter installs a `SIG_IGN` for `SIGPIPE` so dying readers don't kill
  the sniffer.
