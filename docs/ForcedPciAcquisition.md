# Forced-PCI (exact) cell acquisition — `-N` flag

**What it does:** lets LTESniffer lock onto an **exact PCI** you specify (not just the
strongest cell in its PSS group), while still using the fast PSS/SSS + CFO
acquisition. Combine with `-l` (force N_id_2) for a full exact-PCI lock:

```
PCI = 3 * N_id_1 + N_id_2
    -l  <N_id_2 = PCI % 3>     forces the PSS group (already existed)
    -N  <N_id_1 = PCI / 3>     forces the SSS   (this change)
```
Example — lock exactly **PCI 240**: `-C -l 0 -N 80`  (240%3=0, 240/3=80).

## Why it was needed
Cell-search picks the **strongest** N_id_1 (SSS) in the group. So `-l` alone locks
the strongest cell in the group — fine when the target is the strongest/only one
(e.g. 237 vs 238, different groups), but wrong when a stronger cell shares the
group (e.g. 237 vs 240, both group 0). `-N` forces the exact SSS.

## How it works (the mechanism — verify here first if it breaks)
**REVISED 2026-07-09 (perf fix).** Exact-PCI is enforced by *auto-detect + filter*,
NOT by forcing the SSS sequence:
1. Normal SSS auto-detection runs during the scan (fast + robust — the same path
   a plain strongest-cell search uses).
2. In `srsran_ue_cellsearch_scan_N_id_2[_multi_usrp]` (ue_cell_search.c), a detected
   frame is **counted only if its full PCI == `3*force_N_id_1 + N_id_2`**; other
   cells in the group are ignored. `get_cell()` then returns the pinned PCI.
3. `-l` already limits the PSS search to the one N_id_2 group, so only that group
   is scanned.

**Old mechanism (removed from the search path, code still in sync.c):**
`srsran_sync_set_N_id_1()` → `sss_generated=1`, honoured by `sync_sss_symbol()`
(~517). It gated frame acceptance on a flaky sf0/sf5 correlation ratio > 1.2 that
**stalled acquisition ~1 min even when the pinned PCI was the strongest cell** —
that's the bug this revision fixes. If you ever want the old behaviour back, it's
still callable; just don't, it's slow.

## Where the code lives (all GUARDED by `force_N_id_1 >= 0`; default -1 = stock)
- `src/include/ArgManager.h` / `src/src/ArgManager.cc` — `-N` flag → `args.force_N_id_1`.
- `src/src/LTESniffer_Core.cc` — `cell_detect_config.force_N_id_1 = args.force_N_id_1;`
- `build/srsRAN-src/.../rf/rf_utils.h` — `force_N_id_1` field in `cell_search_cfg_t`.
- `build/srsRAN-src/.../rf/rf_utils.c` — `cs.force_N_id_1 = config->force_N_id_1;` in
  `rf_cell_search_multi_usrp`.
- `build/srsRAN-src/.../ue/ue_cell_search.h` — `force_N_id_1` field in the cellsearch struct.
- `build/srsRAN-src/.../ue/ue_cell_search.c` — in BOTH scan functions, the PCI-match
  filter on the detected `cell_id` (the old guarded `srsran_sync_set_N_id_1()` block
  was replaced by this).

## Rebuild after touching any of these
`cd build && make -j$(nproc)`  (rebuilds libsrsran_phy.a, libsrsran_rf.so, LTESniffer).

## If it misbehaves — quick triage
- **Locks the wrong PCI / a group-mate:** confirm `-N` reaches the scan
  (`q->force_N_id_1`), and that `sss_generated` is still true at `sync_sss_symbol`
  (a stray reset that clears it would break the force).
- **Won't lock at all:** `-N`/`-I` need real signal; also check `-l` = PCI%3 and
  `-N` = PCI/3 are consistent with the PCI, and the PRB matches.
- **Default runs changed:** should be impossible — everything is behind
  `force_N_id_1 >= 0`. If a stock run regressed, check the ArgManager default
  (`= -1`) and that `cell_detect_config.force_N_id_1` isn't left at 0.
- **Fastest sanity check:** `-l`/`-N` are ignored when `-C` is off; with `-C` and
  no `-N`, behaviour is identical to before this change.
