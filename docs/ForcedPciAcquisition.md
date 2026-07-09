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
1. `srsran_sync_set_N_id_1(sync, N_id_1)` (sync.c) → `generate_freq_sss()` →
   sets `q->sss_generated = true` and builds the SSS for that N_id_1.
2. `sync_sss_symbol()` (sync.c ~517): **if `sss_generated`, it USES `q->N_id_1`**
   instead of deriving the strongest from correlation. This is the whole trick.
3. `srsran_sync_reset()` (sync.c ~845) does **not** clear `sss_generated` — so the
   forced value survives the reset the scan does before its find loop.

## Where the code lives (all GUARDED by `force_N_id_1 >= 0`; default -1 = stock)
- `src/include/ArgManager.h` / `src/src/ArgManager.cc` — `-N` flag → `args.force_N_id_1`.
- `src/src/LTESniffer_Core.cc` — `cell_detect_config.force_N_id_1 = args.force_N_id_1;`
- `build/srsRAN-src/.../rf/rf_utils.h` — `force_N_id_1` field in `cell_search_cfg_t`.
- `build/srsRAN-src/.../rf/rf_utils.c` — `cs.force_N_id_1 = config->force_N_id_1;` in
  `rf_cell_search_multi_usrp`.
- `build/srsRAN-src/.../ue/ue_cell_search.h` — `force_N_id_1` field in the cellsearch struct.
- `build/srsRAN-src/.../ue/ue_cell_search.c` — in the scan, after `set_N_id_2`, the
  guarded `srsran_sync_set_N_id_1()` on `sfind`+`strack` (injected in BOTH scan
  functions).

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
