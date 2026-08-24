import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useStore, shallow } from "../lib/store";

export function CaptureControls({ compact = false }: { compact?: boolean }) {
  const state = useStore((s) => ({ lifecycle: s.lifecycle, argv: s.argv }), shallow);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [ulFreqMissing, setUlFreqMissing] = useState(false);
  const [pinCfg, setPinCfg] = useState<{ cell_id: number; force_n_id_2: number } | null>(null);
  const running = state.lifecycle === "running";

  // Re-fetch config on every mount (= every Dashboard navigation) and after
  // lifecycle changes so the UL freq guard reflects the latest saved config.
  useEffect(() => {
    api.getConfig()
      .then((c) => {
        const needsUl = (c.sniffer_mode === 1 || c.sniffer_mode === 2) && c.ul_freq === 0;
        setUlFreqMissing(needsUl);
        setPinCfg({ cell_id: c.cell_id, force_n_id_2: c.force_n_id_2 });
      })
      .catch(() => {});
  }, [state.lifecycle]);

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  // Pin (fast targeted search, constrained to the PCI's PSS group) vs strongest
  // (unconstrained search). Both use fast cell-search; pin just narrows to the
  // target's group. Sets force_n_id_2 so the NEXT Start/Restart uses that mode.
  async function togglePin(pin: boolean) {
    await run(async () => {
      const full = await api.getConfig();
      full.cell_search = true;                                       // always fast search
      full.force_n_id_2 = pin ? (full.cell_id % 3) : -1;             // pin => PSS group (-l)
      full.force_n_id_1 = pin ? Math.floor(full.cell_id / 3) : -1;   // pin => SSS (-N) => EXACT PCI
      await api.putConfig(full);
      setPinCfg({ cell_id: full.cell_id, force_n_id_2: full.force_n_id_2 });
    });
  }

  const pinToggle = pinCfg && (
    <label className="flex items-center gap-1.5 text-xs cursor-pointer"
      title="On: fast lock of the EXACT PCI (forces the PSS group + SSS via -l/-N). Off: search & lock the strongest cell overall. Applies to the next Start/Restart.">
      <input type="checkbox" checked={pinCfg.force_n_id_2 >= 0} disabled={busy || running}
        onChange={(e) => togglePin(e.target.checked)} />
      <span>Pin PCI {pinCfg.cell_id} <span className="text-muted">(exact; off = strongest)</span></span>
    </label>
  );

  const startDisabled = busy || running || ulFreqMissing;
  const startTitle = ulFreqMissing
    ? "UL frequency is not set — go to Config and set UL frequency before starting"
    : undefined;

  // Visual state: highlight the action that matches the current lifecycle,
  // ghost the others. Concretely:
  //   * stopped  → Start is solid, Stop/Restart are subdued
  //   * running  → Stop  is solid, Start (disabled) and Restart are highlighted
  // This is mostly cosmetic but in busy dashboards the right next-action
  // jumps out at a glance.
  const startCls   = !running ? "btn btn-ok"           : "btn btn-ok opacity-50";
  const stopCls    = running  ? "btn btn-danger"       : "btn btn-danger opacity-50";
  const restartCls = "btn btn-primary";

  const body = (
    <>
      <button
        className={startCls}
        disabled={startDisabled}
        title={startTitle ?? (running ? "Already running — use Restart" : "Start a new capture")}
        onClick={() => run(() => api.start())}
      >
        <span aria-hidden>▶</span> Start
      </button>
      <button
        className={stopCls}
        disabled={busy || !running}
        title={running ? "Stop the running capture" : "No capture is running"}
        onClick={() => run(() => api.stop())}
      >
        <span aria-hidden>■</span> Stop
      </button>
      <button
        className={restartCls}
        disabled={busy}
        title="Stop (if running) and start fresh"
        onClick={() => run(() => api.restart())}
      >
        <span aria-hidden>⟳</span> Restart
      </button>
      {/* Dense Test: runs the from-scratch calibrated-window UL decoder
          (UlDenseDecoder / UL_DENSE2) instead of the legacy per-grant decode,
          plus UL diagnostics saved to <run>/ul_diag.log. */}
      <button
        className="btn btn-warn"
        disabled={startDisabled}
        title={startTitle ?? "Dense Test: new calibrated-window UL decoder (self-calibrates the UL FFT-window offset per-UE); diagnostics saved to ul_diag.log"}
        onClick={() => run(() => api.denseTest())}
      >
        <span aria-hidden>🧪</span> Dense Test
      </button>
    </>
  );

  if (compact) {
    return (
      <div className="flex items-center gap-2 flex-wrap" title={err ?? undefined}>
        {body}
        {pinToggle}
        {ulFreqMissing && (
          <span className="text-xs text-bad font-mono ml-1">⛔ Set UL freq</span>
        )}
        {err && <span className="text-xs text-bad font-mono ml-2 truncate max-w-[24ch]">{err}</span>}
      </div>
    );
  }

  return (
    <div className="panel p-4">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">Capture</h2>
      <div className="flex flex-wrap gap-2">{body}</div>
      {pinToggle && <div className="mt-2">{pinToggle}</div>}
      {ulFreqMissing && (
        <div className="mt-2 text-xs text-bad">
          ⛔ UL frequency is 0 — set it in Config before starting UL/Dual mode.
        </div>
      )}
      {err && <div className="mt-3 text-xs text-bad font-mono">{err}</div>}
      {state.argv.length > 0 && (
        <div className="mt-3">
          <div className="label mb-1">Argv</div>
          <div className="text-xs font-mono text-slate-300 break-all bg-bg border border-border rounded p-2">
            {state.argv.join(" ")}
          </div>
        </div>
      )}
    </div>
  );
}
