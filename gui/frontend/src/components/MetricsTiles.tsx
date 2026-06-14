import { useMemo } from "react";
import type { AppState } from "../lib/store";
import { useFullState as useStore } from "../lib/store";
import { useStableTick } from "../lib/useStableTick";

// Same logic as useRates() but callable from inside another memo without
// triggering the React hook contract.
function useRatesPure(state: AppState): { dci: number; tbs: number; rb: number } {
  const samples = state.rateSamples;
  if (samples.length < 2) return { dci: 0, tbs: 0, rb: 0 };
  const span = samples[samples.length - 1].ts - samples[0].ts;
  if (span <= 0) return { dci: 0, tbs: 0, rb: 0 };
  let dci = 0, tbs = 0, rb = 0;
  for (const s of samples) { dci += s.dci; tbs += s.tbs; rb += s.rb; }
  return { dci: dci / span, tbs: tbs / span, rb: rb / span };
}

function fmtBytes(n: number, suffix = "B"): string {
  if (n < 1024) return `${Math.round(n)} ${suffix}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} K${suffix}`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} M${suffix}`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} G${suffix}`;
}

/** Quantize a rate so the displayed digits don't jitter every refresh. */
function quantizeRate(n: number): number {
  if (n < 1)   return Math.round(n * 10) / 10;
  if (n < 10)  return Math.round(n * 2) / 2;        // 0.5 steps
  if (n < 100) return Math.round(n);
  if (n < 1000) return Math.round(n / 5) * 5;       // 5 steps
  return Math.round(n / 50) * 50;                   // 50 steps
}

function fmtRate(n: number, unit: string): string {
  const q = quantizeRate(n);
  if (q < 100) return `${q < 10 ? q.toFixed(1) : q} ${unit}`;
  if (q < 1_000) return `${q} ${unit}`;
  if (q < 1_000_000) return `${(q / 1000).toFixed(1)}k ${unit}`;
  return `${(q / 1_000_000).toFixed(1)}M ${unit}`;
}

function Tile({
  label, value, sub, accent,
}: {
  label: string; value: React.ReactNode; sub?: React.ReactNode;
  accent?: "ok" | "warn" | "bad" | "accent";
}) {
  const accentClass =
    accent === "ok"     ? "text-ok" :
    accent === "warn"   ? "text-warn" :
    accent === "bad"    ? "text-bad" :
    accent === "accent" ? "text-accent" :
    "text-slate-100";
  return (
    <div className="panel p-3 flex flex-col min-w-0">
      <span className="label">{label}</span>
      <span className={`mt-1 text-2xl font-mono font-semibold leading-tight tabular-nums truncate ${accentClass}`}>
        {value}
      </span>
      {sub != null && <span className="mt-0.5 text-[11px] text-muted truncate font-mono">{sub}</span>}
    </div>
  );
}

export function MetricsTiles() {
  // MetricsTiles reads many slices and already paces via useStableTick; the
  // useFullState read is fine because the useMemo([tick]) below gates churn.
  const state = useStore();
  // Sample the underlying state once per second. The hook's tick is a
  // dependency for the useMemo below — even if the store re-renders us at
  // 15 Hz, the snapshot only recomputes when `tick` changes, so the
  // displayed numbers stay stable for 1 s at a time.
  const tick = useStableTick(1000);

  const snap = useMemo(() => {
    const rates = useRatesPure(state);
    const elapsedSec = state.startedAt != null ? Math.floor((Date.now() - state.startedAt) / 1000) : null;
    return {
      totals: state.totals,
      ues: state.rntis.size,
      statsNofRnti: state.stats?.nof_rnti ?? null,
      dciRate: rates.dci,
      rbRate: rates.rb,
      bytes_s: rates.tbs / 8,
      elapsedSec,
      health: (() => {
        const s = state.stats;
        if (!s) return null;
        const total = s.sf_processed + s.sf_skipped;
        if (total === 0) return null;
        return { pct: (100 * s.sf_processed) / total, processed: s.sf_processed, skipped: s.sf_skipped };
      })(),
    };
    // intentional: gate on tick, not on state
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  const { totals, health, ues, statsNofRnti, dciRate, rbRate, bytes_s, elapsedSec } = snap;

  function fmtElapsed(sec: number): string {
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }
  const healthAccent: "ok" | "warn" | "bad" | undefined =
    health == null ? undefined :
    health.pct >= 99 ? "ok" :
    health.pct >= 95 ? "warn" : "bad";

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      <Tile
        label="Run time"
        value={elapsedSec != null ? fmtElapsed(elapsedSec) : "—"}
        sub={elapsedSec != null ? `${elapsedSec.toLocaleString()} seconds` : "not running"}
        accent={elapsedSec != null ? "ok" : undefined}
      />
      <Tile
        label="UEs seen"
        value={ues.toLocaleString()}
        sub={statsNofRnti != null ? `stats: ${statsNofRnti}` : "—"}
      />
      <Tile
        label="Throughput"
        value={fmtBytes(bytes_s) + "/s"}
        sub={`total ${fmtBytes(totals.tbs / 8)}`}
        accent="accent"
      />
      <Tile
        label="Resource blocks"
        value={fmtRate(rbRate, "RB/s")}
        sub={`total ${totals.rb.toLocaleString()}`}
      />
      <Tile
        label="Decoding health"
        value={health ? `${health.pct.toFixed(1)} %` : "—"}
        sub={health ? `${health.processed.toLocaleString()} ok · ${health.skipped.toLocaleString()} skipped` : "no stats yet"}
        accent={healthAccent}
      />
    </div>
  );
}
