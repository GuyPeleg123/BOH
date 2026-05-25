import { useStore, useRates } from "../lib/store";

function fmtBytes(n: number, suffix = "B"): string {
  if (n < 1024) return `${n.toFixed(0)} ${suffix}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} K${suffix}`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} M${suffix}`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} G${suffix}`;
}

function fmtRate(n: number, unit: string): string {
  if (n < 1) return `${n.toFixed(2)} ${unit}`;
  if (n < 100) return `${n.toFixed(1)} ${unit}`;
  if (n < 1_000) return `${n.toFixed(0)} ${unit}`;
  if (n < 1_000_000) return `${(n / 1_000).toFixed(1)}k ${unit}`;
  return `${(n / 1_000_000).toFixed(1)}M ${unit}`;
}

function Tile({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  accent?: "ok" | "warn" | "bad" | "accent";
}) {
  const accentClass =
    accent === "ok" ? "text-ok" :
    accent === "warn" ? "text-warn" :
    accent === "bad" ? "text-bad" :
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
  const { state } = useStore();
  const rates = useRates(state);
  const totals = state.totals;

  // Estimate throughput in bits/s from TBS rate (each TBS is bits → divide by 8 for bytes).
  // LTE TBS is in *bits*; convert to bytes/s for display.
  const bytes_s = rates.tbs / 8;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      <Tile
        label="DCIs decoded"
        value={totals.dci.toLocaleString()}
        sub={`${fmtRate(rates.dci, "DCI/s")}`}
        accent={totals.dci > 0 ? "ok" : undefined}
      />
      <Tile
        label="DL / UL split"
        value={
          <span>
            <span className="text-accent">{totals.dci_dl.toLocaleString()}</span>
            <span className="text-muted text-xl mx-1">/</span>
            <span className="text-warn">{totals.dci_ul.toLocaleString()}</span>
          </span>
        }
        sub="downlink / uplink DCIs"
      />
      <Tile
        label="Active RNTIs"
        value={state.rntis.size.toLocaleString()}
        sub={state.stats ? `stats: ${state.stats.nof_rnti}` : undefined}
      />
      <Tile
        label="Throughput"
        value={fmtBytes(bytes_s) + "/s"}
        sub={`total ${fmtBytes(totals.tbs / 8)}`}
        accent="accent"
      />
      <Tile
        label="Resource blocks"
        value={fmtRate(rates.rb, "RB/s")}
        sub={`total ${totals.rb.toLocaleString()}`}
      />
      <Tile
        label="Subframes"
        value={totals.sf.toLocaleString()}
        sub={state.stats ? `skipped ${state.stats.sf_skipped}` : undefined}
      />
    </div>
  );
}
