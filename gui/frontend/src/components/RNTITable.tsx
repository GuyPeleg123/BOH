import { useMemo, useState } from "react";
import { useStore } from "../lib/store";
import { useStableTick } from "../lib/useStableTick";
import { rntiColor } from "../lib/color";

type SortKey =
  | "rnti"
  | "last_seen"
  | "dl_count"
  | "ul_count"
  | "dl_rb_total"
  | "ul_rb_total"
  | "dl_tbs_total";

const ACTIVE_WINDOW_S = 5;     // a UE is "active" if seen within this window
const STALE_AFTER_S = 30;      // beyond this, fade row strongly

function fmtBytes(n: number): string {
  if (n < 1024) return Math.round(n).toString();
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1024 / 1024).toFixed(2)}M`;
}

function fmtAgo(s: number): string {
  if (s < 1) return "now";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

export function RNTITable() {
  const { state } = useStore();
  // Pace render so individual numbers don't tick up faster than the eye can read.
  useStableTick(500);

  // Default to RNTI ascending so the row ordering is *stable* — no swapping
  // every 50ms as last_seen ticks. Operator can still click to re-sort.
  const [sort, setSort] = useState<SortKey>("rnti");
  const [desc, setDesc] = useState(false);
  const [onlyActive, setOnlyActive] = useState(false);

  const now = state.monotonic;

  const rows = useMemo(() => {
    let arr = Array.from(state.rntis.values());
    if (onlyActive) {
      arr = arr.filter((r) => now - r.last_seen <= ACTIVE_WINDOW_S);
    }
    arr.sort((a, b) => {
      const diff = desc ? b[sort] - a[sort] : a[sort] - b[sort];
      if (diff !== 0) return diff;
      // Secondary key by RNTI so rows with tied values don't shuffle.
      return a.rnti - b.rnti;
    });
    return arr;
  }, [state.rntis, sort, desc, onlyActive, now]);

  function H({ k, label, align = "left" }: { k: SortKey; label: string; align?: "left" | "right" }) {
    const active = sort === k;
    return (
      <th
        className={`px-2 py-1.5 cursor-pointer select-none text-${align} font-semibold uppercase tracking-wide text-[10px] text-muted hover:text-slate-200`}
        onClick={() => (active ? setDesc(!desc) : (setSort(k), setDesc(true)))}
      >
        {label} {active && (desc ? "▼" : "▲")}
      </th>
    );
  }

  const activeCount = useMemo(
    () => Array.from(state.rntis.values()).filter((r) => now - r.last_seen <= ACTIVE_WINDOW_S).length,
    [state.rntis, now]
  );

  return (
    <div className="panel p-4 flex flex-col min-h-0">
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">RNTIs</h2>
        <span className="text-xs text-muted font-mono">
          <span className="text-ok">{activeCount}</span>
          <span className="text-muted">/{state.rntis.size}</span>
          <span className="ml-1">active</span>
        </span>
      </div>
      <div className="mb-2">
        <label className="inline-flex items-center gap-2 text-xs text-muted cursor-pointer select-none">
          <input
            type="checkbox"
            className="accent-accent"
            checked={onlyActive}
            onChange={(e) => setOnlyActive(e.target.checked)}
          />
          show only active (last {ACTIVE_WINDOW_S}s)
        </label>
      </div>
      <div className="overflow-auto min-h-0">
        <table className="w-full text-sm font-mono tabular-nums">
          <thead className="sticky top-0 bg-panel z-10">
            <tr className="border-b border-border">
              <th className="px-2 py-1.5 w-2"></th>
              <H k="rnti"          label="RNTI" />
              <H k="last_seen"     label="Last" align="right" />
              <H k="dl_count"      label="DL"   align="right" />
              <H k="dl_rb_total"   label="DL RB" align="right" />
              <H k="dl_tbs_total"  label="DL B"  align="right" />
              <H k="ul_count"      label="UL"   align="right" />
              <H k="ul_rb_total"   label="UL RB" align="right" />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const ago = Math.max(0, now - r.last_seen);
              const stale = ago > STALE_AFTER_S;
              const idle = !stale && ago > ACTIVE_WINDOW_S;
              return (
                <tr
                  key={r.rnti}
                  className={`border-b border-border/40 ${stale ? "opacity-30" : idle ? "opacity-65" : ""}`}
                >
                  <td className="px-2 py-1">
                    <span className="inline-block w-2 h-2 rounded-sm" style={{ background: rntiColor(r.rnti) }} />
                  </td>
                  <td className="px-2 py-1 text-slate-100">{r.rnti}</td>
                  <td className="px-2 py-1 text-right text-muted">{fmtAgo(ago)}</td>
                  <td className="px-2 py-1 text-right">{r.dl_count.toLocaleString()}</td>
                  <td className="px-2 py-1 text-right">{r.dl_rb_total.toLocaleString()}</td>
                  <td className="px-2 py-1 text-right">{fmtBytes(r.dl_tbs_total / 8)}</td>
                  <td className="px-2 py-1 text-right">{r.ul_count.toLocaleString()}</td>
                  <td className="px-2 py-1 text-right">{r.ul_rb_total.toLocaleString()}</td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="text-center text-muted py-8">
                  {onlyActive
                    ? `No UE seen in the last ${ACTIVE_WINDOW_S}s.`
                    : "No DCIs decoded yet."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
