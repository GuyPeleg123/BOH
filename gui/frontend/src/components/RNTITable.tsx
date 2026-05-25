import { useMemo, useState } from "react";
import { useStore } from "../lib/store";
import { rntiColor } from "../lib/color";

type SortKey = "rnti" | "last_seen" | "dl_count" | "ul_count" | "dl_rb_total" | "ul_rb_total" | "dl_tbs_total";

function fmtBytes(n: number): string {
  if (n < 1024) return n.toString();
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1024 / 1024).toFixed(2)}M`;
}

export function RNTITable() {
  const { state } = useStore();
  const [sort, setSort] = useState<SortKey>("last_seen");
  const [desc, setDesc] = useState(true);

  const rows = useMemo(() => {
    const arr = Array.from(state.rntis.values());
    arr.sort((a, b) => (desc ? b[sort] - a[sort] : a[sort] - b[sort]));
    return arr;
  }, [state.rntis, sort, desc]);

  const now = state.monotonic;

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

  return (
    <div className="panel p-4 flex flex-col min-h-0">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">RNTIs</h2>
        <span className="text-xs text-muted font-mono">{rows.length} seen</span>
      </div>
      <div className="overflow-auto min-h-0">
        <table className="w-full text-sm font-mono tabular-nums">
          <thead className="sticky top-0 bg-panel z-10">
            <tr className="border-b border-border">
              <th className="px-2 py-1.5 w-2"></th>
              <H k="rnti" label="RNTI" />
              <H k="last_seen" label="Last" align="right" />
              <H k="dl_count" label="DL" align="right" />
              <H k="dl_rb_total" label="DL RB" align="right" />
              <H k="dl_tbs_total" label="DL B" align="right" />
              <H k="ul_count" label="UL" align="right" />
              <H k="ul_rb_total" label="UL RB" align="right" />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const ago = Math.max(0, now - r.last_seen);
              const stale = ago > 5;
              return (
                <tr key={r.rnti} className={`border-b border-border/40 ${stale ? "opacity-50" : ""}`}>
                  <td className="px-2 py-1">
                    <span className="inline-block w-2 h-2 rounded-sm" style={{ background: rntiColor(r.rnti) }} />
                  </td>
                  <td className="px-2 py-1 text-slate-100">{r.rnti}</td>
                  <td className="px-2 py-1 text-right text-muted">
                    {ago < 1 ? "now" : ago < 60 ? `${ago.toFixed(0)}s ago` : `${(ago / 60).toFixed(1)}m`}
                  </td>
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
                <td colSpan={8} className="text-center text-muted py-8">No DCIs decoded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
