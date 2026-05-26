import { useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "../lib/store";


import { rntiColor } from "../lib/color";

type Filter = "all" | "dl" | "ul";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1024 / 1024).toFixed(1)}M`;
}

export function PacketFeed() {
  const recentDci = useStore((s) => s.recentDci);
  const state = { recentDci };
  const [filter, setFilter] = useState<Filter>("all");
  const [paused, setPaused] = useState(false);
  const [rntiFilter, setRntiFilter] = useState("");
  const [frozen, setFrozen] = useState<typeof state.recentDci | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-pause while the mouse is hovering, so the operator can read.
  const [hovering, setHovering] = useState(false);
  const effectivelyPaused = paused || hovering;

  const list = effectivelyPaused ? (frozen ?? state.recentDci) : state.recentDci;

  // Freeze the list when paused/hovered, unfreeze when released.
  useEffect(() => {
    if (effectivelyPaused) {
      if (!frozen) setFrozen(state.recentDci);
    } else {
      setFrozen(null);
    }
    // Intentionally not listing state.recentDci so we don't re-freeze every batch
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectivelyPaused]);

  const filtered = useMemo(() => {
    const rntiNum = rntiFilter.trim() === "" ? null : Number(rntiFilter.trim());
    return list.filter(
      (d) =>
        (filter === "all" || d.dir === filter) &&
        (rntiNum == null || isNaN(rntiNum) || d.rnti === rntiNum)
    );
  }, [list, filter, rntiFilter]);

  // Count of new items that arrived while paused (delta vs frozen length).
  const newWhilePaused = effectivelyPaused && frozen ? state.recentDci.length - frozen.length : 0;

  const FilterBtn = ({ v, label }: { v: Filter; label: string }) => (
    <button
      className={`btn !px-2 !py-0.5 !text-xs ${filter === v ? "btn-primary" : ""}`}
      onClick={() => setFilter(v)}
    >
      {label}
    </button>
  );

  return (
    <div className="panel p-4 flex flex-col min-h-0">
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">
          Packets · live DCI feed
        </h2>
        <span className="text-xs text-muted font-mono">
          {filtered.length}/{state.recentDci.length}
        </span>
        {effectivelyPaused && newWhilePaused > 0 && (
          <span className="text-xs font-mono text-warn">+{newWhilePaused} while paused</span>
        )}
        <div className="ml-auto flex items-center gap-2 flex-wrap">
          <FilterBtn v="all" label="ALL" />
          <FilterBtn v="dl"  label="DL" />
          <FilterBtn v="ul"  label="UL" />
          <input
            className="input !py-0.5 !text-xs !w-28"
            placeholder="filter RNTI"
            value={rntiFilter}
            onChange={(e) => setRntiFilter(e.target.value)}
          />
          <button
            className={`btn !px-2 !py-0.5 !text-xs ${paused ? "btn-danger" : ""}`}
            onClick={() => setPaused((p) => !p)}
            title="Pause / resume. Hovering also pauses automatically."
          >
            {paused ? "▶ resume" : "❚❚ pause"}
          </button>
        </div>
      </div>

      <div
        ref={scrollRef}
        onMouseEnter={() => setHovering(true)}
        onMouseLeave={() => setHovering(false)}
        className="overflow-auto flex-1 bg-bg border border-border rounded"
        title="Hovering pauses the feed so you can read."
      >
        <table className="w-full text-xs font-mono">
          <thead className="sticky top-0 bg-bg z-10 text-[10px] uppercase text-muted">
            <tr className="border-b border-border">
              <th className="text-left  px-2 py-1.5 w-8">Dir</th>
              <th className="text-right px-2 py-1.5 w-20">SFN.sf</th>
              <th className="text-right px-2 py-1.5 w-16">Time</th>
              <th className="text-left  px-2 py-1.5 w-2"></th>
              <th className="text-right px-2 py-1.5 w-16">RNTI</th>
              <th className="text-left  px-2 py-1.5 w-12">Fmt</th>
              <th className="text-right px-2 py-1.5 w-12">MCS</th>
              <th className="text-right px-2 py-1.5 w-12">PRB</th>
              <th className="text-right px-2 py-1.5 w-16">TBS</th>
              <th className="text-right px-2 py-1.5 w-12">NDI</th>
              <th className="text-right px-2 py-1.5 w-12">HARQ</th>
              <th className="text-left  px-2 py-1.5">DCI hex</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((d, i) => (
              <tr key={`${d.sfn}-${d.sf}-${d.rnti}-${d.dir}-${i}`} className="border-b border-border/30 hover:bg-panel/50">
                <td className="px-2 py-1">
                  <span className={`px-1 py-0 text-[10px] rounded font-semibold ${d.dir === "dl" ? "bg-accent/20 text-accent" : "bg-warn/20 text-warn"}`}>
                    {d.dir.toUpperCase()}
                  </span>
                </td>
                <td className="px-2 py-1 text-right text-muted">{d.sfn}.{d.sf}</td>
                <td className="px-2 py-1 text-right text-muted">{d.ts.toFixed(1)}s</td>
                <td className="px-2 py-1"><span className="inline-block w-2 h-2 rounded-sm" style={{ background: rntiColor(d.rnti) }} /></td>
                <td className="px-2 py-1 text-right text-slate-100">{d.rnti}</td>
                <td className="px-2 py-1 text-muted">{d.fmt}</td>
                <td className="px-2 py-1 text-right">{d.mcs}</td>
                <td className="px-2 py-1 text-right">{d.nprb}</td>
                <td className="px-2 py-1 text-right">{fmtBytes(d.tbs)}</td>
                <td className="px-2 py-1 text-right text-muted">{d.ndi}</td>
                <td className="px-2 py-1 text-right text-muted">{d.harq ?? "-"}</td>
                <td className="px-2 py-1 text-muted truncate max-w-[160px]">{d.hex}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={12} className="text-center text-muted py-8">
                  {state.recentDci.length === 0 ? "No DCIs decoded yet." : "Nothing matches the filter."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="mt-2 text-[10px] text-muted text-right">
        hover to pause · newest first
      </div>
    </div>
  );
}
