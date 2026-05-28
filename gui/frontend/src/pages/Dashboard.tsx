import { useState } from "react";
import { CellCard } from "../components/CellCard";
import { CaptureControls } from "../components/CaptureControls";
import { MetricsTiles } from "../components/MetricsTiles";
import { RNTITable } from "../components/RNTITable";
import { RBWaterfall } from "../components/RBWaterfall";
import { LogPanel } from "../components/LogPanel";
import { IdentitiesPanel } from "../components/IdentitiesPanel";
import { PacketFeed } from "../components/PacketFeed";
import { SpectrumButton } from "../components/SpectrumButton";
import { WiresharkButton } from "../components/WiresharkButton";
import { CapturesPanel } from "../components/CapturesPanel";

export function Dashboard() {
  const [mode, setMode] = useState<"alloc" | "power">("alloc");
  const [direction, setDirection] = useState<"dl" | "ul">("dl");
  const [bottomTab, setBottomTab] = useState<"logs" | "captures" | "identities">("logs");

  return (
    <div className="p-3 flex flex-col gap-3 h-full overflow-y-auto">
      {/* row 1: capture + spectrum on left, cell card stretches right */}
      <div className="flex items-stretch gap-3">
        <div className="panel p-3 flex items-center gap-2 shrink-0">
          <CaptureControls compact />
        </div>
        <div className="shrink-0 flex items-center gap-2">
          <SpectrumButton />
          <WiresharkButton />
        </div>
        <div className="flex-1 min-w-0">
          <CellCard />
        </div>
      </div>

      {/* row 2: metrics tiles */}
      <MetricsTiles />

      {/* row 3: main grid — packets (large), waterfall (medium), RNTIs (side).
          NOTE: each panel is the grid item DIRECTLY, no wrapper div. A wrapper
          div is `display: block` so its child (the panel) sizes to its
          intrinsic content height, which means `flex-1` on inner scroll
          containers has nothing to be flex-1 OF — the panel just grows
          tall enough to fit every row and overflows the grid cell. Making
          the panel the grid item itself fixes this: grid items default to
          `align-self: stretch`, so the panel inherits the grid row's height
          and its inner `flex-col + flex-1 + min-h-0` chain finally has a
          bounded container to lay out against. */}
      <div className="grid gap-3 flex-1 min-h-0" style={{ gridTemplateColumns: "minmax(0, 1.4fr) minmax(0, 1fr) 340px" }}>
        <PacketFeed />

        <div className="panel p-3 flex flex-col min-h-0">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mr-auto">
              RB waterfall
            </h2>
            <div className="flex gap-1">
              <button className={`btn !px-2 !py-0.5 !text-xs ${mode === "alloc" ? "btn-primary" : ""}`} onClick={() => setMode("alloc")}>Alloc</button>
              <button className={`btn !px-2 !py-0.5 !text-xs ${mode === "power" ? "btn-primary" : ""}`} onClick={() => setMode("power")}>Power</button>
            </div>
            {mode === "alloc" ? (
              <div className="flex gap-1">
                <button className={`btn !px-2 !py-0.5 !text-xs ${direction === "dl" ? "btn-primary" : ""}`} onClick={() => setDirection("dl")}>DL</button>
                <button className={`btn !px-2 !py-0.5 !text-xs ${direction === "ul" ? "btn-primary" : ""}`} onClick={() => setDirection("ul")}>UL</button>
              </div>
            ) : (
              <div className="flex gap-1">
                <button className="btn !px-2 !py-0.5 !text-xs" disabled title="Power graph is DL-only (no pwr_ul in protocol)">DL</button>
                <button className="btn !px-2 !py-0.5 !text-xs" disabled title="Power graph is DL-only (no pwr_ul in protocol)">UL</button>
              </div>
            )}
          </div>
          <div className="flex-1 min-h-0"><RBWaterfall mode={mode} direction={direction} /></div>
          <div className="mt-1 text-[10px] text-muted font-mono text-center">
            newest at bottom · width = PRB index · {mode === "alloc" ? "color = per-RNTI" : "color = RSRP"}
          </div>
        </div>

        <RNTITable />
      </div>

      {/* row 4: tabbed footer */}
      <div className="panel p-3 flex flex-col min-h-0" style={{ flexBasis: "180px", flexShrink: 0 }}>
        <div className="flex gap-1 mb-2">
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "logs" ? "btn-primary" : ""}`} onClick={() => setBottomTab("logs")}>Logs</button>
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "captures" ? "btn-primary" : ""}`} onClick={() => setBottomTab("captures")}>Captures</button>
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "identities" ? "btn-primary" : ""}`} onClick={() => setBottomTab("identities")}>Identities</button>
        </div>
        <div className="flex-1 min-h-0">
          {bottomTab === "logs"
            ? <LogPanel embedded />
            : bottomTab === "captures"
              ? <CapturesPanel embedded />
              : <IdentitiesPanel embedded />}
        </div>
      </div>
    </div>
  );
}
