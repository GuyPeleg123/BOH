import { useState } from "react";
import { CellCard } from "../components/CellCard";
import { CaptureControls } from "../components/CaptureControls";
import { MetricsTiles } from "../components/MetricsTiles";
import { RNTITable } from "../components/RNTITable";
import { LogPanel } from "../components/LogPanel";
import { IdentitiesPanel } from "../components/IdentitiesPanel";
import { PacketFeed } from "../components/PacketFeed";
import { SpectrumButton } from "../components/SpectrumButton";
import { WiresharkButton } from "../components/WiresharkButton";
import { CapturesPanel } from "../components/CapturesPanel";
import { LogHistoryPanel } from "../components/LogHistoryPanel";

export function Dashboard() {
  const [bottomTab, setBottomTab] = useState<"logs" | "history" | "captures" | "identities">("logs");

  return (
    <div className="p-3 flex flex-col gap-3 h-full overflow-hidden">
      {/* The dashboard fills the viewport and never page-scrolls — each region
          (packet feed, RNTI table, log footer) scrolls internally instead, so
          the log panel is always visible without scrolling the whole page. */}
      {/* row 1: capture + spectrum on left, cell card stretches right */}
      <div className="flex items-stretch gap-3 shrink-0">
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

      {/* row 3: main grid — packets (large) + RNTI table (wide side).
          NOTE: each panel is the grid item DIRECTLY, no wrapper div. A wrapper
          div is `display: block` so its child (the panel) sizes to its
          intrinsic content height, which means `flex-1` on inner scroll
          containers has nothing to be flex-1 OF — the panel just grows
          tall enough to fit every row and overflows the grid cell. Making
          the panel the grid item itself fixes this: grid items default to
          `align-self: stretch`, so the panel inherits the grid row's height
          and its inner `flex-col + flex-1 + min-h-0` chain finally has a
          bounded container to lay out against. */}
      <div className="grid gap-3 flex-1 min-h-0" style={{ gridTemplateColumns: "minmax(0, 1fr) 440px" }}>
        <PacketFeed />
        <RNTITable />
      </div>

      {/* row 4: tabbed footer */}
      <div className="panel p-3 flex flex-col min-h-0" style={{ flexBasis: "240px", flexShrink: 0 }}>
        <div className="flex gap-1 mb-2">
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "logs" ? "btn-primary" : ""}`} onClick={() => setBottomTab("logs")}>Logs</button>
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "history" ? "btn-primary" : ""}`} onClick={() => setBottomTab("history")}>Log History</button>
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "captures" ? "btn-primary" : ""}`} onClick={() => setBottomTab("captures")}>Captures</button>
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "identities" ? "btn-primary" : ""}`} onClick={() => setBottomTab("identities")}>Identities</button>
        </div>
        <div className="flex-1 min-h-0">
          {bottomTab === "logs"
            ? <LogPanel embedded />
            : bottomTab === "history"
              ? <LogHistoryPanel embedded />
              : bottomTab === "captures"
                ? <CapturesPanel embedded />
                : <IdentitiesPanel embedded />}
        </div>
      </div>
    </div>
  );
}
