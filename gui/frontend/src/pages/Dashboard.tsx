import { useState } from "react";
import { CellCard } from "../components/CellCard";
import { CaptureControls } from "../components/CaptureControls";
import { MetricsTiles } from "../components/MetricsTiles";
import { LogPanel } from "../components/LogPanel";
import { IdentitiesPanel } from "../components/IdentitiesPanel";
import { SpectrumButton } from "../components/SpectrumButton";
import { WiresharkButton } from "../components/WiresharkButton";
import { PacketTypeCounter } from "../components/PacketTypeCounter";

export function Dashboard() {
  const [bottomTab, setBottomTab] = useState<"logs" | "identities">("logs");

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

      {/* row 3: packet type counter */}
      <PacketTypeCounter />

      {/* row 4: tabbed log footer — expands to fill remaining height */}
      <div className="panel p-3 flex flex-col min-h-0 flex-1">
        <div className="flex gap-1 mb-2">
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "logs" ? "btn-primary" : ""}`} onClick={() => setBottomTab("logs")}>Logs</button>
          <button className={`btn !px-2 !py-0.5 !text-xs ${bottomTab === "identities" ? "btn-primary" : ""}`} onClick={() => setBottomTab("identities")}>Identities</button>
        </div>
        <div className="flex-1 min-h-0 flex flex-col">
          {bottomTab === "logs" ? <LogPanel embedded /> : <IdentitiesPanel embedded />}
        </div>
      </div>
    </div>
  );
}
