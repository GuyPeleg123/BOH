import { LogHistoryPanel } from "../components/LogHistoryPanel";

export function LogHistoryPage() {
  return (
    <div className="p-3 h-full flex flex-col min-h-0">
      <div className="panel p-4 flex flex-col flex-1 min-h-0">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">Log History</h2>
        <LogHistoryPanel embedded />
      </div>
    </div>
  );
}
