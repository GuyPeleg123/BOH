import { CapturesPanel } from "../components/CapturesPanel";

export function CapturesPage() {
  return (
    <div className="p-4 h-full flex flex-col min-h-0">
      <div className="panel p-5 flex flex-col flex-1 min-h-0">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-slate-100">Captures</h2>
          <p className="text-sm text-muted mt-0.5">Browse, download and decrypt recorded pcaps.</p>
        </div>
        <CapturesPanel embedded />
      </div>
    </div>
  );
}
