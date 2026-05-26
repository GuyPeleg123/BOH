import { useState } from "react";
import { api } from "../lib/api";
import { useStore, shallow } from "../lib/store";

export function CaptureControls({ compact = false }: { compact?: boolean }) {
  const state = useStore((s) => ({ lifecycle: s.lifecycle, argv: s.argv }), shallow);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const running = state.lifecycle === "running";

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e: any) {
      setErr(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  }

  const body = (
    <>
      <button className="btn btn-ok" disabled={busy || running} onClick={() => run(() => api.start())}>▶ Start</button>
      <button className="btn btn-danger" disabled={busy || !running} onClick={() => run(() => api.stop())}>■ Stop</button>
      <button className="btn btn-primary" disabled={busy} onClick={() => run(() => api.restart())}>⟳ Restart</button>
    </>
  );

  if (compact) {
    return (
      <div className="flex items-center gap-2" title={err ?? undefined}>
        {body}
        {err && <span className="text-xs text-bad font-mono ml-2 truncate max-w-[24ch]">{err}</span>}
      </div>
    );
  }

  return (
    <div className="panel p-4">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">Capture</h2>
      <div className="flex flex-wrap gap-2">{body}</div>
      {err && <div className="mt-3 text-xs text-bad font-mono">{err}</div>}
      {state.argv.length > 0 && (
        <div className="mt-3">
          <div className="label mb-1">Argv</div>
          <div className="text-xs font-mono text-slate-300 break-all bg-bg border border-border rounded p-2">
            {state.argv.join(" ")}
          </div>
        </div>
      )}
    </div>
  );
}
