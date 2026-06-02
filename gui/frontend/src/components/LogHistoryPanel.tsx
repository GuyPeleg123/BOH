import { useEffect, useRef, useState } from "react";
import { api, type RunLog } from "../lib/api";

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

// Run tag is "YYYY-MM-DD_HH-MM-SS" → split into date + clock for display.
function fmtRun(run: string): { date: string; time: string } {
  const m = run.match(/^(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})$/);
  if (m) return { date: m[1], time: `${m[2]}:${m[3]}:${m[4]}` };
  return { date: run, time: "" };
}

export function LogHistoryPanel({ embedded = false }: { embedded?: boolean }) {
  const [runs, setRuns] = useState<RunLog[] | null>(null);
  const [sel, setSel] = useState<string | null>(null);   // selected run path
  const [text, setText] = useState<string>("");
  const [loadingText, setLoadingText] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const preRef = useRef<HTMLPreElement>(null);

  function refresh() {
    api.logHistory()
      .then((r) => setRuns(r.runs))
      .catch((e) => setErr(e.message));
  }

  useEffect(() => { refresh(); }, []);

  function openRun(path: string) {
    setSel(path);
    setLoadingText(true);
    setText("");
    api.logContent(path)
      .then((r) => {
        setText(r.text);
        // Jump to the end — the interesting bit (errors, exit) is usually last.
        requestAnimationFrame(() => {
          if (preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight;
        });
      })
      .catch((e) => setText(`Failed to load: ${e.message}`))
      .finally(() => setLoadingText(false));
  }

  const body = (
    <div className="flex-1 min-h-0 grid grid-cols-[220px_1fr] gap-3">
      {/* Run list — newest first */}
      <div className="flex flex-col min-h-0 bg-bg border border-border rounded">
        <div className="flex items-center justify-between px-2 py-1.5 border-b border-border">
          <span className="label">Runs</span>
          <button className="btn !px-2 !py-0.5 !text-[10px]" onClick={refresh}>↻</button>
        </div>
        <div className="flex-1 overflow-auto">
          {runs === null && <div className="text-muted text-xs p-3">Loading…</div>}
          {runs && runs.length === 0 && (
            <div className="text-muted text-xs p-3">No past runs yet. Start a capture to record one.</div>
          )}
          {runs?.map((r) => {
            const { date, time } = fmtRun(r.run);
            const active = sel === r.path;
            return (
              <button
                key={r.path}
                onClick={() => openRun(r.path)}
                className={`w-full text-left px-2 py-1.5 border-b border-border/40 text-xs ${active ? "bg-accent/15 text-accent" : "hover:bg-border/40 text-slate-200"}`}
              >
                <div className="font-mono">{time || r.run}</div>
                <div className="text-[10px] text-muted font-mono flex justify-between">
                  <span>{date}</span><span>{fmtBytes(r.size)}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected log content */}
      <pre
        ref={preRef}
        className="bg-bg border border-border rounded p-3 overflow-auto font-mono text-[11px] leading-[1.45] whitespace-pre-wrap text-slate-200 min-h-0"
      >
        {!sel && <span className="text-muted">Select a run on the left to view its log.</span>}
        {sel && loadingText && <span className="text-muted">Loading…</span>}
        {sel && !loadingText && text}
      </pre>
    </div>
  );

  if (embedded) {
    return (
      <div className="flex flex-col min-h-0 flex-1">
        {err && <div className="text-bad text-xs mb-1">{err}</div>}
        {body}
      </div>
    );
  }
  return (
    <div className="panel p-4 flex flex-col min-h-0">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">Log History</h2>
      {err && <div className="text-bad text-xs mb-1">{err}</div>}
      {body}
    </div>
  );
}
