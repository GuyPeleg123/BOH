import { useEffect, useRef } from "react";
import { useStore } from "../lib/store";

const levelClass: Record<string, string> = {
  debug: "text-muted",
  info: "text-slate-300",
  warn: "text-warn",
  error: "text-bad",
};

export function LogPanel({ embedded = false }: { embedded?: boolean }) {
  const { state } = useStore();
  const scrollRef = useRef<HTMLDivElement>(null);
  const atBottomRef = useRef(true);

  // Track whether the user is near the bottom so we know whether to auto-scroll.
  function onScroll() {
    const el = scrollRef.current;
    if (!el) return;
    // "at bottom" = within 60 px of the bottom edge
    atBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  }

  // Auto-scroll only when already pinned to the bottom.
  useEffect(() => {
    if (!atBottomRef.current) return;
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [state.logs.length]);

  const body = (
    <div
      ref={scrollRef}
      onScroll={onScroll}
      className="flex-1 overflow-auto bg-bg border border-border rounded p-2 font-mono text-xs leading-5"
    >
      {state.logs.length === 0 && (
        <div className="text-muted text-center py-4">No log lines yet.</div>
      )}
      {state.logs.map((l, i) => (
        <div key={i} className="whitespace-pre-wrap">
          <span className="text-muted">{l.ts > 0 ? l.ts.toFixed(2).padStart(8) : "        "}</span>{" "}
          <span className={`uppercase ${levelClass[l.level] ?? "text-slate-300"}`}>{(l.level ?? "info").padEnd(5)}</span>{" "}
          {l.source && <span className="text-muted">[{l.source}]</span>}{" "}
          <span className="text-slate-200">{l.msg}</span>
        </div>
      ))}
    </div>
  );

  if (embedded) return body;

  return (
    <div className="panel p-4 flex flex-col min-h-0">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">Logs</h2>
      {body}
    </div>
  );
}
