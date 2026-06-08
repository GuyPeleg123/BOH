import { useEffect, useRef, useState } from "react";
import { useStore } from "../lib/store";



const levelClass: Record<string, string> = {
  debug: "text-muted",
  info: "text-slate-300",
  warn: "text-warn",
  error: "text-bad",
};

export function LogPanel({ embedded = false }: { embedded?: boolean }) {
  const logs = useStore((s) => s.logs);
  const state = { logs };  // keep the existing references through the rest of the component
  const scrollRef = useRef<HTMLDivElement>(null);
  const atBottomRef = useRef(true);
  // Mirror "pinned to bottom" into React state so we can show a jump button
  // while the user is scrolled up reading history.
  const [pinned, setPinned] = useState(true);

  // Track whether the user is near the bottom so we know whether to auto-scroll.
  function onScroll() {
    const el = scrollRef.current;
    if (!el) return;
    // "at bottom" = within 60 px of the bottom edge
    const bottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
    atBottomRef.current = bottom;
    setPinned(bottom);
  }

  function jumpToLatest() {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
    atBottomRef.current = true;
    setPinned(true);
  }

  // Auto-scroll only when already pinned to the bottom.
  useEffect(() => {
    if (!atBottomRef.current) return;
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [state.logs.length]);

  const body = (
    // relative wrapper so the floating "jump to latest" pill can sit over the
    // scroll area without affecting layout.
    <div className="relative flex-1 min-h-0 flex flex-col">
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
      {/* Shown only while scrolled up — click to snap back to the live tail.
          Auto-scroll resumes once pinned. */}
      {!pinned && state.logs.length > 0 && (
        <button
          onClick={jumpToLatest}
          className="btn btn-primary !text-xs !px-2.5 !py-1 absolute bottom-2 right-3 shadow-lg"
          title="Scroll to newest log lines and resume auto-scroll"
        >
          ↓ Latest
        </button>
      )}
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
