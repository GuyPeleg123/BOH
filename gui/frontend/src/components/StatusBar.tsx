import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { useStore, shallow } from "../lib/store";
import { api } from "../lib/api";

async function handleLogout() {
  // Drop server session + cookie, then force a hard reload to nuke any
  // in-memory React state that was tied to the authed session (WebSocket,
  // capture-state polls, etc.). Reload is the simplest path back to Login.
  try { await api.logout(); } catch {}
  if (typeof window !== "undefined") window.location.reload();
}

export function StatusBar() {
  // Only re-render when the connection / lifecycle status or cell identity changes.
  const state = useStore((s) => ({
    connected: s.connected,
    lifecycle: s.lifecycle,
    pid: s.pid,
    cell: s.cell,
  }), shallow);
  const loc = useLocation();

  // Best-effort whoami so we can show the signed-in username on the right.
  // Skip it on an explicit fail; the StatusBar is decorative — wrong-but-
  // optimistic state is fine, and an extra round-trip on render isn't worth
  // a placeholder spinner.
  const [username, setUsername] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    api.whoami().then((r) => { if (!cancelled) setUsername(r.username); })
              .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const tab = (path: string, label: string) => (
    <Link
      to={path}
      className={`px-4 py-2 rounded-md text-[15px] font-medium whitespace-nowrap transition-colors ${
        loc.pathname === path
          ? "bg-border text-slate-100"
          : "text-muted hover:text-slate-200 hover:bg-border/40"
      }`}
    >
      {label}
    </Link>
  );

  const running = state.lifecycle === "running";

  return (
    <header className="flex items-center gap-5 px-5 py-2.5 border-b border-border bg-panel">
      {/* Logo + name */}
      <div className="flex items-center gap-2 shrink-0">
        <svg width="26" height="26" viewBox="0 0 16 16" aria-hidden>
          <path d="M2 12 L5 6 L8 10 L11 4 L14 8" stroke="#6cb6ff" strokeWidth="1.5" fill="none" />
        </svg>
        <span className="font-semibold tracking-tight text-lg">LTESniffer</span>
      </div>

      <nav className="flex gap-1.5 shrink-0">
        {tab("/", "Dashboard")}
        {tab("/ues", "UEs")}
        {tab("/sessions", "Sessions")}
        {tab("/config", "Config")}
        {tab("/captures", "Captures")}
        {tab("/log-history", "Log History")}
        {tab("/help", "Help")}
      </nav>

      <div className="ml-auto flex items-center gap-3.5 text-sm">
        {/* Connection state */}
        <span
          className={`flex items-center gap-1.5 ${state.connected ? "text-ok" : "text-bad"}`}
          title={state.connected ? "WebSocket connected" : "WebSocket disconnected — backend may be down"}
        >
          <span className={`inline-block w-2 h-2 rounded-full ${state.connected ? "bg-ok" : "bg-bad"} ${state.connected ? "animate-pulse" : ""}`} />
          {state.connected ? "connected" : "disconnected"}
        </span>

        {/* Capture lifecycle */}
        <span
          className={`flex items-center gap-1.5 ${running ? "text-ok" : "text-muted"}`}
          title={running ? `Sniffer running (pid ${state.pid})` : "Sniffer stopped"}
        >
          <span className={`inline-block w-2 h-2 rounded-full ${running ? "bg-ok animate-pulse" : "bg-muted"}`} />
          {running ? <span>running <span className="text-muted">· pid {state.pid}</span></span> : "stopped"}
        </span>

        {/* Cell identity */}
        {state.cell && (
          <span className="text-muted hidden md:inline whitespace-nowrap">
            PCI <span className="text-slate-100 font-mono">{state.cell.pci}</span> ·{" "}
            <span className="font-mono">{state.cell.nof_prb}</span>&nbsp;PRB ·{" "}
            <span className="font-mono">{(state.cell.dl_freq / 1e6).toFixed(1)}</span>&nbsp;MHz
          </span>
        )}

        {/* User + logout */}
        <div className="flex items-center gap-1 pl-3 ml-1 border-l border-border">
          {username && (
            <span className="text-muted hidden sm:inline" title="Signed in user">
              <span className="font-mono text-slate-200">{username}</span>
            </span>
          )}
          <button
            className="px-2.5 py-1.5 rounded-md text-base text-muted hover:text-bad hover:bg-bad/10 transition-colors"
            onClick={handleLogout}
            title="Log out (clears the session cookie and returns to the login page)"
          >
            ⎋
          </button>
        </div>
      </div>
    </header>
  );
}
