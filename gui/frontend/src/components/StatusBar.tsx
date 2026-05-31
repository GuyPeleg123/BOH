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
  const tab = (path: string, label: string) => (
    <Link
      to={path}
      className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
        loc.pathname === path ? "bg-border text-slate-100" : "text-muted hover:text-slate-200"
      }`}
    >
      {label}
    </Link>
  );

  return (
    <div className="flex items-center gap-4 px-4 py-2 border-b border-border bg-panel">
      <div className="flex items-center gap-2">
        <svg width="22" height="22" viewBox="0 0 16 16">
          <path d="M2 12 L5 6 L8 10 L11 4 L14 8" stroke="#6cb6ff" strokeWidth="1.5" fill="none" />
        </svg>
        <span className="font-semibold tracking-tight">LTESniffer</span>
      </div>
      <nav className="flex gap-1">
        {tab("/", "Dashboard")}
        {tab("/keys", "Keys")}
        {tab("/config", "Config")}
        {tab("/help", "Help")}
      </nav>
      <div className="ml-auto flex items-center gap-4 text-xs">
        <span className={state.connected ? "text-ok" : "text-bad"}>
          {state.connected ? "● connected" : "○ disconnected"}
        </span>
        <span className={state.lifecycle === "running" ? "text-ok" : "text-muted"}>
          {state.lifecycle === "running" ? `● running (pid ${state.pid})` : "○ stopped"}
        </span>
        {state.cell && (
          <span className="text-muted">
            PCI <span className="text-slate-100 font-mono">{state.cell.pci}</span> ·{" "}
            {state.cell.nof_prb} PRB · {(state.cell.dl_freq / 1e6).toFixed(1)} MHz
          </span>
        )}
        <button
          className="px-2 py-1 rounded-md text-muted hover:text-slate-200 hover:bg-border/50 transition-colors"
          onClick={handleLogout}
          title="Log out (clears the session cookie and returns to the login page)"
        >
          ⎋ Logout
        </button>
      </div>
    </div>
  );
}
