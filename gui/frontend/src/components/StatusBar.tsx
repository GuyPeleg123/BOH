import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { useStore, shallow } from "../lib/store";
import { api } from "../lib/api";
import type { ForwardStatus, ReceiveStatus } from "../lib/types";

// Cross-machine link status — is THIS instance actually talking to the
// other one, not just "is my own browser tab's websocket alive" (that's
// the separate connected/disconnected dot below). Polls the matching
// status endpoint for whichever role this build is; caller passes which.
function LinkStatus({ kind }: { kind: "forward" | "receive" }) {
  const [st, setSt] = useState<ForwardStatus | ReceiveStatus | null>(null);
  useEffect(() => {
    let live = true;
    const tick = () => {
      const p = kind === "forward" ? api.forwardStatus() : api.receiveStatus();
      p.then((s) => { if (live) setSt(s); }).catch(() => {});
    };
    tick();
    const iv = setInterval(tick, 2000);
    return () => { live = false; clearInterval(iv); };
  }, [kind]);

  const linked = st?.state === "connected";
  const label =
    !st || !st.enabled ? "not configured"
    : st.state === "connected" ? "linked"
    : st.state === "listening" ? "waiting"
    : st.state;
  const target =
    kind === "forward" && st && "host" in st && st.host ? `→ ${st.host}:${st.port}`
    : kind === "receive" && st && "peer" in st && st.peer ? `← ${st.peer}`
    : null;

  return (
    <span
      className={`flex items-center gap-1.5 ${linked ? "text-ok" : "text-muted"}`}
      title={
        kind === "forward"
          ? "Live pcap forwarding — is this capture instance actually connected to a decrypt instance right now"
          : "Pcap receiving — is a capture instance actually connected and pushing data right now"
      }
    >
      <span className={`inline-block w-2 h-2 rounded-full ${linked ? "bg-ok animate-pulse" : "bg-muted"}`} />
      link: {label}{target && <span className="text-muted">&nbsp;{target}</span>}
    </span>
  );
}

async function handleLogout() {
  // Drop server session + cookie, then force a hard reload to nuke any
  // in-memory React state that was tied to the authed session (WebSocket,
  // capture-state polls, etc.). Reload is the simplest path back to Login.
  try { await api.logout(); } catch {}
  if (typeof window !== "undefined") window.location.reload();
}

export type NavTab = { path: string; label: string };

export function StatusBar({ tabs, showCaptureStatus = true, linkKind }: {
  tabs: NavTab[];
  showCaptureStatus?: boolean;
  linkKind?: "forward" | "receive";
}) {
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
        {tabs.map((t) => <span key={t.path}>{tab(t.path, t.label)}</span>)}
      </nav>

      <div className="ml-auto flex items-center gap-3.5 text-sm">
        {/* Connection state — this backend's own websocket, not the cross-
            machine link (that's the separate "link:" indicator below). */}
        <span
          className={`flex items-center gap-1.5 ${state.connected ? "text-ok" : "text-bad"}`}
          title={state.connected ? "WebSocket connected" : "WebSocket disconnected — backend may be down"}
        >
          <span className={`inline-block w-2 h-2 rounded-full ${state.connected ? "bg-ok" : "bg-bad"} ${state.connected ? "animate-pulse" : ""}`} />
          {state.connected ? "connected" : "disconnected"}
        </span>

        {/* Cross-machine link — is this instance actually connected to the
            other one (forwarding out, or receiving in) right now. */}
        {linkKind && <LinkStatus kind={linkKind} />}

        {/* Capture lifecycle + cell identity — only meaningful on an instance
            that actually runs a capture. */}
        {showCaptureStatus && (
          <>
            <span
              className={`flex items-center gap-1.5 ${running ? "text-ok" : "text-muted"}`}
              title={running ? `Sniffer running (pid ${state.pid})` : "Sniffer stopped"}
            >
              <span className={`inline-block w-2 h-2 rounded-full ${running ? "bg-ok animate-pulse" : "bg-muted"}`} />
              {running ? <span>running <span className="text-muted">· pid {state.pid}</span></span> : "stopped"}
            </span>

            {state.cell && (
              <span className="text-muted hidden md:inline whitespace-nowrap">
                PCI <span className="text-slate-100 font-mono">{state.cell.pci}</span> ·{" "}
                <span className="font-mono">{state.cell.nof_prb}</span>&nbsp;PRB ·{" "}
                <span className="font-mono">{(state.cell.dl_freq / 1e6).toFixed(1)}</span>&nbsp;MHz
              </span>
            )}
          </>
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
