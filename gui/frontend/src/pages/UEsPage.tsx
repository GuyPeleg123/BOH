import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import type { SessionsResponse, UeSession } from "../lib/types";
import { FileBrowser } from "../components/FileBrowser";

// UE roster for a received/analyzed capture. Sourced from the same post-hoc
// tshark analysis as the Sessions page (/api/sessions) — NOT from the live
// /api/events WebSocket stream, which only exists during an active capture
// and would be permanently empty on a decrypt-role instance (this instance
// never captures; it only receives pcaps pushed over the network).

function Stat({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: "ok" | "warn" | "bad" }) {
  const c = accent === "ok" ? "text-ok" : accent === "warn" ? "text-warn" : accent === "bad" ? "text-bad" : "text-slate-100";
  return (
    <div className="panel p-3 flex flex-col gap-0.5 min-w-[9rem]">
      <span className="text-[10px] uppercase tracking-wide text-muted">{label}</span>
      <span className={`text-2xl font-semibold ${c}`}>{value}</span>
      {sub && <span className="text-[11px] text-muted">{sub}</span>}
    </div>
  );
}

const confColor: Record<string, string> = {
  imsi: "bg-bad/20 text-bad border-bad/40",
  guti: "bg-ok/20 text-ok border-ok/40",
  tmsi: "bg-ok/20 text-ok border-ok/40",
  "rnti-only": "bg-muted/15 text-muted border-border",
};

function idLabel(s: UeSession): string {
  const i = s.identity;
  return i.guti ? `guti ${i.guti}` : i.s_tmsi ? `s-tmsi ${i.s_tmsi}` : i.imsi ? `imsi ${i.imsi}` : i.m_tmsi ? `m-tmsi ${i.m_tmsi}` : "";
}

export function UEsPage() {
  const [path, setPath] = useState<string | null>(null);   // null = latest capture
  const [name, setName] = useState<string>("(latest capture)");
  const [browsing, setBrowsing] = useState(false);
  const [running, setRunning] = useState(false);
  const [resp, setResp] = useState<SessionsResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");

  async function run(p: string | null = path) {
    setErr(null); setRunning(true);
    try {
      const r = await api.analyzeSessions(p);
      setResp(r);
      if (!r.ok) setErr(r.error);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setRunning(false); }
  }

  // UEs is the landing page — load the latest capture automatically so
  // there's something on screen without an extra click.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { run(null); }, []);

  const sessions = resp?.sessions ?? [];
  const nImsi = new Set(sessions.map((s) => s.identity.imsi).filter(Boolean)).size;
  const nTmsi = new Set(sessions.map((s) => s.identity.m_tmsi).filter(Boolean)).size;
  const nIdentified = sessions.filter((s) => s.identity.confidence !== "rnti-only").length;

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return sessions;
    return sessions.filter((s) => {
      const hay = [s.c_rnti_hex, s.identity.m_tmsi, s.identity.imsi, s.identity.s_tmsi,
                   s.identity.guti, s.plmn, idLabel(s)].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(needle);
    });
  }, [sessions, q]);

  const ago = (t: number) => (resp ? Math.max(0, (sessions[0]?.end ?? t) - t) : 0);

  return (
    <div className="p-3 h-full flex flex-col min-h-0 gap-3 overflow-auto">
      <div className="flex items-center gap-2 text-xs bg-bg border border-border rounded px-2 py-1.5 flex-wrap">
        <span className="text-muted uppercase text-[10px] shrink-0">Capture</span>
        <span className="font-mono text-slate-100 truncate" title={path ?? ""}>{name}</span>
        <button className="btn !px-3 !py-1.5 !text-sm" onClick={() => setBrowsing(true)}>📁 Browse…</button>
        <button className="btn !px-3 !py-1.5 !text-sm" onClick={() => { setPath(null); setName("(latest capture)"); run(null); }}>↺ latest</button>
        <button className="btn btn-primary !px-3.5 !py-1.5 !text-sm ml-auto" disabled={running} onClick={() => run()}>
          {running ? "Analyzing…" : "Refresh"}
        </button>
      </div>

      {err && <div className="text-bad text-xs font-mono border border-bad/40 rounded p-2">{err}</div>}

      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-2">Identified UEs</h2>
        <div className="flex flex-wrap gap-2">
          <Stat label="UE sessions" value={sessions.length} sub="distinct C-RNTI sessions" />
          <Stat label="Identified" value={nIdentified} sub="have a TMSI/IMSI/GUTI" accent={nIdentified > 0 ? "ok" : undefined} />
          <Stat label="IMSI" value={nImsi} sub="distinct" accent={nImsi > 0 ? "bad" : undefined} />
          <Stat label="M-TMSI" value={nTmsi} sub="distinct" accent={nTmsi > 0 ? "warn" : undefined} />
        </div>
        <p className="text-[11px] text-muted mt-1">
          One row per UE session (a C-RNTI lifetime), from the same post-capture analysis as the Sessions page. Identities are read in the clear (paging, RRC request, attach).
        </p>
      </div>

      <div className="panel p-3 flex flex-col min-h-0">
        <div className="flex items-center gap-2 mb-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">UEs ({filtered.length}{filtered.length !== sessions.length ? ` / ${sessions.length}` : ""})</h3>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="search RNTI / TMSI / IMSI / GUTI…"
            className="ml-auto w-64 max-w-[50vw] bg-bg border border-border rounded px-2 py-1 text-xs font-mono text-slate-100"
          />
        </div>
        {sessions.length === 0 ? (
          <div className="text-sm text-muted text-center py-4">
            {resp?.ok === false ? "No capture available to analyze." : "No UE sessions found in this capture."}
          </div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead className="text-[10px] uppercase tracking-wide text-muted">
              <tr className="border-b border-border">
                <th className="px-2 py-1.5 text-left">C-RNTI</th>
                <th className="px-2 py-1.5 text-left">Identity</th>
                <th className="px-2 py-1.5 text-left">Via</th>
                <th className="px-2 py-1.5 text-right">DL/UL</th>
                <th className="px-2 py-1.5 text-right">Dur</th>
                <th className="px-2 py-1.5 text-right">Ago (s)</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => (
                <tr key={s.session_id} className="border-b border-border/40">
                  <td className="px-2 py-1 text-slate-100">{s.c_rnti_hex}</td>
                  <td className="px-2 py-1">
                    <span className="text-slate-100">{idLabel(s) || "—"}</span>
                    <span className={`ml-2 px-1 rounded border text-[9px] ${confColor[s.identity.confidence] ?? confColor["rnti-only"]}`}>{s.identity.confidence}</span>
                  </td>
                  <td className="px-2 py-1 text-muted">{s.identity.id_via ?? "—"}</td>
                  <td className="px-2 py-1 text-right text-muted">{s.dl_frames}/{s.ul_frames}</td>
                  <td className="px-2 py-1 text-right text-muted">{s.duration_s}s</td>
                  <td className="px-2 py-1 text-right text-muted">{ago(s.end).toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {browsing && (
        <FileBrowser startPath={path}
          onClose={() => setBrowsing(false)}
          onPick={(p, n) => { setPath(p); setName(n); setBrowsing(false); run(p); }} />
      )}
    </div>
  );
}
