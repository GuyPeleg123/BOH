import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { SnifferConfig, ReceiveStatus } from "../lib/types";

function fmtKB(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(2)} MB`;
}

// This instance never captures — it only receives the live pcap a capture
// instance's "Live pcap forwarding" pushes in. Counterpart to that Config
// section (see pages/Config.tsx); bind/port here are the same
// pcap_receive_bind/port fields in SnifferConfig, applied immediately on
// save (PUT /api/config restarts the listener — see main.py).
export function ReceiveConfigPage() {
  const [cfg, setCfg] = useState<SnifferConfig | null>(null);
  const [bind, setBind] = useState("0.0.0.0");
  const [port, setPort] = useState(9000);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [st, setSt] = useState<ReceiveStatus | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.getConfig().then((c) => {
      setCfg(c);
      setBind(c.pcap_receive_bind ?? "0.0.0.0");
      setPort(c.pcap_receive_port ?? 9000);
    }).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => {
    let live = true;
    const tick = () => api.receiveStatus().then((s) => { if (live) setSt(s); }).catch(() => {});
    tick();
    const iv = setInterval(tick, 2000);
    return () => { live = false; clearInterval(iv); };
  }, []);

  async function save() {
    if (!cfg) return;
    setSaving(true); setErr(null); setSaved(false);
    try {
      const r = await api.putConfig({ ...cfg, pcap_receive_bind: bind, pcap_receive_port: port });
      setCfg(r);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  const target = st ? `${st.host_ip}:${st.port}` : "";
  function copyTarget() {
    if (!target) return;
    navigator.clipboard?.writeText(target).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  const color =
    !st ? "text-muted border-border" :
    st.state === "connected" ? "text-ok border-ok/40 bg-ok/5" :
    st.state === "error" ? "text-bad border-bad/40 bg-bad/5" :
    "text-slate-200 border-border";

  return (
    <div className="p-4 h-full overflow-auto max-w-2xl">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-1">Config — pcap receiving</h2>
      <p className="text-[11px] text-muted mb-4">
        This instance never captures — it receives the live pcap a capture instance pushes over the network
        (that instance's Config → "Live pcap forwarding").
      </p>

      <div className="panel p-4 mb-4">
        <div className="flex items-center gap-3 mb-3">
          <label className="text-sm text-slate-200 w-40 shrink-0">Bind address</label>
          <input value={bind} onChange={(e) => setBind(e.target.value)}
            className="w-48 bg-bg border border-border rounded px-2 py-1.5 text-sm font-mono text-slate-100" />
          <span className="text-[11px] text-muted">0.0.0.0 = reachable from the LAN · 127.0.0.1 = this machine only</span>
        </div>
        <div className="flex items-center gap-3 mb-4">
          <label className="text-sm text-slate-200 w-40 shrink-0">Listen port</label>
          <input type="number" min={1} max={65535} value={port}
            onChange={(e) => setPort(Number(e.target.value))}
            className="w-48 bg-bg border border-border rounded px-2 py-1.5 text-sm font-mono text-slate-100" />
        </div>
        <div className="flex items-center gap-3">
          <button className="btn btn-primary !px-4 !py-1.5 !text-sm" disabled={saving || !cfg} onClick={save}>
            {saving ? "Saving…" : "Save"}
          </button>
          {saved && <span className="text-ok text-xs">Applied — listener restarted.</span>}
          {err && <span className="text-bad text-xs font-mono">{err}</span>}
        </div>
      </div>

      <div className={`panel p-4 border ${color}`}>
        <div className="flex items-center gap-2 mb-3">
          <span className="font-semibold text-sm">Receiver: {st ? st.state : "…"}</span>
          {st?.last_error && <span className="text-bad text-xs font-mono truncate" title={st.last_error}>{st.last_error}</span>}
        </div>
        <div className="text-xs text-muted mb-1">
          Point the capture instance's "Destination IP / host" and "Destination port" at:
        </div>
        <div className="flex items-center gap-2">
          <span className="font-mono text-lg text-slate-100 bg-bg border border-border rounded px-3 py-1.5">{target || "…"}</span>
          <button className="btn !px-3 !py-1.5 !text-sm" onClick={copyTarget} disabled={!target}>
            {copied ? "Copied!" : "📋 Copy"}
          </button>
        </div>
        {st && st.enabled && (
          <div className="text-xs text-muted mt-3 tabular-nums">
            received {fmtKB(st.bytes_in)} · {st.records.toLocaleString()} rec · {st.connections} conn
            {st.peer && <> · from {st.peer}</>}
          </div>
        )}
      </div>
    </div>
  );
}
