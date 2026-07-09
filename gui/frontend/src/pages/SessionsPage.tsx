import { Fragment, useState } from "react";
import { api } from "../lib/api";
import type { DecryptEntry, SessionsResponse, SessionTa, UeSession } from "../lib/types";
import { FileBrowser } from "../components/FileBrowser";

const DECRYPT_LS = "ltesniffer-decrypt-entries";   // shared with the Decrypt modal

// Pull saved keys from the Decrypt modal's localStorage so the user doesn't
// re-enter them. Only rows with an RNTI + (raw keys OR kasme+nas) are usable.
function savedKeys(): DecryptEntry[] {
  try {
    const arr = JSON.parse(localStorage.getItem(DECRYPT_LS) ?? "");
    if (!Array.isArray(arr)) return [];
    const out: DecryptEntry[] = [];
    for (const e of arr) {
      const r = String(e.rnti ?? "").trim().replace(/^0x/i, "");
      const rnti = /^[0-9a-fA-F]+$/.test(r) ? parseInt(r, 16) : NaN;
      if (!Number.isFinite(rnti)) continue;
      const hasRaw = /^[0-9a-fA-F]{32}$/.test((e.rrcenc_key ?? "").trim()) && /^[0-9a-fA-F]{32}$/.test((e.upenc_key ?? "").trim());
      const hasDer = /^[0-9a-fA-F]{64}$/.test((e.kasme ?? "").trim()) && String(e.nas_count ?? "").trim() !== "";
      if (!hasRaw && !hasDer) continue;
      out.push({
        rnti, rrcenc_key: (e.rrcenc_key ?? "").trim(), upenc_key: (e.upenc_key ?? "").trim(),
        kasme: hasDer ? (e.kasme ?? "").trim() : undefined,
        nas_count: hasDer ? parseInt(String(e.nas_count).trim(), 10) : undefined,
        cipher_algo: e.cipher_algo ?? "EEA2", integ_algo: e.integ_algo ?? "EIA2",
      });
    }
    return out;
  } catch { return []; }
}

function fmtRange(m: number | null): string {
  if (m == null) return "—";
  return m >= 1000 ? `${(m / 1000).toFixed(2)} km` : `${m} m`;
}

// Per-row TA value + its translated distance (one TA step ≈ 78 m one-way).
// We only have an absolute TA (and therefore a real distance) when the session
// had a RAR anchor; otherwise there is only relative drift and we show "—".
function taCell(ta: SessionTa): { taText: string; distText: string; known: boolean; title: string } {
  if (ta.anchor_ta != null && ta.anchor_range_m != null)
    return {
      taText: String(ta.anchor_ta), distText: fmtRange(ta.anchor_range_m), known: true,
      title: `RAR-anchored absolute TA: ${ta.anchor_ta} steps × ~78 m ≈ ${fmtRange(ta.anchor_range_m)}`,
    };
  return {
    taText: "—", distText: "—", known: false,
    title: ta.n_samples > 0 ? "only relative TA drift — no absolute anchor for this session" : "no TA observed",
  };
}

const confColor: Record<string, string> = {
  imsi: "bg-bad/20 text-bad border-bad/40",
  guti: "bg-ok/20 text-ok border-ok/40",
  tmsi: "bg-ok/20 text-ok border-ok/40",
  "rnti-only": "bg-muted/15 text-muted border-border",
};

export function SessionsPage() {
  const [path, setPath] = useState<string | null>(null);   // null = current/latest capture
  const [name, setName] = useState<string>("(latest capture)");
  const [browsing, setBrowsing] = useState(false);
  const [decrypt, setDecrypt] = useState(false);
  const [running, setRunning] = useState(false);
  const [resp, setResp] = useState<SessionsResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [filters, setFilters] = useState({ crnti: "", tmsi: "", ta: "", distance: "", cellid: "", plmn: "", identity: "" });

  async function run() {
    setErr(null); setResp(null); setRunning(true);
    try {
      const keys = decrypt ? savedKeys() : [];
      if (decrypt && keys.length === 0) {
        setErr("Decrypt is on but no usable keys are saved — set per-RNTI keys (or K_ASME+NAS) in the Captures → Decrypt panel first.");
        setRunning(false); return;
      }
      const r = await api.analyzeSessions(path, keys, decrypt);
      setResp(r);
      if (!r.ok) setErr(r.error);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setRunning(false); }
  }

  const sessions = resp?.sessions ?? [];
  const identified = sessions.filter((s) => s.identity.confidence !== "rnti-only");
  const located = sessions.filter((s) => s.ta.n_samples > 0);
  // distinct identity counts
  const nImsi = new Set(sessions.map((s) => s.identity.imsi).filter(Boolean)).size;
  const nStmsi = new Set(sessions.map((s) => s.identity.s_tmsi).filter(Boolean)).size;
  const nGuti = new Set(sessions.map((s) => s.identity.m_tmsi).filter(Boolean)).size;

  // per-column filters — case-insensitive substring match on the displayed value
  const idLabel = (i: UeSession["identity"]) =>
    `${i.guti ? `guti ${i.guti}` : i.s_tmsi ? `s-tmsi ${i.s_tmsi}` : i.imsi ? `imsi ${i.imsi}` : i.m_tmsi ? `m-tmsi ${i.m_tmsi}` : ""} ${i.confidence}`;
  const has = (val: string, f: string) => !f.trim() || val.toLowerCase().includes(f.trim().toLowerCase());
  const shown = sessions.filter((s) => {
    const info = taCell(s.ta);
    return has(s.c_rnti_hex, filters.crnti)
      && has(s.identity.m_tmsi ?? "", filters.tmsi)
      && has(info.taText, filters.ta)
      && has(info.distText, filters.distance)
      && has(s.cell_identity ?? "", filters.cellid)
      && has(s.plmn ?? "", filters.plmn)
      && has(idLabel(s.identity), filters.identity);
  });
  const anyFilter = Object.values(filters).some((v) => v.trim() !== "");
  const fInput = (key: keyof typeof filters, align: "left" | "right" = "left") => (
    <input value={filters[key]} onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.value }))}
      placeholder="filter…"
      className={`w-full bg-bg border border-border rounded px-1 py-0.5 text-[11px] font-normal text-${align} text-slate-100`} />
  );

  return (
    <div className="h-full overflow-auto p-4">
      <div className="flex items-center gap-2 mb-1">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">Sessions</h2>
        <span className="text-[11px] text-muted">— correlate RNTI ↔ identity (M-TMSI / S-TMSI / GUTI / IMSI) ↔ TA range</span>
      </div>
      <p className="text-[11px] text-muted mb-3">
        Each row is a UE session (a C-RNTI lifetime) with its identity and Timing-Advance distance from the cell.
        The goal: attribute a TA location to a specific GUTI. Identities seen in the clear (RRC Connection Request, paging);
        enable Decrypt to complete GUTI/IMSI from NAS.
      </p>

      <div className="flex items-center gap-2 mb-3 text-xs bg-bg border border-border rounded px-2 py-1.5 flex-wrap">
        <span className="text-muted uppercase text-[10px] shrink-0">Capture</span>
        <span className="font-mono text-slate-100 truncate" title={path ?? ""}>{name}</span>
        <button className="btn !px-2 !py-0.5 !text-xs" onClick={() => setBrowsing(true)}>📁 Browse…</button>
        <button className="btn !px-2 !py-0.5 !text-xs" onClick={() => { setPath(null); setName("(latest capture)"); }}>↺ latest</button>
        <label className="flex items-center gap-1 cursor-pointer ml-2">
          <input type="checkbox" checked={decrypt} onChange={(e) => setDecrypt(e.target.checked)} />
          <span>Decrypt (use saved keys)</span>
        </label>
        <button className="btn btn-primary !px-3 !py-1 !text-xs ml-auto" disabled={running} onClick={run}>
          {running ? "Analyzing…" : "Analyze sessions"}
        </button>
      </div>

      {err && <div className="text-bad text-xs font-mono border border-bad/40 rounded p-2 mb-3">{err}</div>}

      {resp?.ok && (
        <>
          <div className="flex gap-3 mb-2 text-xs">
            <span className="text-muted">Sessions: <span className="text-slate-100">{anyFilter ? `${shown.length} / ${sessions.length}` : sessions.length}</span></span>
            <span className="text-muted">Identified: <span className="text-ok">{identified.length}</span></span>
            <span className="text-muted">IMSI: <span className="text-bad">{nImsi}</span></span>
            <span className="text-muted">S-TMSI: <span className="text-slate-100">{nStmsi}</span></span>
            <span className="text-muted">GUTI (M-TMSI): <span className="text-ok">{nGuti}</span></span>
            <span className="text-muted">With TA: <span className="text-slate-100">{located.length}</span></span>
            <span className="text-muted">Unmatched RAR: <span className="text-warn">{resp.unmatched_rar}</span></span>
            <span className="text-muted ml-auto font-mono truncate max-w-[40%]" title={resp.source ?? ""}>{(resp.source ?? "").split("/").slice(-2).join("/")}</span>
          </div>
          {resp.note && <div className="text-[11px] text-muted mb-2">ℹ {resp.note}</div>}

          <div className="bg-bg border border-border rounded overflow-auto">
            <table className="w-full text-xs font-mono">
              <thead className="sticky top-0 bg-bg text-[10px] uppercase text-muted">
                <tr className="border-b border-border">
                  <th className="text-left px-2 py-1.5">C-RNTI</th>
                  <th className="text-left px-2 py-1.5">TMSI</th>
                  <th className="text-right px-2 py-1.5">TA</th>
                  <th className="text-right px-2 py-1.5">Distance</th>
                  <th className="text-left px-2 py-1.5">Cell ID</th>
                  <th className="text-left px-2 py-1.5">MCC/MNC</th>
                  <th className="text-left px-2 py-1.5">Identity (GUTI / S-TMSI / IMSI)</th>
                  <th className="text-right px-2 py-1.5">DL/UL</th>
                  <th className="text-right px-2 py-1.5">Dur</th>
                  <th className="text-right px-2 py-1.5">TA n</th>
                  <th className="text-right px-2 py-1.5">Range min/med/max</th>
                </tr>
                <tr className="border-b border-border">
                  <th className="px-1 pb-1.5">{fInput("crnti")}</th>
                  <th className="px-1 pb-1.5">{fInput("tmsi")}</th>
                  <th className="px-1 pb-1.5">{fInput("ta", "right")}</th>
                  <th className="px-1 pb-1.5">{fInput("distance", "right")}</th>
                  <th className="px-1 pb-1.5">{fInput("cellid")}</th>
                  <th className="px-1 pb-1.5">{fInput("plmn")}</th>
                  <th className="px-1 pb-1.5">{fInput("identity")}</th>
                  <th /><th /><th /><th />
                </tr>
              </thead>
              <tbody>
                {shown.map((s: UeSession) => {
                  const i = s.identity, ta = s.ta;
                  const taInfo = taCell(ta);
                  const isOpen = open === s.session_id;
                  return (
                    <Fragment key={s.session_id}>
                      <tr
                          className="border-b border-border/30 hover:bg-panel/50 cursor-pointer"
                          onClick={() => setOpen(isOpen ? null : s.session_id)}>
                        <td className="px-2 py-1 text-slate-100">{isOpen ? "▾" : "▸"} {s.c_rnti_hex}</td>
                        <td className="px-2 py-1 text-slate-100">{i.m_tmsi ?? "—"}</td>
                        <td className="px-2 py-1 text-right" title={taInfo.title}>
                          <span className={taInfo.known ? "text-slate-100" : "text-muted"}>{taInfo.taText}</span>
                        </td>
                        <td className="px-2 py-1 text-right" title={taInfo.title}>
                          <span className={taInfo.known ? "text-slate-100" : "text-muted"}>{taInfo.known ? "≈ " : ""}{taInfo.distText}</span>
                        </td>
                        <td className="px-2 py-1 text-slate-100">{s.cell_identity ?? "—"}</td>
                        <td className="px-2 py-1 text-slate-100">{s.plmn ?? "—"}</td>
                        <td className="px-2 py-1">
                          <span className="text-slate-100">{i.guti ? `guti ${i.guti}` : i.s_tmsi ? `s-tmsi ${i.s_tmsi}` : i.imsi ? `imsi ${i.imsi}` : i.m_tmsi ? `m-tmsi ${i.m_tmsi}` : "—"}</span>
                          <span className={`ml-2 px-1 rounded border text-[9px] ${confColor[i.confidence] ?? confColor["rnti-only"]}`}>{i.confidence}</span>
                        </td>
                        <td className="px-2 py-1 text-right text-muted">{s.dl_frames}/{s.ul_frames}</td>
                        <td className="px-2 py-1 text-right text-muted">{s.duration_s}s</td>
                        <td className="px-2 py-1 text-right">{ta.n_samples}</td>
                        <td className="px-2 py-1 text-right text-muted">{fmtRange(ta.min_range_m)} / {fmtRange(ta.median_range_m)} / {fmtRange(ta.max_range_m)}</td>
                      </tr>
                      {isOpen && (
                        <tr className="border-b border-border/30 bg-bg/60">
                          <td colSpan={11} className="px-3 py-2">
                            <div className="grid grid-cols-2 gap-4 text-[11px]">
                              <div>
                                <div className="text-muted uppercase text-[10px] mb-1">Identity</div>
                                <div>M-TMSI: <span className="text-slate-100">{i.m_tmsi ?? "—"}</span></div>
                                <div>MMEC: <span className="text-slate-100">{i.mmec ?? "—"}</span></div>
                                <div>S-TMSI: <span className="text-slate-100">{i.s_tmsi ?? "—"}</span></div>
                                <div>GUTI: <span className="text-slate-100">{i.guti ?? "— (needs PLMN+MMEC)"}</span></div>
                                <div>IMSI: <span className="text-slate-100">{i.imsi ?? "— (needs decrypt)"}</span></div>
                                <div>PLMN: <span className="text-slate-100">{i.plmn ?? "—"}</span></div>
                                <div className="text-muted">source: {i.source ?? "—"}</div>
                              </div>
                              <div>
                                <div className="text-muted uppercase text-[10px] mb-1">
                                  TA timeline {ta.has_absolute ? "(absolute range)" : "(relative — no RAR anchor)"}
                                </div>
                                {ta.n_samples === 0 && <div className="text-muted">No TA observed for this session.</div>}
                                <div className="max-h-40 overflow-auto">
                                  {ta.samples.map((smp, k) => (
                                    <div key={k} className="flex gap-3">
                                      <span className="text-muted w-16 text-right">{smp.t}s</span>
                                      <span className="w-10 text-muted">{smp.src}</span>
                                      <span className="text-slate-100 w-20 text-right">{fmtRange(smp.range_m)}</span>
                                      {smp.delta_m != null && <span className="text-muted">Δ{smp.delta_m > 0 ? "+" : ""}{smp.delta_m} m</span>}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
                {shown.length === 0 && (
                  <tr><td colSpan={11} className="text-center text-muted py-6">
                    {sessions.length === 0 ? "No sessions found in this capture." : "No sessions match the filters."}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {browsing && (
        <FileBrowser startPath={path}
          onClose={() => setBrowsing(false)}
          onPick={(p, n) => { setPath(p); setName(n); setBrowsing(false); setResp(null); }} />
      )}
    </div>
  );
}
