import { Fragment, useEffect, useState } from "react";
import { api } from "../lib/api";
import type { ReceiveStatus, SessionsResponse, SessionTa, UeSession } from "../lib/types";
import { FileBrowser } from "../components/FileBrowser";

// How often the live view re-polls receive status + re-analyzes the
// in-progress pcap. tshark re-parses the whole file each tick, so this is a
// tradeoff between freshness and load — fine for capture-session-length
// files; a very long-running live run will make each tick slower.
const LIVE_POLL_MS = 3000;

function fmtRange(m: number | null): string {
  if (m == null) return "—";
  return m >= 1000 ? `${(m / 1000).toFixed(2)} km` : `${m} m`;
}

// Cell Identity (28-bit ECI) arrives as a hex string like "0x3830200"; show it
// as a plain decimal the operator can read.
function cellIdNum(hex: string | null): number | null {
  if (!hex) return null;
  const s = hex.trim();
  const n = Number(/^0x/i.test(s) ? s : `0x${s}`);
  return Number.isFinite(n) ? n : null;
}
function cellIdDec(hex: string | null): string {
  const n = cellIdNum(hex);
  return n == null ? "—" : String(n);
}

// Columns the Sessions table can sort by.
type SortKey = "crnti" | "tmsi" | "ta" | "distance" | "cellid" | "plmn" | "identity" | "dlul" | "dur" | "tan" | "range";

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

// "ID via" badge: how the identity was learned. UL is the rare/strong case
// (identity seen in an uplink message); "DL paging" = paged then answered; "DL"
// = downlink NAS only.
function idViaBadge(via: "ul" | "paging" | "dl" | null) {
  if (!via) return <span className="text-muted">—</span>;
  const map: Record<string, { label: string; cls: string; title: string }> = {
    ul:     { label: "UL msg",    cls: "bg-warn/20 text-warn border-warn/50", title: "TMSI/IMSI seen in an UPLINK message (RRC ConnReq Msg3 / UL NAS) — rare and strong" },
    paging: { label: "DL paging", cls: "bg-ok/15 text-ok border-ok/40",        title: "This UE was paged on the downlink and then answered (connected here)" },
    dl:     { label: "DL",        cls: "bg-muted/15 text-muted border-border",  title: "Identity only seen in the downlink (DL NAS / contention resolution)" },
  };
  const m = map[via];
  return <span className={`px-1 rounded border text-[9px] ${m.cls}`} title={m.title}>{m.label}</span>;
}

export function SessionsPage() {
  const [path, setPath] = useState<string | null>(null);   // null = current/latest capture
  const [name, setName] = useState<string>("(latest capture)");
  const [browsing, setBrowsing] = useState(false);
  const [running, setRunning] = useState(false);
  const [resp, setResp] = useState<SessionsResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [filters, setFilters] = useState({ crnti: "", tmsi: "", ta: "", distance: "", cellid: "", plmn: "", identity: "" });
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 } | null>(null);
  // Default to showing only UEs confirmed on THIS serving cell (TMSI + TA, or a
  // TMSI seen in the uplink). Paging alone is tracking-area-wide, not cell-proof.
  const [servingOnly, setServingOnly] = useState(true);

  // Live mode: instead of a user-picked file, keep following whatever pcap
  // the receiver is CURRENTLY writing (pcap_receive.py's last_file), which
  // switches automatically to a fresh file the instant a new run connects —
  // so this never shows a stale/old run once a new one starts pushing.
  const [live, setLive] = useState(false);
  const [rxStatus, setRxStatus] = useState<ReceiveStatus | null>(null);

  useEffect(() => {
    if (!live) return;
    let cancelled = false;
    async function tick() {
      let rx: ReceiveStatus;
      try {
        rx = await api.receiveStatus();
      } catch {
        return;   // transient — try again next tick
      }
      if (cancelled) return;
      setRxStatus(rx);
      if (!rx.last_file) return;   // never received anything yet — nothing to analyze
      setPath(rx.last_file);
      setName(rx.last_file.split("/").pop() ?? rx.last_file);
      try {
        const r = await api.analyzeSessions(rx.last_file);
        if (cancelled) return;
        setResp(r);
        setErr(r.ok ? null : r.error);
      } catch (e) {
        if (!cancelled) setErr(e instanceof Error ? e.message : String(e));
      }
    }
    tick();
    const id = setInterval(tick, LIVE_POLL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, [live]);

  async function run() {
    setErr(null); setResp(null); setRunning(true);
    try {
      const r = await api.analyzeSessions(path);
      setResp(r);
      if (!r.ok) setErr(r.error);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setRunning(false); }
  }

  const sessions = resp?.sessions ?? [];

  // "On the serving cell" = we have PROOF this UE was scheduled by THIS cell
  // (not merely paged across the tracking area). Proof = ANY dedicated activity
  // tied to its C-RNTI:
  //   - a TA (RAR / TA-command => it RACHed / is being tracked here), OR
  //   - an uplink frame (measurement report / data / Msg3 => it transmitted here), OR
  //   - an identity we read on its connection (RRC/NAS on the C-RNTI).
  // Crucially this does NOT require a captured TMSI — a located-but-unnamed UE is
  // still on the cell. Paging alone (tracking-area broadcast) is NOT proof.
  const onServingCell = (s: UeSession) =>
    s.ta.n_samples > 0 || s.ul_frames > 0 || s.identity.confidence !== "rnti-only";

  const serving = sessions.filter(onServingCell);
  const servingWithTa = serving.filter((s) => s.ta.n_samples > 0);
  const servingIded = serving.filter((s) => s.identity.confidence !== "rnti-only");

  // distinct identity counts (over the serving-cell set)
  const nImsi = new Set(serving.map((s) => s.identity.imsi).filter(Boolean)).size;
  const nStmsi = new Set(serving.map((s) => s.identity.s_tmsi).filter(Boolean)).size;
  const nGuti = new Set(serving.map((s) => s.identity.m_tmsi).filter(Boolean)).size;
  const nPaged = resp?.paging_summary?.distinct_m_tmsi ?? 0;

  // per-column filters — case-insensitive substring match on the displayed value
  const idLabel = (i: UeSession["identity"]) =>
    `${i.guti ? `guti ${i.guti}` : i.s_tmsi ? `s-tmsi ${i.s_tmsi}` : i.imsi ? `imsi ${i.imsi}` : i.m_tmsi ? `m-tmsi ${i.m_tmsi}` : ""} ${i.confidence}`;
  const has = (val: string, f: string) => !f.trim() || val.toLowerCase().includes(f.trim().toLowerCase());
  const shown = sessions.filter((s) => {
    if (servingOnly && !onServingCell(s)) return false;
    const info = taCell(s.ta);
    return has(s.c_rnti_hex, filters.crnti)
      && has(s.identity.m_tmsi ?? "", filters.tmsi)
      && has(info.taText, filters.ta)
      && has(info.distText, filters.distance)
      && has(cellIdDec(s.cell_identity), filters.cellid)
      && has(s.plmn ?? "", filters.plmn)
      && has(idLabel(s.identity), filters.identity);
  });

  // Sort: rows that HAVE the clicked column's value float to the top (so the
  // operator can surface e.g. every session with a TMSI without knowing the
  // value or scrolling); clicking the same header again flips the order among
  // those. Missing values always sink to the bottom, regardless of direction.
  const sortVal = (s: UeSession, key: SortKey): { has: boolean; num: number; str: string } => {
    const ta = s.ta, info = taCell(ta);
    switch (key) {
      case "crnti":    return { has: true, num: s.c_rnti, str: "" };
      case "tmsi":     return { has: !!s.identity.m_tmsi, num: 0, str: s.identity.m_tmsi ?? "" };
      case "ta":       return { has: info.known, num: ta.anchor_ta ?? 0, str: "" };
      case "distance": return { has: info.known, num: ta.anchor_range_m ?? 0, str: "" };
      case "cellid":   { const n = cellIdNum(s.cell_identity); return { has: n != null, num: n ?? 0, str: "" }; }
      case "plmn":     return { has: !!s.plmn, num: 0, str: s.plmn ?? "" };
      case "identity": return { has: s.identity.confidence !== "rnti-only", num: 0, str: idLabel(s.identity) };
      case "dlul":     return { has: (s.dl_frames + s.ul_frames) > 0, num: s.dl_frames + s.ul_frames, str: "" };
      case "dur":      return { has: true, num: s.duration_s, str: "" };
      case "tan":      return { has: ta.n_samples > 0, num: ta.n_samples, str: "" };
      case "range":    return { has: ta.median_range_m != null, num: ta.median_range_m ?? 0, str: "" };
    }
  };
  const sorted = sort
    ? [...shown].sort((a, b) => {
        const va = sortVal(a, sort.key), vb = sortVal(b, sort.key);
        if (va.has !== vb.has) return va.has ? -1 : 1;                 // present-first
        const c = (va.str || vb.str) ? va.str.localeCompare(vb.str) : va.num - vb.num;
        return c * sort.dir;
      })
    : shown;

  const anyFilter = Object.values(filters).some((v) => v.trim() !== "");
  const fInput = (key: keyof typeof filters, align: "left" | "right" = "left") => (
    <input value={filters[key]} onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.value }))}
      placeholder="filter…"
      className={`w-full bg-bg border border-border rounded px-1 py-0.5 text-[11px] font-normal text-${align} text-slate-100`} />
  );
  // Clickable, sortable column header. Click toggles direction; the arrow marks
  // the active column.
  const arrow = (key: SortKey) => (sort?.key === key ? (sort.dir === 1 ? " ▲" : " ▼") : "");
  const sTh = (key: SortKey, label: string, align: "left" | "right" = "left") => (
    <th className={`text-${align} px-2 py-1.5 cursor-pointer select-none hover:text-slate-100`}
        title="Sort — rows with a value first; click again to flip"
        onClick={() => setSort((p) => (p && p.key === key ? { key, dir: p.dir === 1 ? -1 : 1 } : { key, dir: 1 }))}>
      {label}{arrow(key)}
    </th>
  );

  return (
    <div className="h-full overflow-auto p-4">
      <div className="flex items-center gap-2 mb-1">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">Sessions</h2>
        <span className="text-[11px] text-muted">— correlate RNTI ↔ identity (M-TMSI / S-TMSI / GUTI / IMSI) ↔ TA range</span>
      </div>
      <p className="text-[11px] text-muted mb-3">
        Each row is a UE session (a C-RNTI lifetime) with its identity and Timing-Advance distance from the cell.
        The goal: attribute a TA location to a specific GUTI. Identities are read in the clear (RRC Connection Request, paging).
      </p>

      <div className="flex items-center gap-2 mb-3 text-xs bg-bg border border-border rounded px-2 py-1.5 flex-wrap">
        <span className="text-muted uppercase text-[10px] shrink-0">Capture</span>
        <span className="font-mono text-slate-100 truncate" title={path ?? ""}>{name}</span>
        {!live && (
          <>
            <button className="btn !px-3 !py-1.5 !text-sm" onClick={() => setBrowsing(true)}>📁 Browse…</button>
            <button className="btn !px-3 !py-1.5 !text-sm" onClick={() => { setPath(null); setName("(latest capture)"); }}>↺ latest</button>
            <button className="btn btn-primary !px-3.5 !py-1.5 !text-sm" disabled={running} onClick={run}>
              {running ? "Analyzing…" : "Analyze sessions"}
            </button>
          </>
        )}
        <button
          className={`btn !px-3.5 !py-1.5 !text-sm ${live ? "!bg-bad/25 !border-bad/50 !text-bad" : ""} ml-auto`}
          title="Follow whatever pcap the receiver is currently writing, re-analyzing it every few seconds. Switches automatically to a new run's file the instant one starts pushing."
          onClick={() => setLive((v) => !v)}>
          {live ? "⏹ Stop live" : "🔴 Show live"}
        </button>
      </div>

      {live && (
        <div className="flex items-center gap-3 mb-3 text-xs bg-bg border border-bad/40 rounded px-2 py-1.5 flex-wrap">
          {rxStatus?.state === "connected" ? (
            <>
              <span className="flex items-center gap-1.5 text-bad font-semibold">
                <span className="inline-block w-2 h-2 rounded-full bg-bad animate-pulse" /> LIVE
              </span>
              <span className="text-muted">receiving from <span className="text-slate-100 font-mono">{rxStatus.peer}</span></span>
              <span className="text-muted">records: <span className="text-slate-100">{rxStatus.records.toLocaleString()}</span></span>
              <span className="text-muted">bytes: <span className="text-slate-100">{rxStatus.bytes_in.toLocaleString()}</span></span>
            </>
          ) : rxStatus?.last_file ? (
            <span className="text-muted">⏸ No run connected right now — showing the last received run (<span className="font-mono text-slate-100">{rxStatus.last_file.split("/").pop()}</span>). Will switch automatically when a new one connects.</span>
          ) : (
            <span className="text-muted">⏳ Waiting for a capture instance to connect and start forwarding…</span>
          )}
        </div>
      )}

      {err && <div className="text-bad text-xs font-mono border border-bad/40 rounded p-2 mb-3">{err}</div>}

      {resp?.ok && (
        <>
          <div className="flex gap-3 mb-2 text-xs items-center flex-wrap">
            <label className="flex items-center gap-1.5 cursor-pointer select-none"
              title="Show only UEs proven on THIS cell — i.e. with a TA, an uplink frame, or an identity read on their connection (any dedicated, non-paging activity). Off = also show bare C-RNTIs seen only in the downlink.">
              <input type="checkbox" checked={servingOnly} onChange={(e) => setServingOnly(e.target.checked)} />
              <span className="text-slate-100 font-semibold">On serving cell only</span>
            </label>
            <span className="text-muted" title="UEs proven on this cell (TA, uplink, or a captured identity) — includes located-but-unnamed UEs">
              On serving cell: <span className="text-ok font-semibold">{serving.length}</span> UEs
            </span>
            <span className="text-muted" title="Of those, how many we captured a TMSI/IMSI for">
              identified: <span className="text-ok font-semibold">{servingIded.length}</span>
            </span>
            <span className="text-muted" title="Of those, how many have a TA => a distance from the cell">
              with TA: <span className="text-slate-100">{servingWithTa.length}</span>
            </span>
            {nGuti > 0 && <span className="text-muted" title="Distinct M-TMSIs">M-TMSI: <span className="text-ok">{nGuti}</span></span>}
            {nStmsi > 0 && <span className="text-muted" title="Full S-TMSI (MMEC + M-TMSI)">S-TMSI: <span className="text-slate-100">{nStmsi}</span></span>}
            {nImsi > 0 && <span className="text-muted">IMSI: <span className="text-bad">{nImsi}</span></span>}
            <span className="text-muted">Rows: <span className="text-slate-100">{anyFilter || servingOnly ? `${shown.length} / ${sessions.length}` : sessions.length}</span></span>
            {nPaged > 0 && (
              <span className="text-muted/70 ml-auto text-[11px]" title="Distinct M-TMSIs seen in DL paging. Paging is broadcast across the whole tracking area, so these are NOT confirmed on this cell — shown for reference only.">
                paged in tracking area (not cell-confirmed): {nPaged.toLocaleString()}
              </span>
            )}
            <span className="text-muted font-mono truncate max-w-[30%]" title={resp.source ?? ""}>{(resp.source ?? "").split("/").slice(-2).join("/")}</span>
          </div>
          {resp.note && <div className="text-[11px] text-muted mb-2">ℹ {resp.note}</div>}

          <div className="bg-bg border border-border rounded overflow-auto">
            <table className="w-full text-xs font-mono">
              <thead className="sticky top-0 bg-bg text-[10px] uppercase text-muted">
                <tr className="border-b border-border">
                  {sTh("crnti", "C-RNTI")}
                  {sTh("tmsi", "TMSI")}
                  {sTh("ta", "TA", "right")}
                  {sTh("distance", "Distance", "right")}
                  {sTh("cellid", "Cell ID")}
                  {sTh("plmn", "MCC/MNC")}
                  {sTh("identity", "Identity (GUTI / S-TMSI / IMSI)")}
                  <th className="text-left font-medium px-2 pb-1" title="How the identity was learned: UL = seen in an uplink message (rare/strong); DL paging = the UE was paged then answered; DL = downlink NAS only">ID via</th>
                  {sTh("dlul", "DL/UL", "right")}
                  {sTh("dur", "Dur", "right")}
                  {sTh("tan", "TA n", "right")}
                  {sTh("range", "Range min/med/max", "right")}
                </tr>
                <tr className="border-b border-border">
                  <th className="px-1 pb-1.5">{fInput("crnti")}</th>
                  <th className="px-1 pb-1.5">{fInput("tmsi")}</th>
                  <th className="px-1 pb-1.5">{fInput("ta", "right")}</th>
                  <th className="px-1 pb-1.5">{fInput("distance", "right")}</th>
                  <th className="px-1 pb-1.5">{fInput("cellid")}</th>
                  <th className="px-1 pb-1.5">{fInput("plmn")}</th>
                  <th className="px-1 pb-1.5">{fInput("identity")}</th>
                  <th /><th /><th /><th /><th />
                </tr>
              </thead>
              <tbody>
                {sorted.map((s: UeSession) => {
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
                        <td className="px-2 py-1 text-slate-100" title={s.cell_identity ?? ""}>{cellIdDec(s.cell_identity)}</td>
                        <td className="px-2 py-1 text-slate-100">{s.plmn ?? "—"}</td>
                        <td className="px-2 py-1">
                          <span className="text-slate-100">{i.guti ? `guti ${i.guti}` : i.s_tmsi ? `s-tmsi ${i.s_tmsi}` : i.imsi ? `imsi ${i.imsi}` : i.m_tmsi ? `m-tmsi ${i.m_tmsi}` : "—"}</span>
                          <span className={`ml-2 px-1 rounded border text-[9px] ${confColor[i.confidence] ?? confColor["rnti-only"]}`}>{i.confidence}</span>
                        </td>
                        <td className="px-2 py-1">{idViaBadge(i.id_via)}</td>
                        <td className="px-2 py-1 text-right text-muted">{s.dl_frames}/{s.ul_frames}</td>
                        <td className="px-2 py-1 text-right text-muted">{s.duration_s}s</td>
                        <td className="px-2 py-1 text-right">{ta.n_samples}</td>
                        <td className="px-2 py-1 text-right text-muted">{fmtRange(ta.min_range_m)} / {fmtRange(ta.median_range_m)} / {fmtRange(ta.max_range_m)}</td>
                      </tr>
                      {isOpen && (
                        <tr className="border-b border-border/30 bg-bg/60">
                          <td colSpan={12} className="px-3 py-2">
                            <div className="grid grid-cols-2 gap-4 text-[11px]">
                              <div>
                                <div className="text-muted uppercase text-[10px] mb-1">Identity</div>
                                <div>M-TMSI: <span className="text-slate-100">{i.m_tmsi ?? "—"}</span></div>
                                <div>MMEC: <span className="text-slate-100">{i.mmec ?? "—"}</span></div>
                                <div>S-TMSI: <span className="text-slate-100">{i.s_tmsi ?? "—"}</span></div>
                                <div>GUTI: <span className="text-slate-100">{i.guti ?? "— (needs PLMN+MMEC)"}</span></div>
                                <div>IMSI: <span className="text-slate-100">{i.imsi ?? "—"}</span></div>
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
