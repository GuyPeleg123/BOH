import { useMemo } from "react";
import { useFullState } from "../lib/store";
import { useStableTick } from "../lib/useStableTick";

// A UE/RNTI is "active" if seen within this many seconds of the latest event.
const ACTIVE_WINDOW_S = 5;

type RntiClass = "C-RNTI" | "SI-RNTI" | "P-RNTI" | "RA-RNTI" | "other";

// LTE RNTI value ranges (36.321 Table 7.1-1):
//   0x0001-0x003C RA-RNTI · 0x003D-0xFFF3 C-RNTI · 0xFFFE P-RNTI · 0xFFFF SI-RNTI
function rntiClass(r: number): RntiClass {
  if (r === 0xffff) return "SI-RNTI";
  if (r === 0xfffe) return "P-RNTI";
  if (r >= 0x0001 && r <= 0x003c) return "RA-RNTI";
  if (r >= 0x003d && r <= 0xfff3) return "C-RNTI";
  return "other";
}
const hex = (r: number) => "0x" + r.toString(16).toUpperCase().padStart(4, "0");

const kindBadge: Record<string, string> = {
  imsi: "bg-bad/20 text-bad border-bad/40",
  tmsi: "bg-warn/20 text-warn border-warn/40",
  guti: "bg-warn/20 text-warn border-warn/40",
  ue_capa: "bg-accent/20 text-accent border-accent/40",
  identity_map: "bg-ok/20 text-ok border-ok/40",
};
// Friendlier display names.
const kindLabel: Record<string, string> = { tmsi: "M-TMSI", imsi: "IMSI", guti: "GUTI", ue_capa: "UE-Capa", identity_map: "ID-map" };

const classBadge: Record<RntiClass, string> = {
  "C-RNTI": "bg-ok/20 text-ok border-ok/40",
  "SI-RNTI": "bg-muted/20 text-muted border-border",
  "P-RNTI": "bg-muted/20 text-muted border-border",
  "RA-RNTI": "bg-accent/20 text-accent border-accent/40",
  "other": "bg-muted/20 text-muted border-border",
};

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

export function UEsPage() {
  const state = useFullState();
  const tick = useStableTick(1000);

  const v = useMemo(() => {
    const now = state.monotonic;
    const rntis = Array.from(state.rntis.values());

    const byClass: Record<RntiClass, number> = { "C-RNTI": 0, "SI-RNTI": 0, "P-RNTI": 0, "RA-RNTI": 0, "other": 0 };
    let cActive = 0, cGhost = 0, cRecur = 0;
    for (const r of rntis) {
      const cls = rntiClass(r.rnti);
      byClass[cls]++;
      if (cls === "C-RNTI") {
        const seen = r.dl_count + r.ul_count;
        if (now - r.last_seen <= ACTIVE_WINDOW_S) cActive++;
        if (seen <= 1) cGhost++; else if (seen >= 3) cRecur++;
      }
    }

    // De-duplicate identities (the store keeps one record per sighting).
    const idMap = new Map<string, { kind: string; value: string; rntis: Set<number>; count: number; last: number; from: string }>();
    for (const id of state.identities) {
      const key = id.kind + "|" + id.value;
      let e = idMap.get(key);
      if (!e) { e = { kind: id.kind, value: id.value, rntis: new Set(), count: 0, last: id.ts, from: id.from }; idMap.set(key, e); }
      e.count++; e.rntis.add(id.rnti); e.last = Math.max(e.last, id.ts);
    }
    const ids = Array.from(idMap.values()).sort((a, b) => b.last - a.last);
    const nImsi = ids.filter((i) => i.kind === "imsi").length;
    const nTmsi = ids.filter((i) => i.kind === "tmsi").length;

    const rows = rntis.slice().sort((a, b) => b.last_seen - a.last_seen).slice(0, 500);
    return { now, byClass, cActive, cGhost, cRecur, cTotal: byClass["C-RNTI"], ids, nImsi, nTmsi, rows };
    // gate recompute on the 1 s tick so the page doesn't thrash at event rate
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  const ago = (t: number) => Math.max(0, v.now - t);

  return (
    <div className="p-3 h-full flex flex-col min-h-0 gap-3 overflow-auto">
      {/* Honest summary — identities are the real UE count; RNTIs are sessions/signals. */}
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-2">Identified UEs</h2>
        <div className="flex flex-wrap gap-2">
          <Stat label="UEs identified" value={v.nImsi + v.nTmsi} sub="distinct IMSI + M-TMSI" accent={v.nImsi + v.nTmsi > 0 ? "ok" : undefined} />
          <Stat label="IMSI" value={v.nImsi} sub="distinct" accent={v.nImsi > 0 ? "bad" : undefined} />
          <Stat label="M-TMSI" value={v.nTmsi} sub="distinct" accent={v.nTmsi > 0 ? "warn" : undefined} />
        </div>
        <p className="text-[11px] text-muted mt-1">
          Lower bound — only UEs that exposed an identity in the clear (paging, RRC request, attach) with API mode (-z) on.
        </p>
      </div>

      {/* RNTIs — sessions/signals, not UEs. Broken down so it's honest. */}
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-2">Radio sessions (RNTIs)</h2>
        <div className="flex flex-wrap gap-2">
          <Stat label="Active C-RNTIs" value={v.cActive} sub={`seen in last ${ACTIVE_WINDOW_S}s`} accent={v.cActive > 0 ? "ok" : undefined} />
          <Stat label="Distinct C-RNTIs" value={v.cTotal} sub={`${v.cRecur} recurring · ${v.cGhost} one-hit`} />
          <Stat label="One-hit C-RNTIs" value={v.cGhost} sub="likely false positives" accent={v.cGhost > 0 ? "warn" : undefined} />
          <Stat label="Broadcast RNTIs" value={v.byClass["SI-RNTI"] + v.byClass["P-RNTI"] + v.byClass["RA-RNTI"]} sub={`SI ${v.byClass["SI-RNTI"]} · P ${v.byClass["P-RNTI"]} · RA ${v.byClass["RA-RNTI"]} (not UEs)`} />
        </div>
        <p className="text-[11px] text-muted mt-1">
          A UE gets a new C-RNTI per connection and blind search produces one-hit ghosts — so distinct-RNTI count is NOT a UE count.
        </p>
      </div>

      {/* Identity detail */}
      <div className="panel p-3 flex flex-col min-h-0">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted mb-2">Identities ({v.ids.length})</h3>
        {v.ids.length === 0 ? (
          <div className="text-sm text-muted text-center py-4">None yet. Enable API mode (-z) — IMSI/M-TMSI appear from paging / RRC requests.</div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead className="text-[10px] uppercase tracking-wide text-muted">
              <tr className="border-b border-border">
                <th className="px-2 py-1.5 text-left">Type</th>
                <th className="px-2 py-1.5 text-left">Value</th>
                <th className="px-2 py-1.5 text-right">RNTIs</th>
                <th className="px-2 py-1.5 text-right">Seen</th>
                <th className="px-2 py-1.5 text-left">From</th>
                <th className="px-2 py-1.5 text-right">Last (s)</th>
              </tr>
            </thead>
            <tbody>
              {v.ids.map((id, i) => (
                <tr key={i} className="border-b border-border/40">
                  <td className="px-2 py-1"><span className={`px-1.5 py-0.5 rounded border text-[10px] uppercase ${kindBadge[id.kind] ?? "border-border text-muted"}`}>{kindLabel[id.kind] ?? id.kind}</span></td>
                  <td className="px-2 py-1 text-slate-100">{id.value}</td>
                  <td className="px-2 py-1 text-right text-muted">{Array.from(id.rntis).map(hex).join(", ")}</td>
                  <td className="px-2 py-1 text-right">{id.count}</td>
                  <td className="px-2 py-1 text-muted">{id.from}</td>
                  <td className="px-2 py-1 text-right text-muted">{ago(id.last).toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* RNTI detail */}
      <div className="panel p-3 flex flex-col min-h-0">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted mb-2">RNTIs seen ({state.rntis.size}{state.rntis.size >= 500 ? ", showing 500" : ""})</h3>
        {v.rows.length === 0 ? (
          <div className="text-sm text-muted text-center py-4">No RNTIs decoded yet.</div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead className="text-[10px] uppercase tracking-wide text-muted">
              <tr className="border-b border-border">
                <th className="px-2 py-1.5 text-left">RNTI</th>
                <th className="px-2 py-1.5 text-left">Class</th>
                <th className="px-2 py-1.5 text-right">DL</th>
                <th className="px-2 py-1.5 text-right">UL</th>
                <th className="px-2 py-1.5 text-right">Last (s)</th>
                <th className="px-2 py-1.5 text-left">State</th>
              </tr>
            </thead>
            <tbody>
              {v.rows.map((r) => {
                const cls = rntiClass(r.rnti);
                const active = v.now - r.last_seen <= ACTIVE_WINDOW_S;
                const seen = r.dl_count + r.ul_count;
                return (
                  <tr key={r.rnti} className="border-b border-border/40">
                    <td className="px-2 py-1 text-slate-100">{hex(r.rnti)}</td>
                    <td className="px-2 py-1"><span className={`px-1.5 py-0.5 rounded border text-[10px] ${classBadge[cls]}`}>{cls}</span></td>
                    <td className="px-2 py-1 text-right">{r.dl_count}</td>
                    <td className="px-2 py-1 text-right">{r.ul_count}</td>
                    <td className="px-2 py-1 text-right text-muted">{ago(r.last_seen).toFixed(1)}</td>
                    <td className="px-2 py-1 text-[10px]">
                      {active ? <span className="text-ok">active</span> : <span className="text-muted">idle</span>}
                      {cls === "C-RNTI" && seen <= 1 && <span className="text-warn"> · ghost?</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
