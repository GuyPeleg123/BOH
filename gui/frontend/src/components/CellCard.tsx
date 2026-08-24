import { useEffect, useState } from "react";
import { useStore, shallow } from "../lib/store";
import { api } from "../lib/api";
import type { CellIdResponse } from "../lib/types";

function Kv({ k, v, mono = true }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col min-w-0">
      <span className="label">{k}</span>
      <span className={`text-sm text-slate-100 truncate ${mono ? "font-mono" : ""}`}>{v}</span>
    </div>
  );
}

export function CellCard() {
  const state = useStore((s) => ({
    cell: s.cell, mib: s.mib, stats: s.stats, hello: s.hello,
  }), shallow);
  const c = state.cell;
  const m = state.mib;
  const s = state.stats;
  const h = state.hello;

  // Cell ID (ECI) lives in SIB1, not the live cell event — poll the backend,
  // which reads it from the current/live pcap. Refreshes every 10s; cheap
  // (backend caches, and the identity is static per cell lock).
  const [cid, setCid] = useState<CellIdResponse | null>(null);
  useEffect(() => {
    let alive = true;
    const poll = () => { api.cellId().then((r) => { if (alive) setCid(r); }).catch(() => {}); };
    poll();
    const id = setInterval(poll, 10000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  if (!c) {
    return (
      <div className="panel p-4 flex items-center gap-3 text-sm text-muted">
        <span className="inline-block w-2 h-2 rounded-full bg-warn animate-pulse" />
        Waiting for cell discovery…
        {h && (
          <span className="ml-auto font-mono text-xs">
            DL {(h.args.rf_freq / 1e6).toFixed(1)} MHz
            {h.args.ul_freq > 0 && ` · UL ${(h.args.ul_freq / 1e6).toFixed(1)} MHz`}
            {h.args.cell_search ? " · cell-search on" : ""}
          </span>
        )}
      </div>
    );
  }

  return (
    <div className="panel p-4">
      <div className="flex items-baseline gap-3 mb-3">
        <span className="inline-block w-2 h-2 rounded-full bg-ok" />
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">Cell</h2>
        <span className="text-xl font-mono font-semibold text-accent">PCI {c.pci}</span>
        {cid?.ok && cid.cell_identity && (
          <span className="text-sm font-mono"
                title={`E-UTRAN Cell Identity (from SIB1) — which tower you're on. Hex ${cid.cell_identity}.`
                  + ` eNB-ID ${cid.enb_id} · sector ${cid.sector}`
                  + (cid.tac != null ? ` · TAC ${cid.tac}` : "")
                  + (cid.plmn ? ` · PLMN ${cid.plmn}` : "")}>
            <span className="text-muted">Cell&nbsp;ID</span>{" "}
            <span className="text-accent font-semibold">{cid.eci}</span>
          </span>
        )}
        <span className="text-sm font-mono text-slate-100">{c.nof_prb} PRB · {c.nof_ports}-port {c.cp} CP · {c.mode}</span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-x-4 gap-y-2">
        {cid?.ok && cid.eci != null && <Kv k="Cell ID (ECI)" v={`${cid.eci} (${cid.cell_identity})`} />}
        {cid?.ok && cid.enb_id != null && <Kv k="eNB / sector" v={`${cid.enb_id} / ${cid.sector}`} />}
        {cid?.ok && cid.tac != null && <Kv k="TAC" v={String(cid.tac)} />}
        <Kv k="DL freq"      v={`${(c.dl_freq / 1e6).toFixed(3)} MHz`} />
        {c.ul_freq > 0 && <Kv k="UL freq" v={`${(c.ul_freq / 1e6).toFixed(3)} MHz`} />}
        <Kv k="Sample rate"  v={`${(c.sample_rate / 1e6).toFixed(2)} MHz`} />
        <Kv k="Bandwidth"    v={`${prbToMHz(c.nof_prb)} MHz`} />
        {m && <Kv k="MIB SFN" v={`${m.sfn} (offset ${m.sfn_offset})`} />}
        {s && <Kv k="CFO"     v={`${s.cfo_hz.toFixed(1)} Hz`} />}
        {s && <Kv k="Workers" v={`${state.hello?.args?.nof_threads ?? "?"} threads`} />}
        {s && <Kv k="Skipped SF" v={`${s.sf_skipped} (${s.sf_processed ? (100 * s.sf_skipped / (s.sf_processed + s.sf_skipped)).toFixed(1) : "0"}%)`} />}
      </div>
    </div>
  );
}

function prbToMHz(nof_prb: number): string {
  // Standard LTE: 6/15/25/50/75/100 PRB <-> 1.4/3/5/10/15/20 MHz
  const map: Record<number, string> = { 6: "1.4", 15: "3", 25: "5", 50: "10", 75: "15", 100: "20" };
  return map[nof_prb] ?? (nof_prb * 0.18).toFixed(1);
}
