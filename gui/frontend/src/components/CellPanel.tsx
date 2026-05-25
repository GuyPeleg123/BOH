import { useStore } from "../lib/store";

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-3 py-1 border-b border-border last:border-0">
      <span className="kv-key">{k}</span>
      <span className="kv-val">{v}</span>
    </div>
  );
}

export function CellPanel() {
  const { state } = useStore();
  const c = state.cell;
  const m = state.mib;
  const s = state.stats;

  return (
    <div className="panel p-4">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted mb-3">
        Cell & Signal
      </h2>
      {!c ? (
        <div className="text-sm text-muted py-6 text-center">
          Waiting for cell discovery…
        </div>
      ) : (
        <>
          <KV k="PCI" v={c.pci} />
          <KV k="PRB" v={c.nof_prb} />
          <KV k="Ports" v={c.nof_ports} />
          <KV k="CP" v={c.cp} />
          <KV k="Mode" v={c.mode} />
          <KV k="DL freq" v={`${(c.dl_freq / 1e6).toFixed(3)} MHz`} />
          {c.ul_freq > 0 && <KV k="UL freq" v={`${(c.ul_freq / 1e6).toFixed(3)} MHz`} />}
          <KV k="Sample rate" v={`${(c.sample_rate / 1e6).toFixed(2)} MHz`} />
          {m && <KV k="SFN (MIB)" v={`${m.sfn} (offset ${m.sfn_offset})`} />}
          {s && (
            <>
              <KV k="CFO" v={`${s.cfo_hz.toFixed(1)} Hz`} />
              <KV k="SF processed" v={s.sf_processed.toLocaleString()} />
              <KV k="SF skipped" v={s.sf_skipped.toLocaleString()} />
            </>
          )}
        </>
      )}
    </div>
  );
}
